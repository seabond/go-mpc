package dkls23

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"golang.org/x/crypto/sha3"
)

// oteHasher packs what used to be six Writes into one, and reduces mod q without
// math/big. Both are supposed to be invisible: the pads it produces feed straight
// into the VOLE, so a byte that differs here is a signature the counterparty
// cannot verify — and, far worse, a pad that differs only for some inputs would
// be an intermittent one. These are the original implementations, kept as the
// oracle.

func oldOteSeedHash(sid string, choice bool, j int, col []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTESeed))
	h.Write([]byte(sid))
	h.Write([]byte{0x00})
	h.Write([]byte{byte(condUint32(choice))})
	var jbuf [8]byte
	binary.BigEndian.PutUint64(jbuf[:], uint64(j))
	h.Write(jbuf[:])
	h.Write(col)
	out := make([]byte, 32)
	h.Read(out)
	return out
}

func oldOteExpandHash(sid string, choice bool, j, i int, seed []byte) [32]byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTEExpand))
	h.Write([]byte(sid))
	h.Write([]byte{0x00})
	h.Write([]byte{byte(condUint32(choice))})
	var jbuf [8]byte
	binary.BigEndian.PutUint64(jbuf[:], uint64(j))
	h.Write(jbuf[:])
	binary.BigEndian.PutUint64(jbuf[:], uint64(i))
	h.Write(jbuf[:])
	h.Write(seed)

	raw := make([]byte, 64)
	h.Read(raw)
	v := new(big.Int).SetBytes(raw)
	v.Mod(v, curveOrder)
	var out [32]byte
	v.FillBytes(out[:])
	return out
}

func TestOTEHasherMatchesTheHashesItReplaced(t *testing.T) {
	t.Parallel()

	sids := []string{"", "sid", "a-signing-session-id-of-the-usual-length-0123456789abcdef"}
	for _, sid := range sids {
		sh := newOTEHasher(domainOTESeed, sid, LambdaC/8)
		eh := newOTEHasher(domainOTEExpand, sid, 32)

		// Reused across calls, which is the point: state left behind by one call
		// would show up as a mismatch on the next.
		for n := 0; n < 500; n++ {
			col := make([]byte, LambdaC/8)
			if _, err := rand.Read(col); err != nil {
				t.Fatal(err)
			}
			choice := n%2 == 0
			j := n * 7

			got := sh.seedHash(choice, j, col)
			want := oldOteSeedHash(sid, choice, j, col)
			if string(got[:]) != string(want) {
				t.Fatalf("sid %q call %d: seedHash = %x, the hash it replaced gives %x",
					sid, n, got, want)
			}

			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < Ell+Rho; i++ {
				gotE := eh.expandHash(choice, j, i, seed)
				wantE := oldOteExpandHash(sid, choice, j, i, seed)
				if gotE != wantE {
					t.Fatalf("sid %q call %d i %d: expandHash = %x, the hash it replaced gives %x",
						sid, n, i, gotE, wantE)
				}
			}
		}
	}
}

// The hasher's reused scratch is a verbatim copy of material this package
// erases elsewhere — after a seedHash, buf's tail IS the transposed matrix
// column that zeroTransposed wipes — so oteHasher.zero has to actually erase it,
// including the bytes past buf's current length that an earlier, longer call
// left behind. Reusing one buffer is what made the hasher fast; it is also what
// makes dropping the reference insufficient, per zeroize.go's own header.
func TestOTEHasherZeroErasesTheScratchItAccumulated(t *testing.T) {
	t.Parallel()
	sid := "a-signing-session-id"
	sh := newOTEHasher(domainOTESeed, sid, LambdaC/8)

	col := make([]byte, LambdaC/8)
	if _, err := rand.Read(col); err != nil {
		t.Fatal(err)
	}
	sh.seedHash(true, 9, col)

	// Precondition: the column really is sitting in the hasher's buffer, so the
	// assertion below is testing something.
	if !bytes.Contains(sh.buf[:cap(sh.buf)], col) {
		t.Fatal("precondition failed: the column is not in the hasher buffer, so this test proves nothing")
	}

	// A shorter call re-slices buf without overwriting the whole column, which is
	// why zero must reach cap and not len.
	sh.seedHash(false, 1, col[:4])

	sh.zero()

	if bytes.Contains(sh.buf[:cap(sh.buf)], col) {
		t.Error("zero left the matrix column in buf; dropping the reference is not erasure")
	}
	for i, b := range sh.buf[:cap(sh.buf)] {
		if b != 0 {
			t.Fatalf("zero left buf[%d] = %#x, want 0", i, b)
		}
	}
	for i, b := range sh.raw {
		if b != 0 {
			t.Fatalf("zero left raw[%d] = %#x, want 0", i, b)
		}
	}
}

// The expand hasher holds the derived OTE seed in buf and the 64-byte
// pre-reduction pad in raw. Both are secret and both must go.
func TestOTEHasherZeroErasesTheExpandPad(t *testing.T) {
	t.Parallel()
	eh := newOTEHasher(domainOTEExpand, "sid", 32)
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	eh.expandHash(true, 3, 4, seed)

	if !bytes.Contains(eh.buf[:cap(eh.buf)], seed) {
		t.Fatal("precondition failed: the seed is not in the hasher buffer")
	}
	var zeroRaw [64]byte
	if eh.raw == zeroRaw {
		t.Fatal("precondition failed: raw is already zero, so this test proves nothing")
	}

	eh.zero()

	if bytes.Contains(eh.buf[:cap(eh.buf)], seed) {
		t.Error("zero left the derived OTE seed in buf")
	}
	if eh.raw != zeroRaw {
		t.Errorf("zero left the pre-reduction pad in raw: %x", eh.raw)
	}
}

// A seed vector longer than the capacity newOTEHasher was sized for must still
// hash correctly — the buffer grows, and the prefix must survive the growth.
func TestOTEHasherHandlesAnOversizedTail(t *testing.T) {
	t.Parallel()
	sid := "sid"
	eh := newOTEHasher(domainOTEExpand, sid, 8) // deliberately too small
	seed := make([]byte, 400)
	for i := range seed {
		seed[i] = byte(i)
	}
	for n := 0; n < 4; n++ {
		got := eh.expandHash(n%2 == 0, n, n, seed)
		want := oldOteExpandHash(sid, n%2 == 0, n, n, seed)
		if got != want {
			t.Fatalf("call %d: %x, want %x", n, got, want)
		}
	}
}
