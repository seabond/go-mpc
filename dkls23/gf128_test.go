package dkls23

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// The fast implementation is limb arithmetic with a hand-written reduction, and
// a wrong field silently turns the consistency check into a check of nothing —
// it would still pass on honest input and still fail on garbage, while catching
// a real cheat with the wrong probability or not at all.
//
// So it is differential-tested against a reference that is slow and obviously
// right: polynomials as big.Int bitmasks, multiply by shift-and-XOR over set
// bits, reduce by repeated subtraction of the modulus shifted to the leading
// term. Nothing clever, nothing to get wrong.

// gf128Modulus is X^128 + X^7 + X^2 + X + 1.
func gf128Modulus() *big.Int {
	m := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, e := range []uint{7, 2, 1, 0} {
		m.Or(m, new(big.Int).Lsh(big.NewInt(1), e))
	}
	return m
}

func refFromGF(a gf128) *big.Int {
	v := new(big.Int).SetUint64(a.hi)
	v.Lsh(v, 64)
	return v.Or(v, new(big.Int).SetUint64(a.lo))
}

func refToGF(v *big.Int) gf128 {
	lo := new(big.Int).And(v, new(big.Int).SetUint64(^uint64(0)))
	hi := new(big.Int).Rsh(v, 64)
	return gf128{hi: hi.Uint64(), lo: lo.Uint64()}
}

func refMul(x, y *big.Int) *big.Int {
	prod := new(big.Int)
	for i := 0; i < y.BitLen(); i++ {
		if y.Bit(i) == 1 {
			prod.Xor(prod, new(big.Int).Lsh(x, uint(i)))
		}
	}
	m := gf128Modulus()
	for prod.BitLen() > 128 {
		shift := uint(prod.BitLen() - 1 - 128)
		prod.Xor(prod, new(big.Int).Lsh(m, shift))
	}
	return prod
}

func randGF(t *testing.T) gf128 {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return gf128FromBytes(b[:])
}

func TestGF128MulMatchesAReferenceImplementation(t *testing.T) {
	t.Parallel()
	for range 2000 {
		a, b := randGF(t), randGF(t)
		want := refToGF(refMul(refFromGF(a), refFromGF(b)))
		if got := a.mul(b); !got.equal(want) {
			t.Fatalf("a=%016x%016x b=%016x%016x\n got %016x%016x\nwant %016x%016x",
				a.hi, a.lo, b.hi, b.lo, got.hi, got.lo, want.hi, want.lo)
		}
	}
}

// Edge cases the random test is unlikely to reach: the values whose products
// straddle the reduction boundary.
func TestGF128MulOnBoundaryValues(t *testing.T) {
	t.Parallel()
	edges := []gf128{
		{0, 0},
		{0, 1},                                   // 1
		{0, 2},                                   // X
		{^uint64(0), ^uint64(0)},                 // all ones
		{1 << 63, 0},                             // X^127
		{0, 1 << 63},                             // X^63
		{1, 0},                                   // X^64
		{0x8000000000000000, 0x0000000000000001}, // X^127 + 1
		{0x0123456789abcdef, 0xfedcba9876543210}, // no structure
	}
	for _, a := range edges {
		for _, b := range edges {
			want := refToGF(refMul(refFromGF(a), refFromGF(b)))
			if got := a.mul(b); !got.equal(want) {
				t.Fatalf("a=%016x%016x b=%016x%016x\n got %016x%016x\nwant %016x%016x",
					a.hi, a.lo, b.hi, b.lo, got.hi, got.lo, want.hi, want.lo)
			}
		}
	}
}

// The check's correctness argument uses distributivity over the sum and
// associativity when the challenge is folded in; a field that failed either
// would make the verification equation not hold for honest parties.
func TestGF128ObeysTheFieldLawsTheCheckRelieson(t *testing.T) {
	t.Parallel()
	one := gf128{0, 1}
	for range 500 {
		a, b, c := randGF(t), randGF(t), randGF(t)

		if !a.mul(b).equal(b.mul(a)) {
			t.Fatal("multiplication is not commutative")
		}
		if !a.mul(b.mul(c)).equal(a.mul(b).mul(c)) {
			t.Fatal("multiplication is not associative")
		}
		if !a.mul(b.add(c)).equal(a.mul(b).add(a.mul(c))) {
			t.Fatal("multiplication does not distribute over addition")
		}
		if !a.mul(one).equal(a) {
			t.Fatal("1 is not the multiplicative identity")
		}
		if !a.add(a).isZero() {
			t.Fatal("a + a != 0: this is not characteristic 2")
		}
		// A field has no zero divisors. If it did, a cheating receiver could
		// choose values that annihilate the challenge and pass for free.
		if !a.isZero() && !b.isZero() && a.mul(b).isZero() {
			t.Fatalf("zero divisors: %016x%016x * %016x%016x = 0", a.hi, a.lo, b.hi, b.lo)
		}
	}
}

func TestGF128BytesRoundTrip(t *testing.T) {
	t.Parallel()
	for range 500 {
		a := randGF(t)
		b := a.bytes()
		if got := gf128FromBytes(b[:]); !got.equal(a) {
			t.Fatalf("round trip changed the value: %016x%016x -> %016x%016x", a.hi, a.lo, got.hi, got.lo)
		}
	}
	// The protocol hands over LambdaC/8 = 16 bytes, so the padding paths are not
	// exercised in production; they are still asserted so a future caller with a
	// shorter vector gets the alignment it would expect.
	if got := gf128FromBytes([]byte{0x01}); !got.equal(gf128{0, 1}) {
		t.Fatalf("a short input was not right-aligned: %016x%016x", got.hi, got.lo)
	}
}
