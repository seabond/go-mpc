package dkls23

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// randMatrix builds a LambdaC x Xi bit matrix from a deterministic source, so a
// failure names a seed that reproduces it.
func randMatrix(rng *rand.Rand) [][Xi / 8]byte {
	m := make([][Xi / 8]byte, LambdaC)
	for k := range m {
		for b := range m[k] {
			m[k][b] = byte(rng.Intn(256))
		}
	}
	return m
}

// TestTransposeMatchesGetColumn is the correctness argument for bitmatrix.go.
//
// The protocol stopped calling getColumnLambdaC and started reading columns out
// of transposeLambdaCxXi. That substitution is safe if and only if the two agree
// on every column of every matrix, byte for byte — not "as field elements", not
// "up to bit order", byte for byte, because the columns are fed to SHAKE as
// bytes in OTExtSenderExpand and OTExtReceiverExpand, where any reordering would
// silently change every derived seed.
//
// So: for each matrix, all Xi columns, compared against the reference.
func TestTransposeMatchesGetColumn(t *testing.T) {
	t.Parallel()

	// Structured cases first: the ones where a bit-order or block-order mistake
	// hides. All-zero and all-ones are symmetric under any permutation of bits,
	// so they catch nothing on their own but do catch a wholesale wrong length.
	// The rest break every symmetry the 8x8 blocking could confuse.
	cases := map[string][][Xi / 8]byte{}

	zero := make([][Xi / 8]byte, LambdaC)
	cases["all-zero"] = zero

	ones := make([][Xi / 8]byte, LambdaC)
	for k := range ones {
		for b := range ones[k] {
			ones[k][b] = 0xFF
		}
	}
	cases["all-ones"] = ones

	// Row k set iff k is even: distinguishes row order within a block.
	evenRows := make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k += 2 {
		for b := range evenRows[k] {
			evenRows[k][b] = 0xFF
		}
	}
	cases["even-rows"] = evenRows

	// Column j set iff j is even: distinguishes column order within a block.
	evenCols := make([][Xi / 8]byte, LambdaC)
	for k := range evenCols {
		for b := range evenCols[k] {
			evenCols[k][b] = 0x55
		}
	}
	cases["even-cols"] = evenCols

	// Row k carries the value k: every row distinct, so any swap of two rows
	// shows up.
	rowIndex := make([][Xi / 8]byte, LambdaC)
	for k := range rowIndex {
		for b := range rowIndex[k] {
			rowIndex[k][b] = byte(k)
		}
	}
	cases["row-index"] = rowIndex

	// Byte jb of every row carries jb: every byte-column distinct, so any swap
	// of two 8x8 blocks along the long axis shows up.
	colIndex := make([][Xi / 8]byte, LambdaC)
	for k := range colIndex {
		for b := range colIndex[k] {
			colIndex[k][b] = byte(b)
		}
	}
	cases["col-index"] = colIndex

	// The main diagonal of the LambdaC x LambdaC leading square, which is the
	// one input a transpose leaves alone — so it catches an implementation that
	// is accidentally the identity in the other direction.
	diag := make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		diag[k][k/8] |= 1 << (uint(k) % 8)
	}
	cases["diagonal"] = diag

	rng := rand.New(rand.NewSource(20260731))
	for i := 0; i < 64; i++ {
		cases["random-"+string(rune('a'+i%26))+string(rune('0'+i/26))] = randMatrix(rng)
	}

	for name, m := range cases {
		out := transposeLambdaCxXi(m)
		for j := 0; j < Xi; j++ {
			want := getColumnLambdaC(m, j)
			// bytes.Equal rather than require.Equal in the loop: this runs
			// ~30k times per case set and reflection-based comparison dominates
			// the test otherwise.
			if !bytes.Equal(want, out[j][:]) {
				require.Equalf(t, want, out[j][:],
					"case %q column %d: transpose disagrees with getColumnLambdaC", name, j)
			}
		}
	}
}

// TestTransposeSingleBitSweep drives every one of the LambdaC*Xi input bit
// positions on its own and checks where it lands.
//
// The transpose is a permutation of bits, so agreeing with the reference on
// every single-bit input is agreement everywhere: both maps are GF(2)-linear in
// the input bits. This is the sweep that says no bit is dropped, duplicated, or
// routed to a neighbouring column — the failure mode that a random-matrix test
// can miss when the two wrong bits happen to be equal.
func TestTransposeSingleBitSweep(t *testing.T) {
	t.Parallel()

	m := make([][Xi / 8]byte, LambdaC)
	var zeroRow [LambdaC / 8]byte

	for k := 0; k < LambdaC; k++ {
		for j := 0; j < Xi; j++ {
			m[k][j/8] = 1 << (uint(j) % 8)

			out := transposeLambdaCxXi(m)

			// The one live column must equal the reference.
			if !bytes.Equal(getColumnLambdaC(m, j), out[j][:]) {
				require.Equalf(t, getColumnLambdaC(m, j), out[j][:],
					"bit (row %d, col %d) landed wrong", k, j)
			}
			// And nothing may have bled into any other column.
			out[j] = zeroRow
			for jj := 0; jj < Xi; jj++ {
				if out[jj] != zeroRow {
					t.Fatalf("bit (row %d, col %d) also set bits in column %d", k, j, jj)
				}
			}

			m[k][j/8] = 0
		}
	}
}

// TestTranspose8 pins the 8x8 primitive against a naive definition, separately
// from the matrix walk that uses it, so a failure says which of the two is wrong.
func TestTranspose8(t *testing.T) {
	t.Parallel()

	naive := func(x uint64) uint64 {
		var y uint64
		for r := 0; r < 8; r++ {
			for c := 0; c < 8; c++ {
				if x>>(8*r+c)&1 == 1 {
					y |= 1 << (8*c + r)
				}
			}
		}
		return y
	}

	// Exhaustive over single-bit inputs: 64 positions, each of which must land
	// in exactly one place. Linearity extends this to all 2^64 inputs.
	for i := 0; i < 64; i++ {
		x := uint64(1) << i
		require.Equalf(t, naive(x), transpose8(x), "single bit %d", i)
	}

	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200000; i++ {
		x := rng.Uint64()
		if transpose8(x) != naive(x) {
			require.Equalf(t, naive(x), transpose8(x), "random input %#016x", x)
		}
		// A transpose is an involution.
		require.Equalf(t, x, transpose8(transpose8(x)), "not an involution at %#016x", x)
	}
}

// TestZeroTransposed checks the erasure actually clears every byte, since it is
// the only thing standing between the transpose and a second unerased copy of Q.
func TestZeroTransposed(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(99))
	m := randMatrix(rng)
	out := transposeLambdaCxXi(m)

	nonzero := 0
	for j := range out {
		for _, b := range out[j] {
			if b != 0 {
				nonzero++
			}
		}
	}
	require.Greater(t, nonzero, Xi*LambdaC/8/4, "test matrix should be mostly nonzero")

	zeroTransposed(out)
	var zeroRow [LambdaC / 8]byte
	for j := range out {
		require.Equalf(t, zeroRow, out[j], "row %d not erased", j)
	}
}

// TestOTEColumnReadsAgreeAcrossRoles is an end-to-end restatement of the same
// equivalence at the level the protocol cares about: Bob's t^j and Alice's q^j
// must still satisfy q^j = t^j xor (sigma_k & beta_j) columnwise after the
// layout change, which is the relation the consistency check verifies.
func TestOTEColumnReadsAgreeAcrossRoles(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(4242))
	T := randMatrix(rng)

	sigma := make([]bool, LambdaC)
	for k := range sigma {
		sigma[k] = rng.Intn(2) == 1
	}
	var beta [Xi]bool
	for j := range beta {
		beta[j] = rng.Intn(2) == 1
	}
	betaVec := boolsToBitVec(beta)

	// Build corrections and Q exactly as the two roles do. prg1 stands in for
	// PRG(K^1_k): only the algebra is under test here, so any fixed matrix does,
	// and Alice's seed is PRG(K^{sigma_k}_k) — T[k] when sigma_k is 0, prg1[k]
	// when it is 1.
	prg1 := randMatrix(rng)
	corrections := make([][Xi / 8]byte, LambdaC)
	Q := make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		corrections[k] = xorBitVec(xorBitVec(T[k], prg1[k]), betaVec)
		if sigma[k] {
			Q[k] = xorBitVec(prg1[k], corrections[k])
		} else {
			Q[k] = T[k]
		}
	}

	tCols := transposeLambdaCxXi(T)
	qCols := transposeLambdaCxXi(Q)

	for j := 0; j < Xi; j++ {
		var want [LambdaC / 8]byte
		copy(want[:], tCols[j][:])
		if beta[j] {
			for k := 0; k < LambdaC; k++ {
				if sigma[k] {
					want[k/8] ^= 1 << (uint(k) % 8)
				}
			}
		}
		require.Equalf(t, want, qCols[j], "column %d: q^j != t^j + beta_j*sigma", j)
	}
}

// BenchmarkColumnReadPerColumn and BenchmarkColumnReadTransposed measure the
// same work — producing all Xi columns of one LambdaC x Xi matrix — the old way
// and the new way. One of these runs four times per directed VOLE instance per
// signature.
func BenchmarkColumnReadPerColumn(b *testing.B) {
	m := randMatrix(rand.New(rand.NewSource(1)))
	sink := make([][]byte, Xi)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < Xi; j++ {
			sink[j] = getColumnLambdaC(m, j)
		}
	}
	runtimeSink = sink
}

func BenchmarkColumnReadTransposed(b *testing.B) {
	m := randMatrix(rand.New(rand.NewSource(1)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := transposeLambdaCxXi(m)
		runtimeSink = out
	}
}

// oteProveViaGetColumn is oteProve as it stood before the transpose landed:
// same fold, same field arithmetic, columns read one at a time. It exists so
// the change can be judged against the thing it replaced rather than against a
// description of it — TestOTEProveUnchangedByTranspose pins the outputs equal
// and BenchmarkOTEProveViaGetColumn prices the difference in the same binary,
// on the same machine, in the same run.
//
// If oteProve's fold is ever changed on purpose, this must change with it and
// the test below is the reminder.
func oteProveViaGetColumn(sid string, T [][Xi / 8]byte, beta [Xi]bool, corrections [][Xi / 8]byte) oteConsistencyProof {
	chi := oteChallenge(sid, corrections)
	var tTilde, xTilde gf128
	for j := range Xi {
		tj := gf128FromBytes(getColumnLambdaC(T, j))
		tTilde = tTilde.add(tj.mul(chi[j]))
		if beta[j] {
			xTilde = xTilde.add(chi[j])
		}
	}
	return oteConsistencyProof{TTilde: tTilde.bytes(), XTilde: xTilde.bytes()}
}

// TestOTEProveUnchangedByTranspose is the equivalence statement at the level
// that matters on the wire: the consistency proof Bob transmits must be the
// identical 32 bytes it was before the layout change. A proof that differed by
// even one bit would mean the check is now verifying a different claim.
func TestOTEProveUnchangedByTranspose(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(31337))
	for i := 0; i < 200; i++ {
		T := randMatrix(rng)
		corrections := randMatrix(rng)
		var beta [Xi]bool
		for j := range beta {
			beta[j] = rng.Intn(2) == 1
		}
		sid := "equiv-sid-" + string(rune('A'+i%26))

		got, err := oteProve(sid, T, beta, corrections)
		require.NoError(t, err)
		require.Equalf(t, oteProveViaGetColumn(sid, T, beta, corrections), got,
			"iteration %d: transposed fold produced a different proof", i)
	}
}

// BenchmarkOTEProve and BenchmarkOTEProveViaGetColumn time one full KOS15 fold
// each — the heaviest of the four column passes, because every column also costs
// a GF(2^128) multiply. Their ratio is the check's share of the saving.
func BenchmarkOTEProve(b *testing.B) {
	rng := rand.New(rand.NewSource(2))
	T := randMatrix(rng)
	corrections := randMatrix(rng)
	var beta [Xi]bool
	for j := range beta {
		beta[j] = rng.Intn(2) == 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := oteProve("bench-sid", T, beta, corrections); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOTEProveViaGetColumn(b *testing.B) {
	rng := rand.New(rand.NewSource(2))
	T := randMatrix(rng)
	corrections := randMatrix(rng)
	var beta [Xi]bool
	for j := range beta {
		beta[j] = rng.Intn(2) == 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtimeSink = oteProveViaGetColumn("bench-sid", T, beta, corrections)
	}
}

// runtimeSink keeps benchmark results reachable so the compiler cannot delete
// the work being measured.
var runtimeSink any
