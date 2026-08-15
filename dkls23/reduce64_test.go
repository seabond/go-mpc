package dkls23

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// reduce64Scalar replaced a math/big reduction inside the OT extension, where a
// wrong answer would be a wrong pad, an unverifiable signature, and — if it were
// wrong only sometimes — an intermittent one. So the property is exact agreement
// with the arithmetic it replaced, over the boundaries and over random inputs.

func reduce64ViaBigInt(b *[64]byte) btcec.ModNScalar {
	v := new(big.Int).SetBytes(b[:])
	v.Mod(v, curveOrder)
	var buf [32]byte
	v.FillBytes(buf[:])
	var s btcec.ModNScalar
	s.SetBytes(&buf)
	return s
}

func TestReduce64ScalarMatchesBigInt(t *testing.T) {
	t.Parallel()

	var cases [][64]byte
	add := func(v *big.Int) {
		var b [64]byte
		v.FillBytes(b[:])
		cases = append(cases, b)
	}
	q := curveOrder
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	add(big.NewInt(0))
	add(big.NewInt(1))
	add(new(big.Int).Sub(q, big.NewInt(1)))
	add(q)
	add(new(big.Int).Add(q, big.NewInt(1)))
	add(new(big.Int).Sub(two256, big.NewInt(1)))
	add(two256)
	add(new(big.Int).Add(two256, big.NewInt(1)))
	add(new(big.Int).Mul(q, q))
	// All ones: the largest 512-bit value there is.
	all := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 512), big.NewInt(1))
	add(all)

	for i := 0; i < 20000; i++ {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, b)
	}

	for i, b := range cases {
		got := reduce64Scalar(&b)
		want := reduce64ViaBigInt(&b)
		if !got.Equals(&want) {
			gb, wb := got.Bytes(), want.Bytes()
			t.Fatalf("case %d: reduce64Scalar(%x) = %x, big.Int gives %x", i, b, gb, wb)
		}
	}
}

// The public helper reduce64Public still uses math/big, so the two must agree
// too — otherwise a later edit that swaps one for the other silently changes a
// Fiat-Shamir challenge.
func TestReduce64ScalarAgreesWithReduce64Public(t *testing.T) {
	t.Parallel()
	for i := 0; i < 2000; i++ {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		got := reduce64Scalar(&b)
		want := reduce64Public(b[:])
		if !got.Equals(&want) {
			t.Fatalf("reduce64Scalar and reduce64Public disagree on %x", b)
		}
	}
}

func BenchmarkReduce64Scalar(b *testing.B) {
	var in [64]byte
	if _, err := rand.Read(in[:]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reduce64Scalar(&in)
	}
}

func BenchmarkReduce64BigInt(b *testing.B) {
	var in [64]byte
	if _, err := rand.Read(in[:]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reduce64ViaBigInt(&in)
	}
}
