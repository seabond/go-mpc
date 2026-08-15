// Package dkls23 implements the DKLS23 threshold ECDSA protocol from
// "Threshold ECDSA in Three Rounds" by Doerner, Kondi, Lee, and shelat
// (https://eprint.iacr.org/2023/765.pdf).
//
// # Protocol components
//
//   - 2-round DKG using Feldman VSS (Protocol 7.1)
//   - 3-round threshold signing (Protocol 3.6)
//   - Pairwise VOLE setup via base OT + OT extension (Section 5)
//   - Proactive key refresh following KMOS21
//
// # Security model
//
// The protocol operates in a t-of-n threshold setting over secp256k1.
// All secret scalar arithmetic uses constant-time ModNScalar operations.
// Cheating parties are detected during the VOLE consistency check and
// the R-commitment decommitment phase; detected parties are blacklisted
// and excluded from future sessions.
//
// # Concurrency
//
// [SignerSetup] is safe for concurrent reads (parallel signing sessions).
// Mutating operations such as key refresh and party blacklisting acquire
// a write lock internally.
//
// # Usage flow
//
// DKG -> pairwise VOLE/FZero setup -> signing -> optional refresh.
// See the example/ directory for a runnable demonstration.
package dkls23

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Security parameters per DKLS23 §2 / Appendix A.
const (
	// Kappa is the bit-length of the curve order q for secp256k1.
	Kappa = 256
	// LambdaC is the computational security parameter.
	LambdaC = 128
	// LambdaS is the statistical security parameter.
	LambdaS = 80
	// Xi is the number of OT instances per VOLE invocation: Kappa + 2*LambdaS.
	Xi = Kappa + 2*LambdaS // 416
	// Rho is the number of VOLE check elements: ceil(Kappa/LambdaC).
	Rho = 2
	// Ell is the number of VOLE inputs: {r_i, sk_i}.
	Ell = 2
	// SaltLen is the byte length of FCom salts: 2*LambdaC/8 bytes.
	SaltLen = 32
	// baseOTSeedLen is the byte length of a base OT seed, as produced by
	// shake256Seed in ot.go.
	baseOTSeedLen = 32
)

// Domain separation tags for all hash/XOF calls in the protocol.
// Centralized here to prevent accidental collisions.
const (
	domainBaseOT       = "base-ot"
	domainOTEPRG       = "ote-prg"
	domainOTESeed      = "ote-seed"
	domainOTEExpand    = "ote-expand"
	domainOTECheck     = "ote-check"
	domainVOLEFS       = "vole-fs"
	domainVOLEProof    = "vole-proof"
	domainVOLERefresh  = "vole-refresh"
	domainFZero        = "fzero"
	domainFZeroRefresh = "fzero-refresh"
)

// curveOrder is the secp256k1 group order q.
// Retained for the 64-byte hash reduction in reduce64Public and oteExpandHash.
var curveOrder = btcec.S256().N

// gadget is the precomputed gadget vector g[j] = 2^j mod q for j in [0, Xi).
// It is used for the binary decomposition inner product in VOLE.
var gadget [Xi]btcec.ModNScalar

func init() {
	var two btcec.ModNScalar
	two.SetInt(2)
	var cur btcec.ModNScalar
	cur.SetInt(1)
	for j := 0; j < Xi; j++ {
		gadget[j].Set(&cur)
		cur.Mul(&two)
	}
}

// GadgetInnerProduct computes <g, beta> mod q, where g[j] = 2^j mod q.
// This is equivalent to the integer whose binary representation is beta,
// reduced modulo q. It is used in VOLE to convert the OTE's binary
// input beta into a field element chi (paper §5.2).
//
// The computation is branchless: each beta bit selects gadget[j] via
// constant-time scalar multiplication by 0 or 1.
func GadgetInnerProduct(beta [Xi]bool) btcec.ModNScalar {
	var acc btcec.ModNScalar
	for j := 0; j < Xi; j++ {
		var mask btcec.ModNScalar
		mask.SetInt(condUint32(beta[j]))
		var term btcec.ModNScalar
		term.Mul2(&mask, &gadget[j])
		acc.Add(&term)
	}
	return acc
}

// condUint32 returns 1 if b is true, 0 otherwise.
// On Go 1.20+ this compiles to a branchless conditional-move instruction
// (CSEL on ARM64, CMOV on x86-64).
func condUint32(b bool) uint32 {
	var v uint32
	if b {
		v = 1
	}
	return v
}

// orderMinus2 is q-2 for the secp256k1 group order, used by scalarInverse.
// q   = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// q-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F
var orderMinus2 = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
}

// scalarInverse computes val^(-1) mod q in constant time using Fermat's
// little theorem: a^(-1) = a^(q-2) mod q for prime q.
//
// The exponent q-2 is a public constant, so the square-and-multiply
// loop's branch pattern is fixed and leaks no information about val.
// All arithmetic uses constant-time ModNScalar.Square and ModNScalar.Mul.
//
// This replaces btcec's InverseValNonConst, which uses math/big internally.
func scalarInverse(val *btcec.ModNScalar) btcec.ModNScalar {
	var result btcec.ModNScalar
	result.SetInt(1)
	for i := 0; i < 32; i++ {
		for bit := 7; bit >= 0; bit-- {
			result.Square()
			if (orderMinus2[i]>>uint(bit))&1 == 1 {
				result.Mul(val)
			}
		}
	}
	return result
}

// reduce64Public reduces a 64-byte big-endian value modulo the secp256k1 group order
// and returns the result as a ModNScalar. This is used for Fiat-Shamir challenge
// derivation and FZero hashing where the input is a public hash output, so the
// non-constant-time big.Int reduction is acceptable.
func reduce64Public(b []byte) btcec.ModNScalar {
	v := new(big.Int).SetBytes(b)
	v.Mod(v, curveOrder)
	var buf [32]byte
	v.FillBytes(buf[:])
	var s btcec.ModNScalar
	s.SetBytes(&buf)
	return s
}

// twoTo256ModQ is 2^256 mod q: the weight the high half of a 512-bit value
// carries once it is folded into the group.
var twoTo256ModQ = func() btcec.ModNScalar {
	v := new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 256), curveOrder)
	var buf [32]byte
	v.FillBytes(buf[:])
	var s btcec.ModNScalar
	s.SetBytes(&buf)
	return s
}()

// reduce64Scalar is reduce64Public without math/big: it splits the 64 bytes into
// two 256-bit halves, reduces each with ModNScalar.SetBytes, and recombines them
// as hi*2^256 + lo. That is an identity, not an approximation — (hi mod q) *
// (2^256 mod q) + (lo mod q) ≡ hi*2^256 + lo (mod q) — and
// TestReduce64ScalarMatchesBigInt pins it against the big.Int form over random
// inputs.
//
// It exists because oteExpandHash calls this Xi*(Ell+Rho) = 1 664 times per OT
// extension and the big.Int form allocated on every one: `math/big.nat.make`
// under it was 52 % of every byte SignRound1 allocated. The package already
// replaced btcec's big.Int inverse for the same reason; see scalarInverse.
//
// Like reduce64Public it is not constant time in the sense that btcec's own
// SetBytes is not, and it is used on the same kind of value: an OT-extension pad
// derived from a hash, where the reduction's timing carries no secret the
// counterparty does not already hold. It must NOT be reached for a long-lived
// key.
func reduce64Scalar(b *[64]byte) btcec.ModNScalar {
	var hi, lo btcec.ModNScalar
	hi.SetBytes((*[32]byte)(b[0:32]))
	lo.SetBytes((*[32]byte)(b[32:64]))
	hi.Mul(&twoTo256ModQ)
	hi.Add(&lo)
	return hi
}
