package dkls23

import "encoding/binary"

// GF(2^128) arithmetic, for the OT-extension consistency check.
//
// The check needs a random linear combination over a field large enough that a
// cheating receiver cannot pass it by luck. Over GF(2) — random subsets — a
// cheat survives with probability 1/2 per trial, so a useful bound needs many
// repetitions and the analysis is delicate. Over GF(2^128) one combination gives
// 2^-128, which is the whole reason KOS15 works in this field.
//
// The field is GF(2)[X]/(X^128 + X^7 + X^2 + X + 1), the same polynomial GHASH
// uses. Element bit order is the natural one for this code rather than GHASH's
// reflected order: a 16-byte value is read big-endian into two 64-bit limbs,
// hi holding X^127..X^64 and lo holding X^63..X^0, with the LOW bit of lo being
// the constant term. Nothing here interoperates with GHASH, so the reflected
// convention would buy nothing and cost a reversal on every operation.

// gf128 is one field element. hi is the high 64 coefficients, lo the low 64.
type gf128 struct{ hi, lo uint64 }

// gf128FromBytes reads a 16-byte big-endian value. Input shorter than 16 bytes
// is right-aligned; longer input is truncated to its last 16 bytes. Both cases
// exist only so callers can hand over a fixed-size vector without a conversion
// dance, and neither arises in the protocol, where every input is exactly
// LambdaC/8 bytes.
func gf128FromBytes(b []byte) gf128 {
	var buf [16]byte
	switch {
	case len(b) >= 16:
		copy(buf[:], b[len(b)-16:])
	default:
		copy(buf[16-len(b):], b)
	}
	return gf128{
		hi: binary.BigEndian.Uint64(buf[0:8]),
		lo: binary.BigEndian.Uint64(buf[8:16]),
	}
}

// bytes renders the element as 16 bytes, big-endian.
func (a gf128) bytes() [16]byte {
	var out [16]byte
	binary.BigEndian.PutUint64(out[0:8], a.hi)
	binary.BigEndian.PutUint64(out[8:16], a.lo)
	return out
}

// add is XOR: in characteristic 2 addition and subtraction are the same
// operation, which is why the check needs no negation anywhere.
func (a gf128) add(b gf128) gf128 { return gf128{hi: a.hi ^ b.hi, lo: a.lo ^ b.lo} }

func (a gf128) isZero() bool { return a.hi == 0 && a.lo == 0 }

func (a gf128) equal(b gf128) bool { return a.hi == b.hi && a.lo == b.lo }

// clmul64 is a carry-less multiply of two 64-bit values, returning the 128-bit
// product as (hi, lo).
//
// Written as shift-and-XOR rather than with CPU carry-less multiply
// instructions (PMULL on arm64, PCLMULQDQ on amd64), because the alternative is
// assembly per architecture.
//
// That is a real cost and should be read as a debt, not as a free choice. An
// earlier version of this comment said the check "is not on a hot path: the
// check runs once per VOLE instance". That was wrong. The OT extension, and with
// it this check, is re-derived once per SIGNING SESSION per directed pair — see
// freshBobForSession in sign.go and prg in ot_extension.go for why it has to be.
// One pass folds Xi = 416 field elements and each mul is four clmul64 calls of
// 64 iterations apiece, so a single 2-of-3 signature spins this loop on the
// order of a million times, and it is visible in a CPU profile of the ceremony.
// Replacing it with intrinsics is worth doing; the correctness bar is that the
// differential tests against the math/big reference in gf128_test.go still pass.
//
// It is NOT constant time with respect to b — the branch is on b's bits. That is
// deliberate and sound here: every value multiplied in this check is either
// public (the Fiat-Shamir challenge) or is being sent on the wire in the same
// message. Nothing secret is ever an operand. Anywhere that changes, this needs
// to change with it.
func clmul64(a, b uint64) (hi, lo uint64) {
	for i := 0; i < 64; i++ {
		if b&(1<<uint(i)) != 0 {
			lo ^= a << uint(i)
			if i > 0 {
				hi ^= a >> uint(64-i)
			}
		}
	}
	return
}

// mul multiplies in GF(2^128): carry-less product to 256 bits, then reduce.
func (a gf128) mul(b gf128) gf128 {
	// Schoolbook over 64-bit limbs. z is the 256-bit product, z0 lowest.
	ll_h, ll_l := clmul64(a.lo, b.lo)
	hh_h, hh_l := clmul64(a.hi, b.hi)
	lh_h, lh_l := clmul64(a.lo, b.hi)
	hl_h, hl_l := clmul64(a.hi, b.lo)

	mid_h := lh_h ^ hl_h
	mid_l := lh_l ^ hl_l

	z0 := ll_l
	z1 := ll_h ^ mid_l
	z2 := hh_l ^ mid_h
	z3 := hh_h

	return gf128Reduce(z3, z2, z1, z0)
}

// gf128Reduce reduces a 256-bit carry-less product modulo
// X^128 + X^7 + X^2 + X + 1.
//
// Every bit at position 128+i folds back as X^(128+i) = X^i * (X^7+X^2+X+1),
// so a high limb contributes itself shifted left by 7, 2, 1 and 0. Folding is
// done twice because the first pass can push bits back above 128 — the shifts
// are at most 7, so a second pass always finishes.
func gf128Reduce(z3, z2, z1, z0 uint64) gf128 {
	fold := func(hi, lo, h, l uint64) (uint64, uint64) {
		// XOR in (h:l) * X^s for s in {7,2,1,0}, where (h:l) sits at X^128.
		for _, s := range [4]uint{7, 2, 1, 0} {
			if s == 0 {
				hi ^= h
				lo ^= l
				continue
			}
			hi ^= (h << s) | (l >> (64 - s))
			lo ^= l << s
		}
		return hi, lo
	}
	// First pass: fold the top 128 bits (z3:z2) down.
	hi, lo := z1, z0
	hi, lo = fold(hi, lo, z3, z2)
	// The fold shifted (z3:z2) left by up to 7, so bits may have moved above
	// X^128 again. Those live in the top 7 bits of the shifted z3 term.
	var carryHi, carryLo uint64
	for _, s := range [3]uint{7, 2, 1} {
		carryLo ^= z3 >> (64 - s)
	}
	_ = carryHi
	if carryLo != 0 {
		hi, lo = fold(hi, lo, 0, carryLo)
	}
	return gf128{hi: hi, lo: lo}
}
