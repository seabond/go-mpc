package dkls23

// Column-major access to the OT-extension bit matrix.
//
// # Why anything here is hot
//
// The OT extension holds a LambdaC x Xi bit matrix — T on the receiver's side, Q
// on the sender's — stored row-major, one row per base OT, Xi bits to the row.
// Everything downstream wants COLUMNS: column j is OT instance j's LambdaC-bit
// string, and it is what gets hashed into that instance's seed and what gets
// folded into the KOS15 consistency check as an element of GF(2^128).
//
// So the whole matrix is read in the direction it is not stored, four times per
// directed VOLE instance per signing session:
//
//	oteProve            over T   (ote_consistency.go)
//	oteVerify           over Q   (ote_consistency.go)
//	OTExtSenderExpand   over Q   (ot_extension.go)
//	OTExtReceiverExpand over T   (ot_extension.go)
//
// Per session, because the OT extension is re-run per session — see prg in
// ot_extension.go for why that is not negotiable.
//
// # The layout change
//
// getColumnLambdaC below is the definition of a column: LambdaC bit tests, one
// per row, for one column. Doing that Xi times reads every bit of the matrix
// individually, LambdaC*Xi bit tests per pass. transposeLambdaCxXi produces all
// Xi columns in one pass instead, moving 64 bits at a time through 8x8 blocks.
//
// This is a change of memory layout and nothing else. The requirement is exact:
// transposeLambdaCxXi(m)[j] must be byte-identical to getColumnLambdaC(m, j) for
// every matrix m and every j. getColumnLambdaC is kept, unused by the protocol,
// precisely so that requirement has something to be checked against —
// TestTransposeMatchesGetColumn in bitmatrix_test.go is that check, and it is
// the whole correctness argument for this file.

// Both dimensions must be whole numbers of 8-bit blocks, and that is asserted
// here rather than assumed, because the two column readers DISAGREE about what
// happens when it is false and the new one disagrees in the dangerous direction.
//
// getColumnLambdaC walks k over all of LambdaC and indexes rows[k][j/8], so a Xi
// that is not a multiple of 8 makes it read past the row and PANIC — loud, and
// at the first signature. transposeLambdaCxXi walks whole blocks (jb < Xi/8,
// kb < LambdaC/8) and would simply not visit the remainder, leaving those output
// columns ALL ZERO: OTE instances whose t^j is a constant an attacker knows, so
// oteSeedHash derives a seed anyone can recompute and that instance's pad stops
// hiding anything. A parameter change is the plausible way to get there —
// LambdaS is a security parameter and Xi = Kappa + 2*LambdaS — so the failure is
// made a compile error instead of a silent one.
//
// These are the standard constant-overflow assertions: the expression is
// negative, and therefore not representable as uint, exactly when the modulus is
// nonzero.
const (
	_ = uint(0 - Xi%8)
	_ = uint(0 - LambdaC%8)
)

// getBit returns the bit at position j in a packed byte array (LSB-first).
func getBit(v [Xi / 8]byte, j int) bool {
	return (v[j/8]>>(uint(j)%8))&1 == 1
}

// getColumnLambdaC extracts column j of an LambdaC x Xi matrix stored as rows T[k] ∈ {0,1}^Xi.
// Returns LambdaC bits as a packed byte array (LambdaC/8 = 16 bytes).
//
// This is the reference definition of a column. The protocol reads columns
// through transposeLambdaCxXi instead, which must agree with this bit for bit.
func getColumnLambdaC(rows [][Xi / 8]byte, j int) []byte {
	out := make([]byte, LambdaC/8)
	for k := 0; k < LambdaC; k++ {
		if getBit(rows[k], j) {
			out[k/8] |= 1 << (uint(k) % 8)
		}
	}
	return out
}

// transpose8 reads x as an 8x8 bit matrix with element (r, c) at bit 8*r+c and
// returns that matrix transposed, so bit 8*r+c of the result is element (c, r)
// of the input.
//
// Three delta swaps, coarsest first: 4x4 quadrants, then the 2x2 blocks inside
// each quadrant, then single bits. Each is the standard exchange
//
//	t = (x ^ (x >> d)) & mask;  x ^= t ^ (t << d)
//
// which swaps the bits selected by mask with the bits d positions above them.
// For blocks of size b the partner sits b rows down and b columns left, i.e.
// d = 8*b - b: 28, 14, 7. The masks select, at each level, the block that has to
// travel down-left — 0x00000000F0F0F0F0 is rows 0..3 columns 4..7, and so on.
//
// This is its own inverse, and it is branchless and data-independent: the
// operation count does not depend on the matrix, which matters because T and Q
// are secret.
func transpose8(x uint64) uint64 {
	t := (x ^ (x >> 28)) & 0x00000000F0F0F0F0
	x ^= t ^ (t << 28)
	t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCC
	x ^= t ^ (t << 14)
	t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AA
	x ^= t ^ (t << 7)
	return x
}

// transposeLambdaCxXi transposes a LambdaC x Xi bit matrix given as LambdaC rows
// of Xi bits into Xi rows of LambdaC bits. Row j of the result is column j of the
// input: bit k of out[j] is bit j of rows[k]. Bits pack LSB-first within a byte
// in both directions, matching getColumnLambdaC.
//
// rows must have exactly LambdaC entries; every caller checks that before
// building the matrix, and a short slice panics here rather than reading
// garbage.
//
// The result is a fresh buffer the caller owns. It is a second copy of secret
// material, so callers erase it with zeroTransposed when the pass is done.
func transposeLambdaCxXi(rows [][Xi / 8]byte) *[Xi][LambdaC / 8]byte {
	_ = rows[LambdaC-1] // bounds check once, not once per row
	out := new([Xi][LambdaC / 8]byte)
	for kb := 0; kb < LambdaC/8; kb++ {
		blk := rows[kb*8 : kb*8+8 : kb*8+8]
		for jb := 0; jb < Xi/8; jb++ {
			// Gather the 8x8 block at rows kb*8..kb*8+7, columns jb*8..jb*8+7.
			// Row r contributes its byte jb at bit offset 8*r, which places input
			// element (r, c) at bit 8*r+c — the layout transpose8 expects.
			w := uint64(blk[0][jb]) |
				uint64(blk[1][jb])<<8 |
				uint64(blk[2][jb])<<16 |
				uint64(blk[3][jb])<<24 |
				uint64(blk[4][jb])<<32 |
				uint64(blk[5][jb])<<40 |
				uint64(blk[6][jb])<<48 |
				uint64(blk[7][jb])<<56

			w = transpose8(w)

			// Scatter: byte c of the result is the block's column jb*8+c, whose
			// bit r is row kb*8+r. That is byte kb of output row jb*8+c.
			col := out[jb*8 : jb*8+8 : jb*8+8]
			col[0][kb] = byte(w)
			col[1][kb] = byte(w >> 8)
			col[2][kb] = byte(w >> 16)
			col[3][kb] = byte(w >> 24)
			col[4][kb] = byte(w >> 32)
			col[5][kb] = byte(w >> 40)
			col[6][kb] = byte(w >> 48)
			col[7][kb] = byte(w >> 56)
		}
	}
	return out
}

// zeroTransposed erases a transposed OTE matrix.
//
// The transpose is a second copy of T or Q, both secret, in one contiguous
// buffer. The per-column reads it replaces left Xi separate 16-byte copies of
// the same bits scattered across the heap and erased none of them, so clearing
// the one buffer gives back ground that used to be conceded. As everywhere else
// in this package, this is a best effort: Go may have copied the buffer during a
// stack or heap move, and nothing here can reach those copies.
func zeroTransposed(m *[Xi][LambdaC / 8]byte) {
	for j := range m {
		m[j] = [LambdaC / 8]byte{}
	}
}
