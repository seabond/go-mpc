package dkls23

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"
)

// --- IKNP OT Extension realizing FEOTE(Zq^{Ell+Rho}, Xi) ---
//
// After base OT setup (LambdaC instances):
//   - VOLE Bob was the base OT sender; he has seeds0[k], seeds1[k] for each k.
//   - VOLE Alice was the base OT receiver with choices sigma; she has aliceSeeds[k] = K^{sigma[k]}_k.
//
// This extension produces Xi OTs with Ell+Rho Zq-element outputs each.

// prg expands a 32-byte seed to Xi bits (Xi/8 = 52 bytes) using SHAKE256.
// The domain is "ote-prg" to avoid collisions with other hash calls.
//
// sid binds the expansion to ONE signing session, and it is load-bearing rather
// than hygiene. The base OT is reused across sessions by design, so without sid
// this is a pure function of a fixed seed: T_k and Q_k are constants, every
// column takes one of two fixed values, and alpha0/alpha1 collapse to four fixed
// pads per index selected only by beta[j]. Sampling a fresh beta then re-selects
// among the SAME pads instead of producing new ones — so any two sessions whose
// beta agrees at index j reuse that pad exactly. Since VOLEAliceMultiply sends
// aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i], subtracting two such
// sessions cancels the pads and yields the difference of Alice's inputs. a[0] is
// her nonce share, so a counterparty learns the difference of two ECDSA nonces
// and recovers the private key by textbook algebra.
//
// Bob chooses beta himself, so he knows exactly which half of the 416 indices
// repeat. Two ordinary signatures suffice.
func prg(sid string, seed []byte) [Xi / 8]byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTEPRG))
	h.Write([]byte(sid))
	h.Write([]byte{0x00}) // separator: sid and seed cannot run together
	h.Write(seed)
	var out [Xi / 8]byte
	h.Read(out[:])
	return out
}

// xorBitVec XORs two Xi-bit vectors (Xi/8 bytes each).
func xorBitVec(a, b [Xi / 8]byte) [Xi / 8]byte {
	var out [Xi / 8]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// boolsToBitVec converts [Xi]bool to a packed byte array (LSB-first per byte).
func boolsToBitVec(beta [Xi]bool) [Xi / 8]byte {
	var out [Xi / 8]byte
	for j, b := range beta {
		if b {
			out[j/8] |= 1 << (uint(j) % 8)
		}
	}
	return out
}

// Column reads of the LambdaC x Xi matrix live in bitmatrix.go.

// oteHasher is one SHAKE256 state and the scratch it absorbs through, reused
// across an expansion's thousands of hashes.
//
// It exists for a measured reason, not for tidiness. Each expansion makes
// Xi = 416 seed hashes and Xi*(Ell+Rho) = 1 664 expand hashes, and the
// straightforward form — a fresh state per call, a `[]byte(domain)` conversion
// per call, a `[]byte{0x00}` per call, a heap `raw` per call — allocated roughly
// eight objects on each one. That was the bulk of everything SignRound1
// allocated, and on a build with runtime/secret erasure active the sweep at the
// end of every Do is proportional to exactly that.
//
// The digest is UNCHANGED. A hash absorbs a byte stream, so one Write of
// domain‖sid‖0x00‖choice‖j[‖i]‖tail is the same input as the six Writes it
// replaced; TestOTEHasherMatchesTheHashesItReplaced pins that against the
// original form.
//
// It is not safe for concurrent use, and must not be: two goroutines sharing one
// would interleave their absorbs and produce pads neither party can reproduce.
// Each expansion builds its own.
type oteHasher struct {
	h sha3.ShakeHash
	// buf holds domain‖sid‖0x00 in its first pre bytes, then whatever this call
	// appends. Kept at full capacity between calls so the append never reallocates.
	buf []byte
	pre int
	// raw is the XOF output, a field rather than a local so that handing it to
	// h.Read — an interface method, which escape analysis cannot see into — does
	// not allocate on every call.
	raw [64]byte
}

func newOTEHasher(domain, sid string, tail int) *oteHasher {
	buf := make([]byte, 0, len(domain)+len(sid)+1+1+8+8+tail)
	buf = append(buf, domain...)
	buf = append(buf, sid...)
	buf = append(buf, 0x00) // separator: sid and what follows cannot run together
	return &oteHasher{h: sha3.NewShake256(), buf: buf, pre: len(buf)}
}

// zero erases the scratch this hasher accumulated. Callers defer it, the way
// they already defer zeroTransposed on the matrix that feeds it.
//
// It is needed because the scratch is a verbatim copy of material this package
// erases elsewhere: after a seedHash, buf's tail holds the transposed T/Q column
// that zeroTransposed exists to wipe, and after an expandHash it holds the
// derived OTE seed while raw holds the 64-byte pre-reduction pad. zeroize.go's
// own header says dropping the reference was never erasure, so the reused
// buffer that made this hasher fast must be wiped the way a per-call buffer's
// garbage would not have to be.
//
// buf is wiped to its full capacity, not its length: seedHash and expandHash
// leave it re-sliced to whatever the last call appended, and the bytes past that
// length are the previous call's column.
func (o *oteHasher) zero() {
	zeroBytes(o.buf[:cap(o.buf)])
	zeroBytes(o.raw[:])
}

// absorb resets the state and feeds it the constant prefix plus this call's
// suffix, leaving the buffer ready for the next one.
func (o *oteHasher) absorb(suffix []byte) {
	o.h.Reset()
	o.h.Write(suffix)
}

// seedHash computes SHAKE256("ote-seed" || choice_byte || j_bytes || col_bytes) → 32 bytes.
// choice goes through condUint32, which compiles to a byte move rather than a
// branch — see its comment, because on the receiver's side that bit is secret.
func (o *oteHasher) seedHash(choice bool, j int, col []byte) [32]byte {
	b := append(o.buf[:o.pre], byte(condUint32(choice)))
	b = binary.BigEndian.AppendUint64(b, uint64(j))
	b = append(b, col...)
	o.buf = b
	o.absorb(b)
	var out [32]byte
	o.h.Read(o.raw[:32])
	copy(out[:], o.raw[:32])
	return out
}

// expandHash computes SHAKE256("ote-expand" || choice_byte || j || i || seed) mod q → 32 bytes.
// choice goes through condUint32, which compiles to a byte move rather than a
// branch — see its comment, because on the receiver's side that bit is secret.
//
// The reduction is reduce64Scalar, not math/big: the same value, and where this
// function's remaining cost was — `big.nat.make` under it was 52 % of every byte
// SignRound1 allocated.
func (o *oteHasher) expandHash(choice bool, j, i int, seed []byte) [32]byte {
	b := append(o.buf[:o.pre], byte(condUint32(choice)))
	b = binary.BigEndian.AppendUint64(b, uint64(j))
	b = binary.BigEndian.AppendUint64(b, uint64(i))
	b = append(b, seed...)
	o.buf = b
	o.absorb(b)
	o.h.Read(o.raw[:])
	s := reduce64Scalar(&o.raw)
	return s.Bytes()
}

// OTExtReceiverCorrections computes Bob's correction vectors for IKNP OT extension.
// Bob uses his base OT sender seeds (bobSeeds0, bobSeeds1) and his OTE input beta ∈ {0,1}^Xi.
// For each k ∈ [LambdaC]:
//   - T_k = PRG(K^0_k) ∈ {0,1}^Xi
//   - U_k = T_k XOR PRG(K^1_k) XOR beta_bitvector
//
// Returns corrections[k] = U_k which are sent to Alice.
// This corresponds to the receiver's first message in IKNP OT extension (paper §4 / FEOTE).
// It also returns the consistency proof that ONE beta went into every row.
// Without it the corrections are unverifiable and a malicious receiver reads a
// bit of the sender's long-term choice vector per session; see ote_consistency.go.
func OTExtReceiverCorrections(sid string, bobSeeds0, bobSeeds1 [][]byte, beta [Xi]bool) (corrections [][Xi / 8]byte, proof oteConsistencyProof, err error) {
	if len(bobSeeds0) != LambdaC || len(bobSeeds1) != LambdaC {
		return nil, oteConsistencyProof{}, errors.New("dkls23 OTExtReceiverCorrections: bobSeeds must have LambdaC entries")
	}
	betaVec := boolsToBitVec(beta)
	corrections = make([][Xi / 8]byte, LambdaC)
	T := make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		T_k := prg(sid, bobSeeds0[k])
		prg1_k := prg(sid, bobSeeds1[k])
		// U_k = T_k XOR PRG(K^1_k) XOR beta
		U_k := xorBitVec(xorBitVec(T_k, prg1_k), betaVec)
		corrections[k] = U_k
		T[k] = T_k
	}
	proof, err = oteProve(sid, T, beta, corrections)
	if err != nil {
		return nil, oteConsistencyProof{}, err
	}
	return corrections, proof, nil
}

// OTExtSenderExpand expands Alice's OTE seeds into Zq-element output pairs.
// Alice uses her base OT receiver seeds aliceSeeds[k] = K^{sigma[k]}_k.
// For each k: Q_k = PRG(K^{sigma_k}_k) XOR (sigma_k * corrections[k])
// [equivalently Q_k = PRG(K^0_k) XOR sigma_k*beta_bitvector]
//
// The output alpha0[j][i] and alpha1[j][i] are the two OT messages for OT index j,
// element index i. They are computed by hashing the columns of Q.
// This is the sender's expansion step in IKNP OT extension.
// It REFUSES corrections that fail the consistency proof. That check is not
// optional hardening: IKNP on its own is secure only against a receiver who
// follows the protocol, and a receiver who does not reads one bit of sigma per
// session off whether his own downstream check passes. sigma is long-lived, the
// bits accumulate, and the sender cannot attribute any of it. See
// ote_consistency.go.
func OTExtSenderExpand(sid string, aliceSeeds [][]byte, sigma []bool, corrections [][Xi / 8]byte, proof oteConsistencyProof) (alpha0, alpha1 [][Ell + Rho][32]byte, err error) {
	if len(aliceSeeds) != LambdaC || len(sigma) != LambdaC || len(corrections) != LambdaC {
		return nil, nil, errors.New("dkls23 OTExtSenderExpand: length mismatch")
	}

	// Compute Q matrix: each row Q[k] ∈ {0,1}^Xi
	Q := make([][Xi / 8]byte, LambdaC)
	// sigma as bit vector for XOR
	var sigmaVecLambdaC [LambdaC / 8]byte
	for k, s := range sigma {
		if s {
			sigmaVecLambdaC[k/8] |= 1 << (uint(k) % 8)
		}
	}

	for k := 0; k < LambdaC; k++ {
		Q[k] = prg(sid, aliceSeeds[k])
		if sigma[k] {
			Q[k] = xorBitVec(Q[k], corrections[k])
		}
	}

	// Verified against the Q she just built, and BEFORE a single pad is derived
	// from it: a check that ran after the expansion would be a check on values the
	// caller already holds.
	if err := oteVerify(sid, Q, sigma, corrections, proof); err != nil {
		return nil, nil, err
	}

	// sigma_vec ∈ {0,1}^LambdaC as LambdaC/8 bytes (for column XOR)
	sigmaColBytes := make([]byte, LambdaC/8)
	for k := 0; k < LambdaC; k++ {
		if sigma[k] {
			sigmaColBytes[k/8] |= 1 << (uint(k) % 8)
		}
	}

	alpha0 = make([][Ell + Rho][32]byte, Xi)
	alpha1 = make([][Ell + Rho][32]byte, Xi)

	// All Xi columns of Q in one pass; qCols[j] is column j. See bitmatrix.go.
	qCols := transposeLambdaCxXi(Q)
	defer zeroTransposed(qCols)

	// Two reused SHAKE256 states for every hash this loop makes; see oteHasher.
	// Their scratch holds copies of the same column material qCols does, so it is
	// erased on the same terms.
	sh := newOTEHasher(domainOTESeed, sid, LambdaC/8)
	eh := newOTEHasher(domainOTEExpand, sid, 32)
	defer sh.zero()
	defer eh.zero()
	for j := 0; j < Xi; j++ {
		// q^j = column j of Q matrix ∈ {0,1}^LambdaC
		qj := qCols[j][:]

		// q^j XOR sigma_vec
		var qjXorSigma [LambdaC / 8]byte
		for b := range qjXorSigma {
			qjXorSigma[b] = qj[b] ^ sigmaColBytes[b]
		}

		seed0j := sh.seedHash(false, j, qj)
		seed1j := sh.seedHash(true, j, qjXorSigma[:])

		for i := 0; i < Ell+Rho; i++ {
			alpha0[j][i] = eh.expandHash(false, j, i, seed0j[:])
			alpha1[j][i] = eh.expandHash(true, j, i, seed1j[:])
		}
	}
	return
}

// OTExtReceiverExpand computes Bob's received OTE values.
// For each j ∈ [Xi]:
//   - t^j = column j of T matrix (where T_k = PRG(K^0_k))
//   - bob_seed_j = SHAKE256("ote-seed" || beta[j] || j || t^j) → 32 bytes
//   - gamma[j][i] = oteExpandHash(beta[j], j, i, bob_seed_j) mod q
//
// This equals alpha0[j][i] when beta[j]=false, alpha1[j][i] when beta[j]=true,
// realizing the OTE correctness property.
func OTExtReceiverExpand(sid string, bobSeeds0 [][]byte, beta [Xi]bool, corrections [][Xi / 8]byte) (gamma [][Ell + Rho][32]byte, err error) {
	if len(bobSeeds0) != LambdaC || len(corrections) != LambdaC {
		return nil, errors.New("dkls23 OTExtReceiverExpand: length mismatch")
	}

	// Compute T matrix: T[k] = PRG(K^0_k)
	T := make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		T[k] = prg(sid, bobSeeds0[k])
	}

	// All Xi columns of T in one pass; tCols[j] is column j. See bitmatrix.go.
	tCols := transposeLambdaCxXi(T)
	defer zeroTransposed(tCols)

	gamma = make([][Ell + Rho][32]byte, Xi)
	// Two reused SHAKE256 states for every hash this loop makes; see oteHasher.
	// Their scratch holds copies of the same column material tCols does, so it is
	// erased on the same terms.
	sh := newOTEHasher(domainOTESeed, sid, LambdaC/8)
	eh := newOTEHasher(domainOTEExpand, sid, 32)
	defer sh.zero()
	defer eh.zero()
	for j := 0; j < Xi; j++ {
		tj := tCols[j][:]
		bobSeedJ := sh.seedHash(beta[j], j, tj)
		for i := 0; i < Ell+Rho; i++ {
			gamma[j][i] = eh.expandHash(beta[j], j, i, bobSeedJ[:])
		}
	}
	return
}
