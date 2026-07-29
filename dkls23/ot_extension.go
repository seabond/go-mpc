package dkls23

import (
	"encoding/binary"
	"errors"
	"math/big"

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

// getBit returns the bit at position j in a packed byte array (LSB-first).
func getBit(v [Xi / 8]byte, j int) bool {
	return (v[j/8]>>(uint(j)%8))&1 == 1
}

// getColumnLambdaC extracts column j of an LambdaC x Xi matrix stored as rows T[k] ∈ {0,1}^Xi.
// Returns LambdaC bits as a packed byte array (LambdaC/8 = 16 bytes).
func getColumnLambdaC(rows [][Xi / 8]byte, j int) []byte {
	out := make([]byte, LambdaC/8)
	for k := 0; k < LambdaC; k++ {
		if getBit(rows[k], j) {
			out[k/8] |= 1 << (uint(k) % 8)
		}
	}
	return out
}

// oteSeedHash computes SHAKE256("ote-seed" || choice_byte || j_bytes || col_bytes) → 32 bytes.
// The choice bit is written branchlessly.
func oteSeedHash(sid string, choice bool, j int, col []byte) []byte {
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

// oteExpandHash computes SHAKE256("ote-expand" || choice_byte || j || i || seed) mod q → stored in 32 bytes.
// The choice bit is written branchlessly.
func oteExpandHash(sid string, choice bool, j, i int, seed []byte) [32]byte {
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

// OTExtReceiverCorrections computes Bob's correction vectors for IKNP OT extension.
// Bob uses his base OT sender seeds (bobSeeds0, bobSeeds1) and his OTE input beta ∈ {0,1}^Xi.
// For each k ∈ [LambdaC]:
//   - T_k = PRG(K^0_k) ∈ {0,1}^Xi
//   - U_k = T_k XOR PRG(K^1_k) XOR beta_bitvector
//
// Returns corrections[k] = U_k which are sent to Alice.
// This corresponds to the receiver's first message in IKNP OT extension (paper §4 / FEOTE).
func OTExtReceiverCorrections(sid string, bobSeeds0, bobSeeds1 [][]byte, beta [Xi]bool) (corrections [][Xi / 8]byte, err error) {
	if len(bobSeeds0) != LambdaC || len(bobSeeds1) != LambdaC {
		return nil, errors.New("dkls23 OTExtReceiverCorrections: bobSeeds must have LambdaC entries")
	}
	betaVec := boolsToBitVec(beta)
	corrections = make([][Xi / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		T_k := prg(sid, bobSeeds0[k])
		prg1_k := prg(sid, bobSeeds1[k])
		// U_k = T_k XOR PRG(K^1_k) XOR beta
		U_k := xorBitVec(xorBitVec(T_k, prg1_k), betaVec)
		corrections[k] = U_k
	}
	return
}

// OTExtSenderExpand expands Alice's OTE seeds into Zq-element output pairs.
// Alice uses her base OT receiver seeds aliceSeeds[k] = K^{sigma[k]}_k.
// For each k: Q_k = PRG(K^{sigma_k}_k) XOR (sigma_k * corrections[k])
// [equivalently Q_k = PRG(K^0_k) XOR sigma_k*beta_bitvector]
//
// The output alpha0[j][i] and alpha1[j][i] are the two OT messages for OT index j,
// element index i. They are computed by hashing the columns of Q.
// This is the sender's expansion step in IKNP OT extension.
func OTExtSenderExpand(sid string, aliceSeeds [][]byte, sigma []bool, corrections [][Xi / 8]byte) (alpha0, alpha1 [][Ell + Rho][32]byte, err error) {
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

	// sigma_vec ∈ {0,1}^LambdaC as LambdaC/8 bytes (for column XOR)
	sigmaColBytes := make([]byte, LambdaC/8)
	for k := 0; k < LambdaC; k++ {
		if sigma[k] {
			sigmaColBytes[k/8] |= 1 << (uint(k) % 8)
		}
	}

	alpha0 = make([][Ell + Rho][32]byte, Xi)
	alpha1 = make([][Ell + Rho][32]byte, Xi)

	for j := 0; j < Xi; j++ {
		// q^j = column j of Q matrix ∈ {0,1}^LambdaC
		qj := getColumnLambdaC(Q, j)

		// q^j XOR sigma_vec
		qjXorSigma := make([]byte, LambdaC/8)
		for b := range qjXorSigma {
			qjXorSigma[b] = qj[b] ^ sigmaColBytes[b]
		}

		seed0j := oteSeedHash(sid, false, j, qj)
		seed1j := oteSeedHash(sid, true, j, qjXorSigma)

		for i := 0; i < Ell+Rho; i++ {
			alpha0[j][i] = oteExpandHash(sid, false, j, i, seed0j)
			alpha1[j][i] = oteExpandHash(sid, true, j, i, seed1j)
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

	gamma = make([][Ell + Rho][32]byte, Xi)
	for j := 0; j < Xi; j++ {
		tj := getColumnLambdaC(T, j)
		bobSeedJ := oteSeedHash(sid, beta[j], j, tj)
		for i := 0; i < Ell+Rho; i++ {
			gamma[j][i] = oteExpandHash(sid, beta[j], j, i, bobSeedJ)
		}
	}
	return
}
