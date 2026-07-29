package dkls23

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// OT-extension consistency check (KOS15 §4).
//
// # What it stops
//
// IKNP by itself is secure only against a receiver who follows the protocol.
// Bob builds each correction row as U_k = T_k xor PRG(K^1_k) xor beta, and
// nothing in the correction Alice receives tells her that the same beta went
// into every row. A malicious Bob can use beta xor delta in row k alone. Alice's
// Q_k is T_k xor sigma_k*beta^(k), so her column j moves away from Bob's
// prediction exactly when sigma_k = 1 — and Bob then reads sigma_k off his own
// downstream check: pass means 0, fail means 1.
//
// That is one bit of sigma per session, chosen by Bob, with no error. sigma is
// the base-OT choice vector, which lives in BaseOTMaterial and is reused with
// that peer for every signature ever after, so the bits accumulate. With all
// LambdaC of them Bob reconstructs Alice's whole Q matrix, hence both alpha
// pads, and inverts aTilde = alpha0 - alpha1 + a to read her nonce and her
// rerandomized share. In a 2-of-3 that is the private key.
//
// Alice cannot attribute any of it: when her counterparty aborts she cannot
// distinguish a cheat from a dropped connection, so no blacklist ever fires.
//
// # The check
//
// Write t^j and q^j for column j of Bob's T and Alice's Q, each LambdaC bits,
// read as elements of GF(2^128). Honest Bob gives q^j = t^j + beta_j*sigma.
//
// Alice needs to confirm that ONE sigma-multiple explains every column at once.
// Take a random challenge chi_j per column and fold:
//
//	sum_j chi_j*q^j = sum_j chi_j*t^j + sigma*sum_j chi_j*beta_j
//	               =: t~            + sigma*x~
//
// Bob sends the two right-hand sums, t~ and x~. Alice recomputes the left side
// from her own Q and checks. Bob has to produce one (t~, x~) that satisfies an
// equation depending on sigma, which he does not know; if his rows disagree
// about beta, the residual is a fixed nonzero element multiplied by challenge
// coefficients he committed to before seeing them, so he passes with probability
// 2^-128.
//
// The field size is the whole point. Over GF(2) — random subsets — a cheat
// survives one trial with probability 1/2.
//
// # Why the challenge is derived rather than sent
//
// Alice would otherwise have to speak before Bob's message could be checked, and
// this OT extension runs inside round 1 of a three-round signing protocol with
// no room for another trip. Deriving chi from the session id and the corrections
// themselves fixes them before Bob can see them. Bob can grind U looking for a
// favourable chi, but each attempt is an independent 2^-128.

// oteConsistencyProof is Bob's evidence that one beta explains every correction
// row. It travels with the corrections and is verified before they are used.
type oteConsistencyProof struct {
	// TTilde is sum_j chi_j*t^j over GF(2^128).
	TTilde [16]byte
	// XTilde is sum_j chi_j*beta_j over GF(2^128).
	XTilde [16]byte
}

// oteChallenge derives chi_1..chi_Xi from the session id and the corrections.
//
// Binding to the corrections is what makes the non-interactive form sound: Bob
// must commit to every row before he learns which combination he will be asked
// for. Binding to sid stops a proof from being lifted between sessions.
func oteChallenge(sid string, corrections [][Xi / 8]byte) [Xi]gf128 {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTECheck))
	h.Write([]byte(sid))
	h.Write([]byte{0x00})
	for k := range corrections {
		h.Write(corrections[k][:])
	}
	var chi [Xi]gf128
	var buf [16]byte
	for j := range chi {
		h.Read(buf[:])
		chi[j] = gf128FromBytes(buf[:])
	}
	return chi
}

// oteProve builds Bob's proof. T is his LambdaC x Xi matrix, beta his choice
// vector, and both are exactly what he already computed for the corrections.
func oteProve(sid string, T [][Xi / 8]byte, beta [Xi]bool, corrections [][Xi / 8]byte) (oteConsistencyProof, error) {
	if len(T) != LambdaC {
		return oteConsistencyProof{}, errors.New("dkls23 oteProve: T must have LambdaC rows")
	}
	chi := oteChallenge(sid, corrections)

	var tTilde, xTilde gf128
	for j := range Xi {
		tj := gf128FromBytes(getColumnLambdaC(T, j))
		tTilde = tTilde.add(tj.mul(chi[j]))
		if beta[j] {
			xTilde = xTilde.add(chi[j])
		}
	}
	return oteConsistencyProof{TTilde: tTilde.bytes(), XTilde: xTilde.bytes()}, nil
}

// oteVerify is Alice's side: recompute the left-hand fold from her own Q and
// compare against Bob's claim.
//
// Q here is the matrix she has ALREADY formed from the corrections, so the check
// covers the exact rows she is about to use rather than a restatement of them.
func oteVerify(sid string, Q [][Xi / 8]byte, sigma []bool, corrections [][Xi / 8]byte, proof oteConsistencyProof) error {
	if len(Q) != LambdaC || len(sigma) != LambdaC {
		return errors.New("dkls23 oteVerify: length mismatch")
	}
	chi := oteChallenge(sid, corrections)

	var lhs gf128
	for j := range Xi {
		qj := gf128FromBytes(getColumnLambdaC(Q, j))
		lhs = lhs.add(qj.mul(chi[j]))
	}

	var sigmaVec [LambdaC / 8]byte
	for k, s := range sigma {
		if s {
			sigmaVec[k/8] |= 1 << (uint(k) % 8)
		}
	}
	rhs := gf128FromBytes(proof.TTilde[:]).
		add(gf128FromBytes(sigmaVec[:]).mul(gf128FromBytes(proof.XTilde[:])))

	// Constant time, and on the encoded form rather than on the limbs, so the
	// comparison cannot short-circuit on the high half. sigma is a long-term
	// secret and this is the one place a verifier's timing sees it.
	l, r := lhs.bytes(), rhs.bytes()
	if subtle.ConstantTimeCompare(l[:], r[:]) != 1 {
		return fmt.Errorf("dkls23 oteVerify: OT extension consistency check failed for session %q: "+
			"the corrections were not built from one choice vector", sid)
	}
	return nil
}
