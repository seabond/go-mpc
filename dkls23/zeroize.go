package dkls23

// Erasure for signing round state.
//
// A ceremony's round state is as sensitive as the share it signs with, and for
// two independent reasons. Round1State holds R_i, the nonce scalar: ECDSA gives
// up the signing key to anyone holding the nonce and the signature it produced,
// which is one division. Round2State holds SK_i, the rerandomized Shamir share
// itself. Neither is a derived or masked value that could be published.
//
// Dropping the last reference to that state is not erasure. The bytes stay in
// freed heap until something happens to reuse the span, and a core dump, a swap
// page or a read of this process's memory in the meantime yields them intact.
// Go's runtime/secret erases what a function used and left unreachable; round
// state is deliberately the opposite, since it must survive across three rounds
// and a network round trip.
//
// So the holder has to say when a ceremony is over. These methods are that
// statement. Each is safe on a nil receiver and safe to call twice, because the
// paths that end a ceremony include the ones where it failed halfway.

import "github.com/btcsuite/btcd/btcec/v2"

// Zero erases Pi's round 1 secrets: the nonce, the inversion mask, the FZero
// zero-share, the pairwise psi values and every VOLE Bob state under it.
//
// It deliberately leaves SigID and Signers alone. Neither is secret — the
// counterparties both know them — and a zeroed state that still says which
// session it belonged to is easier to reason about when one turns up in a log.
func (s *Round1State) Zero() {
	if s == nil {
		return
	}
	s.R_i.Zero()
	s.Phi_i.Zero()
	s.ZetaI.Zero()
	zeroBytes(s.R_iPoint)
	s.Salt = [SaltLen]byte{}
	// Overwrite each entry before dropping it: deleting a map key does not clear
	// the bucket slot the value was living in.
	for j := range s.Psi {
		s.Psi[j] = [32]byte{}
		delete(s.Psi, j)
	}
	for j := range s.Com {
		s.Com[j] = [32]byte{}
		delete(s.Com, j)
	}
	for j, bob := range s.VoleBobForRound2 {
		bob.Zero()
		delete(s.VoleBobForRound2, j)
	}
}

// Zero erases Pi's round 2 secrets and then its round 1 secrets.
//
// SK_i is the rerandomized share — share*lagrange + zeta_i — so it is the one
// value here that is the signing secret rather than a step toward it.
func (s *Round2State) Zero() {
	if s == nil {
		return
	}
	s.SK_i.Zero()
	zeroScalarMap(s.C_u)
	zeroScalarMap(s.C_v)
	for j := range s.Round1Commits {
		s.Round1Commits[j] = [32]byte{}
		delete(s.Round1Commits, j)
	}
	s.Round1State.Zero()
}

// Zero erases Bob's VOLE state. Beta is the OTE choice vector and Chi is the
// scalar derived from it; either one recovers what the other protects, so both
// go together.
func (b *VOLEBobState) Zero() {
	if b == nil {
		return
	}
	b.Beta = [Xi]bool{}
	b.Chi.Zero()
	for i := range b.Gamma {
		b.Gamma[i] = [Ell + Rho][32]byte{}
	}
	b.Gamma = nil
}

// Zero erases Alice's VOLE state, including the sender pads. The pads are what
// the per-session sid binding exists to keep fresh, and a stale pair recovered
// from memory is as good as one reused on the wire.
func (a *VOLEAliceState) Zero() {
	if a == nil {
		return
	}
	for i := range a.Alpha0 {
		a.Alpha0[i] = [Ell + Rho][32]byte{}
	}
	for i := range a.Alpha1 {
		a.Alpha1[i] = [Ell + Rho][32]byte{}
	}
	a.Alpha0, a.Alpha1 = nil, nil
	a.C_u.Zero()
	a.C_v.Zero()
}

func zeroScalarMap(m map[int]btcec.ModNScalar) {
	for j := range m {
		var z btcec.ModNScalar
		m[j] = z
		delete(m, j)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
