package dkls23

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Why a signing session id must NEVER be reused, demonstrated rather than
// asserted.
//
// The OT-extension pads are prg(sid, base-OT seed), and the base OT is reused
// with a peer forever by design, so sid is the ONLY thing that makes them fresh.
// sid is voleSIDForPair(sigID, ...), a pure function of the caller's sigID.
// Repeat the sigID and every pad repeats with it, at the indices where the
// freshly sampled beta happens to agree — half of the 416 of them.
//
// The counterparty knows which indices those are: it chose both betas. At each,
// aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i] with the SAME alpha pair in
// both sessions, so subtracting cancels the pads and leaves a^A[i] - a^B[i] in
// the clear. a[0] is the nonce share, and two ECDSA signatures with a known nonce
// difference give up the private key.
//
// THE LIBRARY CANNOT PREVENT THIS, and pretending otherwise would be worse than
// saying so. Preventing it means remembering every sigID ever used, and a
// SignerSetup is unsealed fresh per call from durable storage — an in-memory
// guard on it can never fire. Making sid contributory instead would need both
// parties' fresh nonces before the corrections are built, and the corrections
// ARE round 1, so Bob computes his before Alice's round 1 has arrived. That is a
// protocol restructure, not a check.
//
// So it is the CALLER's obligation, and a caller holding real funds must meet it
// durably: record every sig id, per setup, inside the same durable write
// transaction that consumes it, permanently, with conflict detection that makes
// two concurrent claims impossible. This test is why such a guard has to exist
// and why its record must never expire.
//
// If someone later makes reuse safe, this test fails — and the right response is
// to delete it and the guard together, not to weaken either alone.
func TestReusingASigIDLeaksTheNonceDifference(t *testing.T) {
	t.Parallel()

	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	signers := []int{1, 2}

	// The SAME sigID for both sessions — a coordinator that reuses a request id,
	// a retry after a dropped connection, or a sigID derived from the message.
	const sigID = "reused-session-id"

	type session struct {
		r1 map[int]*Round1State
		r2 map[int]map[int]*Round2Msg
	}
	run := func() session {
		st := map[int]*Round1State{}
		m1 := map[int]map[int]*Round1Msg{}
		for _, id := range signers {
			s, m, err := SignRound1(setups[id], sigID, signers)
			if err != nil {
				t.Fatal(err)
			}
			st[id] = s
			m1[id] = m
		}
		m2 := map[int]map[int]*Round2Msg{}
		for _, id := range signers {
			in := map[int]*Round1Msg{}
			for _, j := range signers {
				if j != id {
					in[j] = m1[j][id]
				}
			}
			_, msgs, err := SignRound2(setups[id], st[id], in)
			if err != nil {
				t.Fatal(err)
			}
			m2[id] = msgs
		}
		return session{r1: st, r2: m2}
	}

	a := run()
	b := run()

	// Party 2 is the attacker. It is VOLE Bob toward party 1 in both sessions, so
	// it holds both betas and both of party 1's aTilde matrices.
	betaA := a.r1[2].VoleBobForRound2[1].Beta
	betaB := b.r1[2].VoleBobForRound2[1].Beta
	aTildeA := a.r2[1][2].VoleMsg.ATilde
	aTildeB := b.r2[1][2].VoleMsg.ATilde

	// The secret it must not learn: the difference of party 1's two nonce shares.
	var wantDiff btcec.ModNScalar
	wantDiff.Set(&a.r1[1].R_i)
	var negRB btcec.ModNScalar
	negRB.NegateVal(&b.r1[1].R_i)
	wantDiff.Add(&negRB)

	agreeing, leaked := 0, 0
	for j := range Xi {
		if betaA[j] != betaB[j] {
			continue
		}
		agreeing++
		// aTilde^A[j][0] - aTilde^B[j][0]: the pads cancel iff they repeated.
		var x, y btcec.ModNScalar
		x.SetBytes(&aTildeA[j][0])
		y.SetBytes(&aTildeB[j][0])
		y.Negate()
		x.Add(&y)
		if x.Equals(&wantDiff) {
			leaked++
		}
	}
	if agreeing == 0 {
		t.Fatal("no index had a matching beta bit; the test learned nothing")
	}
	// The leak is the point. Every index where beta agreed hands the counterparty
	// (r_1^A - r_1^B), because the pads repeated and cancelled.
	if leaked != agreeing {
		t.Fatalf("expected reuse of sigID %q to leak the nonce difference at all %d "+
			"agreeing indices, got %d. If the pads no longer repeat under one sigID, "+
			"the caller obligation this documents has been lifted — check what changed "+
			"and retire the caller-side sigID guard with it rather than leaving a guard "+
			"whose reason has gone", sigID, agreeing, leaked)
	}
	t.Logf("reusing one sigID leaked the nonce difference at %d of %d agreeing indices; "+
		"this is why sig ids are claimed durably and never expire", leaked, agreeing)
}
