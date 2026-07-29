package dkls23

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Two signing sessions run under the SAME sigID must not reuse the OT-extension
// pads.
//
// The pads are derived as prg(sid, base-OT seed), and the base OT is reused with
// a peer forever by design, so sid is the ONLY thing that makes them fresh. sid
// is voleSIDForPair(sigID, ...) — a pure function of the caller-supplied sigID.
// Repeat the sigID and every pad repeats with it, at exactly the indices where
// the freshly sampled beta happens to agree, which is half of the 416 of them.
//
// The counterparty knows which indices those are: he chose both betas. At each
// one, aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i] with the same alpha
// pair in both sessions, so subtracting cancels the pads and leaves a^A[i] -
// a^B[i] in the clear. a[0] is Alice's ECDSA nonce share.
//
// This test asserts the property directly: no index may reveal the difference of
// Alice's nonce shares.
func TestRepeatedSigIDDoesNotLeakAliceNonceDifference(t *testing.T) {
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
	if leaked != 0 {
		t.Fatalf("reusing sigID %q leaked the difference of party 1's nonce shares at "+
			"%d of %d indices where beta agreed: the OT-extension pads repeated, so "+
			"subtracting the two aTilde matrices cancels them and hands the "+
			"counterparty (r_1^A - r_1^B) in the clear. Two ordinary signatures with a "+
			"known nonce difference recover the ECDSA private key.",
			sigID, leaked, agreeing)
	}
}
