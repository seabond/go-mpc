package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// setupSigners runs DKG + pairwise VOLE + FZero setup for all parties.
// Pairwise VOLE setup is parallelised across goroutines.
// For the common 3-of-3 case, prefer fullSetup() which caches the result.
func setupSigners(t testing.TB, allIDs []int, threshold int) map[int]*SignerSetup {
	t.Helper()
	setups, err := buildSetups(allIDs, threshold)
	require.NoError(t, err)
	return setups
}

// randomBools returns n random boolean values.
func randomBools(t *testing.T, n int) []bool {
	t.Helper()
	buf := make([]byte, (n+7)/8)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	out := make([]bool, n)
	for k := 0; k < n; k++ {
		out[k] = (buf[k/8]>>(uint(k)%8))&1 == 1
	}
	return out
}

// computeRx reconstructs R = sum(R_j) from round2 states and returns the x-coordinate mod q.
func computeRx(t *testing.T, signers []int, round2States map[int]*Round2State) btcec.ModNScalar {
	t.Helper()
	var R btcec.JacobianPoint
	for _, id := range signers {
		Rj, err := compressedToPoint(round2States[id].R_iPoint)
		require.NoError(t, err)
		btcec.AddNonConst(&R, Rj, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx
}

// runSigning executes a complete 3-round signing session among signers and returns (r, s).
// It calls t.Fatal on any error.
func runSigning(t *testing.T, setups map[int]*SignerSetup, signers []int, message []byte) (r, s []byte) {
	t.Helper()
	sigID := "test-sig-" + string(message[:min(4, len(message))])

	// Round 1.
	round1States := make(map[int]*Round1State)
	round1Msgs := make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err, "SignRound1 party %d", id)
		round1States[id] = st
		round1Msgs[id] = msgs
	}

	round1For := func(myID int) map[int]*Round1Msg {
		m := make(map[int]*Round1Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round1Msgs[j][myID]
			}
		}
		return m
	}

	// Round 2.
	round2States := make(map[int]*Round2State)
	round2Msgs := make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		st2, msgs, err := SignRound2(setups[id], round1States[id], round1For(id))
		require.NoError(t, err, "SignRound2 party %d", id)
		round2States[id] = st2
		round2Msgs[id] = msgs
	}

	round2For := func(myID int) map[int]*Round2Msg {
		m := make(map[int]*Round2Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round2Msgs[j][myID]
			}
		}
		return m
	}

	// Round 3.
	round3Frags := make(map[int]map[int]*Round3Msg)
	for _, id := range signers {
		frags, err := SignRound3(setups[id], round2States[id], message, round2For(id))
		require.NoError(t, err, "SignRound3 party %d", id)
		round3Frags[id] = frags
	}

	// Combine using signers[0] as combiner.
	combiner := signers[0]
	myFrag := round3Frags[combiner][combiner]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)

	rx := computeRx(t, signers, round2States)

	allRound3 := make(map[int]*Round3Msg)
	for _, j := range signers {
		if j != combiner {
			allRound3[j] = round3Frags[j][combiner]
		}
	}

	r, s, err := SignCombine(setups[combiner], &rx, &myW, &myU, allRound3, message)
	require.NoError(t, err, "SignCombine")
	return r, s
}

// verifyECDSA checks (r,s) against the master public key and message.
func verifyECDSA(t *testing.T, pubKeyBytes []byte, message, r, s []byte) {
	t.Helper()
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)
	msgHash := sha256.Sum256(message)
	var rS, sS btcec.ModNScalar
	rS.SetByteSlice(r)
	sS.SetByteSlice(s)
	sig := ecdsa.NewSignature(&rS, &sS)
	require.True(t, sig.Verify(msgHash[:], pubKey), "signature must verify")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSign3of3(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	message := []byte("hello threshold ecdsa world!")
	r, s := runSigning(t, setups, allIDs, message)
	require.Len(t, r, 32)
	require.Len(t, s, 32)

	verifyECDSA(t, setups[1].PubKey, message, r, s)
	t.Logf("3-of-3 signature verified: r=%x s=%x", r, s)
}

func TestSign3of3MultipleMessages(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	for i := 0; i < 2; i++ {
		msg := []byte{byte(i), 0x42, 0xde, 0xad}
		r, s := runSigning(t, setups, allIDs, msg)
		verifyECDSA(t, setups[1].PubKey, msg, r, s)
		t.Logf("message %d signature verified", i)
	}
}

func TestSignBadRCommitment(t *testing.T) {
	t.Parallel()
	// A party that sends a bad round-1 commitment must be detected in round 3.
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)
	signers := allIDs
	sigID := "test-bad-commit"
	message := []byte("bad commitment test message!!")

	// Round 1.
	round1States := make(map[int]*Round1State)
	round1Msgs := make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		round1States[id] = st
		round1Msgs[id] = msgs
	}

	// Party 2 corrupts its commitment sent to all other parties.
	for _, j := range signers {
		if j == 2 {
			continue
		}
		round1Msgs[2][j].Commitment[0] ^= 0xff
	}

	round1For := func(myID int) map[int]*Round1Msg {
		m := make(map[int]*Round1Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round1Msgs[j][myID]
			}
		}
		return m
	}

	// Round 2.
	round2States := make(map[int]*Round2State)
	round2Msgs := make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		st2, msgs, err := SignRound2(setups[id], round1States[id], round1For(id))
		require.NoError(t, err)
		round2States[id] = st2
		round2Msgs[id] = msgs
	}

	round2For := func(myID int) map[int]*Round2Msg {
		m := make(map[int]*Round2Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round2Msgs[j][myID]
			}
		}
		return m
	}

	// Parties 1 and 3 must detect bad decommitment from party 2 in round 3.
	for _, id := range []int{1, 3} {
		_, err := SignRound3(setups[id], round2States[id], message, round2For(id))
		require.Error(t, err, "party %d must detect bad R commitment from party 2", id)
		t.Logf("Party %d correctly detected bad R commitment: %v", id, err)
	}
}

func TestNewBaseOTMaterial(t *testing.T) {
	t.Parallel()
	// Direction i→j: j is base-OT sender, i is base-OT receiver, so i becomes VOLE Alice.
	jPriv, jPub, err := BaseSenderRound1(LambdaC)
	require.NoError(t, err)
	mySigma := randomBools(t, LambdaC)
	responses, aliceSeeds, err := BaseReceiverRound1(jPub, mySigma)
	require.NoError(t, err)
	// j's matching Bob half for THIS direction. i's Alice half pairs with this,
	// not with i's own Bob half — those come from the other direction's base OT
	// and share no seeds at all.
	jBob0, jBob1, err := BaseSenderFinalize(jPriv, jPub, responses)
	require.NoError(t, err)

	// Direction j→i: i is base-OT sender, so i becomes VOLE Bob.
	myPriv, myPub, err := BaseSenderRound1(LambdaC)
	require.NoError(t, err)
	theirSigma := randomBools(t, LambdaC)
	responses2, _, err := BaseReceiverRound1(myPub, theirSigma)
	require.NoError(t, err)
	bobSeeds0, bobSeeds1, err := BaseSenderFinalize(myPriv, myPub, responses2)
	require.NoError(t, err)

	m, err := NewBaseOTMaterial(bobSeeds0, bobSeeds1, aliceSeeds, mySigma)
	require.NoError(t, err)
	require.Equal(t, LambdaC, len(m.BobSeeds0))
	require.Equal(t, LambdaC, len(m.BobSeeds1))
	require.Equal(t, LambdaC, len(m.AliceSeeds))
	require.Equal(t, LambdaC, len(m.Sigma))

	// The material must be usable to derive matching single-use VOLE states: Bob
	// draws a fresh beta and publishes corrections, Alice expands against them.
	//
	// The two halves are paired ACROSS parties, which is the only pairing that
	// exists in the protocol. Running Bob and Alice off one party's own material
	// would pair two unrelated base OTs; it used to look like it worked because
	// nothing checked the correlation, and the consistency check now refuses it.
	jMaterial, err := NewBaseOTMaterial(jBob0, jBob1, aliceSeeds, mySigma)
	require.NoError(t, err)

	bob, corrections, oteProof, err := freshBobForSession(testSID, jMaterial)
	require.NoError(t, err)
	require.Equal(t, LambdaC, len(corrections))
	require.False(t, bob.Chi.IsZero(), "bob chi should be initialized")
	require.Equal(t, Xi, len(bob.Gamma))

	alice, err := freshAliceForSession(testSID, m, corrections, oteProof)
	require.NoError(t, err)
	require.Equal(t, Xi, len(alice.Alpha0))
}

func TestNewBaseOTMaterialRejectsWrongLengths(t *testing.T) {
	t.Parallel()
	full := make([][]byte, LambdaC)
	for i := range full {
		full[i] = make([]byte, baseOTSeedLen)
	}
	sigma := make([]bool, LambdaC)

	_, err := NewBaseOTMaterial(full[:LambdaC-1], full, full, sigma)
	require.Error(t, err)
	_, err = NewBaseOTMaterial(full, full[:1], full, sigma)
	require.Error(t, err)
	_, err = NewBaseOTMaterial(full, full, full[:0], sigma)
	require.Error(t, err)
	_, err = NewBaseOTMaterial(full, full, full, sigma[:LambdaC-1])
	require.Error(t, err)
}

// A signing session must never reuse a VOLE correlation. Reuse makes Bob's chi
// constant across sessions, at which point three transcripts determine the
// counterparty's Shamir share by linear algebra. This test is the tripwire: if a
// future change reintroduces a stored correlation, two sessions will start agreeing
// and this fails.
func TestSignDerivesFreshVOLEPerSession(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	seenChi := map[string]bool{}
	seenCorrections := map[string]bool{}
	for session := 0; session < 3; session++ {
		sigID := fmt.Sprintf("freshness-%d", session)
		for _, id := range signers {
			st, msgs, err := SignRound1(setups[id], sigID, signers)
			require.NoError(t, err)
			for peer, bob := range st.VoleBobForRound2 {
				chi := bob.Chi.Bytes()
				key := fmt.Sprintf("%d->%d:%x", peer, id, chi[:])
				require.False(t, seenChi[key], "party %d reused chi toward %d across sessions", id, peer)
				seenChi[key] = true
			}
			for peer, msg := range msgs {
				require.Equal(t, LambdaC, len(msg.OTECorrections),
					"party %d sent no OTE corrections to %d", id, peer)
				key := fmt.Sprintf("%d->%d:%x", id, peer, msg.OTECorrections[0])
				require.False(t, seenCorrections[key], "party %d reused corrections toward %d", id, peer)
				seenCorrections[key] = true
			}
		}
	}
}

// A counterparty that omits or truncates its corrections must abort the session, not
// fall back to anything. A fallback path here would restore the reuse break under an
// attacker-controllable condition.
func TestSignRound2RejectsBadCorrections(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	sigID := "bad-corrections"

	states := map[int]*Round1State{}
	msgs := map[int]map[int]*Round1Msg{}
	for _, id := range signers {
		st, m, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		states[id] = st
		msgs[id] = m
	}

	incoming := func(me int, mutate func(map[int]*Round1Msg)) map[int]*Round1Msg {
		in := map[int]*Round1Msg{}
		for _, j := range signers {
			if j == me {
				continue
			}
			src := msgs[j][me]
			in[j] = &Round1Msg{Commitment: src.Commitment, OTECorrections: src.OTECorrections}
		}
		mutate(in)
		return in
	}

	_, _, err := SignRound2(setups[1], states[1], incoming(1, func(in map[int]*Round1Msg) {
		in[2].OTECorrections = nil
	}))
	require.Error(t, err, "missing corrections must abort")

	_, _, err = SignRound2(setups[1], states[1], incoming(1, func(in map[int]*Round1Msg) {
		in[2].OTECorrections = in[2].OTECorrections[:LambdaC-1]
	}))
	require.Error(t, err, "truncated corrections must abort")
}

func TestComputeRxFromDecommitments(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	sigID := "compute-rx-test"

	// Round 1
	r1States := map[int]*Round1State{}
	r1Msgs := map[int]map[int]*Round1Msg{}
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1States[id] = st
		r1Msgs[id] = msgs
	}

	// Round 2
	r2States := map[int]*Round2State{}
	r2Msgs := map[int]map[int]*Round2Msg{}
	for _, id := range signers {
		in := map[int]*Round1Msg{}
		for _, j := range signers {
			if j != id {
				in[j] = r1Msgs[j][id]
			}
		}
		st, msgs, err := SignRound2(setups[id], r1States[id], in)
		require.NoError(t, err)
		r2States[id] = st
		r2Msgs[id] = msgs
	}

	// Compute rx the old way: from local Round2State.R_iPoint
	rxOld := computeRxFromStates(signers, r2States)

	// Compute rx from decommitments (the distributed pattern)
	noncePoints := map[int][]byte{
		1: r2States[1].R_iPoint,
		2: r2Msgs[2][1].Decommitment,
		3: r2Msgs[3][1].Decommitment,
	}
	rxNew, err := ComputeRx(noncePoints)
	require.NoError(t, err)
	require.True(t, rxOld.Equals(&rxNew), "rx from decommitments must match rx from states")

	// Verify node 2's view produces the same rx
	noncePoints2 := map[int][]byte{
		1: r2Msgs[1][2].Decommitment,
		2: r2States[2].R_iPoint,
		3: r2Msgs[3][2].Decommitment,
	}
	rxNode2, err := ComputeRx(noncePoints2)
	require.NoError(t, err)
	require.True(t, rxOld.Equals(&rxNode2), "all nodes must compute the same rx")
}

func TestComputeRxUsedInSignCombine(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	msg := []byte("ComputeRx end-to-end test")
	signers := []int{1, 2, 3}
	sigID := "rx-e2e-test"

	r1s := map[int]*Round1State{}
	r1m := map[int]map[int]*Round1Msg{}
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1s[id] = st
		r1m[id] = msgs
	}
	r2s := map[int]*Round2State{}
	r2m := map[int]map[int]*Round2Msg{}
	for _, id := range signers {
		in := map[int]*Round1Msg{}
		for _, j := range signers {
			if j != id {
				in[j] = r1m[j][id]
			}
		}
		st, msgs, err := SignRound2(setups[id], r1s[id], in)
		require.NoError(t, err)
		r2s[id] = st
		r2m[id] = msgs
	}
	r3f := map[int]map[int]*Round3Msg{}
	for _, id := range signers {
		in := map[int]*Round2Msg{}
		for _, j := range signers {
			if j != id {
				in[j] = r2m[j][id]
			}
		}
		frags, err := SignRound3(setups[id], r2s[id], msg, in)
		require.NoError(t, err)
		r3f[id] = frags
	}

	noncePoints := map[int][]byte{
		1: r2s[1].R_iPoint,
		2: r2m[2][1].Decommitment,
		3: r2m[3][1].Decommitment,
	}
	rx, err := ComputeRx(noncePoints)
	require.NoError(t, err)

	myFrag := r3f[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)
	allFrags := map[int]*Round3Msg{}
	for _, j := range signers {
		if j != 1 {
			allFrags[j] = r3f[j][1]
		}
	}
	r, s, err := SignCombine(setups[1], &rx, &myW, &myU, allFrags, msg)
	require.NoError(t, err)
	require.NotEmpty(t, r)
	require.NotEmpty(t, s)
	t.Logf("Signature with distributed ComputeRx: r=%x s=%x", r[:4], s[:4])
}

func TestComputeRxEmpty(t *testing.T) {
	_, err := ComputeRx(map[int][]byte{})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "no nonce points")
}

func TestComputeRxNil(t *testing.T) {
	_, err := ComputeRx(nil)
	require.Error(t, err)
}

func TestComputeRxBadPoint(t *testing.T) {
	_, err := ComputeRx(map[int][]byte{1: {0xff, 0xff}})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "party 1")
}

func TestComputeRxSinglePoint(t *testing.T) {
	var scalar btcec.ModNScalar
	scalar.SetInt(42)
	compressed, err := scalarMulGCompressed(&scalar)
	require.NoError(t, err)

	rx, err := ComputeRx(map[int][]byte{1: compressed})
	require.NoError(t, err)

	var pt btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&scalar, &pt)
	pt.ToAffine()
	expected := make([]byte, 32)
	pt.X.PutBytesUnchecked(expected)
	var expectedRx btcec.ModNScalar
	expectedRx.SetByteSlice(expected)
	require.True(t, rx.Equals(&expectedRx))
}

func TestSignBadVOLEMessage(t *testing.T) {
	t.Parallel()
	// A party that sends a bad VOLE multiply message must be detected in round 3.
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)
	signers := allIDs
	sigID := "test-bad-vole"
	message := []byte("bad vole test message!!!!!!!!")

	// Round 1.
	round1States := make(map[int]*Round1State)
	round1Msgs := make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		round1States[id] = st
		round1Msgs[id] = msgs
	}

	round1For := func(myID int) map[int]*Round1Msg {
		m := make(map[int]*Round1Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round1Msgs[j][myID]
			}
		}
		return m
	}

	// Round 2.
	round2States := make(map[int]*Round2State)
	round2Msgs := make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		st2, msgs, err := SignRound2(setups[id], round1States[id], round1For(id))
		require.NoError(t, err)
		round2States[id] = st2
		round2Msgs[id] = msgs
	}

	// Party 2 tampers its VOLE multiply message addressed to party 1.
	round2Msgs[2][1].VoleMsg.ATilde[0][0][0] ^= 0xff

	round2For := func(myID int) map[int]*Round2Msg {
		m := make(map[int]*Round2Msg)
		for _, j := range signers {
			if j != myID {
				m[j] = round2Msgs[j][myID]
			}
		}
		return m
	}

	// Party 1 must detect party 2's bad VOLE message.
	_, err := SignRound3(setups[1], round2States[1], message, round2For(1))
	require.Error(t, err, "party 1 must detect bad VOLE message from party 2")
	t.Logf("Party 1 correctly detected bad VOLE message: %v", err)
}

func TestSignRound1BelowThreshold(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{1, 2})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "below threshold")
}

func TestSignRound1MyIDNotInSigners(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{2, 3, 4})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "myID not in signers")
}

func TestSignRound1DuplicateSigners(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{1, 1, 2, 3})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "duplicate")
}

func TestSignNilVoleBobState(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	sigID := "nil-vole-test"

	r1States := make(map[int]*Round1State)
	r1Msgs := make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1States[id] = st
		r1Msgs[id] = msgs
	}

	r1States[1].VoleBobForRound2[2] = nil

	in := map[int]*Round1Msg{}
	for _, j := range signers {
		if j != 1 {
			in[j] = r1Msgs[j][1]
		}
	}
	_, _, err := SignRound2(setups[1], r1States[1], in)
	require.Error(t, err, "should detect nil VOLE Bob state without panic")
	var corruptErr *CorruptStateError
	require.True(t, errors.As(err, &corruptErr))
	require.Contains(t, corruptErr.Detail, "missing VOLE Bob state")
}

func TestSignCounterIncrements(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	require.Equal(t, uint64(0), setups[1].SignCounter)

	signers := []int{1, 2, 3}
	_, _, err := SignRound1(setups[1], "counter-test-1", signers)
	require.NoError(t, err)
	require.Equal(t, uint64(1), setups[1].SignCounter)

	_, _, err = SignRound1(setups[1], "counter-test-2", signers)
	require.NoError(t, err)
	require.Equal(t, uint64(2), setups[1].SignCounter)
}
