package dkls23

import (
	"encoding/json"
	"strings"
	"testing"
)

// Round 2 runs the OTE sender expansion over corrections the COUNTERPARTY
// supplies, against this party's long-lived base-OT choice vector sigma. Alice's
// pad in column j changes under a flipped correction bit exactly when
// sigma[j] = 1, and aTilde carries that difference.
//
// So two round-2 runs over ONE Round1State — same r_i, same sk_i, same sigma —
// let the counterparty read sigma straight off by comparing the two aTilde
// matrices. From sigma it reconstructs the whole Q matrix, hence both alpha
// pads, and inverting aTilde = alpha0 - alpha1 + a yields r_i and sk_i exactly.
// sk_i is share*lagrange + zeta_i, and the counterparty knows the pairwise FZero
// seed, so it finishes with the victim's raw Shamir share.
//
// In a 2-of-3 that is one compromised signer plus one signature for the whole
// private key. Round 3 was already single-use for the same reason; round 2 was
// not, and its consequence is worse — sigma is not session material, it lives in
// BaseOTMaterial and is reused with that peer forever.
func TestRound2IsSingleUsePerRound1State(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	const sigID = "single-use-session"
	signers := []int{1, 2}

	st1, _, err := SignRound1(setups[1], sigID, signers)
	if err != nil {
		t.Fatal(err)
	}
	_, m2, err := SignRound1(setups[2], sigID, signers)
	if err != nil {
		t.Fatal(err)
	}
	honest := m2[1]

	if _, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{2: honest}); err != nil {
		t.Fatalf("the first round 2 must succeed: %v", err)
	}

	// The attack needs a SECOND transcript over the same state. Honest corrections
	// are enough to prove the guard fires; the tampering below is what makes the
	// second transcript useful, and it must not get that far either.
	_, _, err = SignRound2(setups[1], st1, map[int]*Round1Msg{2: honest})
	if err == nil {
		t.Fatal("round 2 ran twice on one Round1State: two transcripts under one sigma " +
			"is the whole key-recovery attack")
	}
	if !strings.Contains(err.Error(), "single-use") {
		t.Fatalf("second round 2 failed for the wrong reason: %v", err)
	}

	tampered := &Round1Msg{
		Commitment:     honest.Commitment,
		OTECorrections: make([][Xi / 8]byte, len(honest.OTECorrections)),
	}
	copy(tampered.OTECorrections, honest.OTECorrections)
	for k := range LambdaC {
		tampered.OTECorrections[k][k/8] ^= 1 << (uint(k) % 8)
	}
	if _, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{2: tampered}); err == nil {
		t.Fatal("a second round 2 with chosen corrections was accepted; sigma is readable")
	}
}

// Marked spent on ENTRY, before any check that could fail — otherwise a
// counterparty sends one deliberately invalid message, has it rejected, and
// still holds its retry.
func TestARejectedRound2StillSpendsTheState(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	st1, _, err := SignRound1(setups[1], "rejected-first", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}

	// A round 1 message from nobody: this fails well before any OTE work.
	if _, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{}); err == nil {
		t.Fatal("expected the empty round 1 map to be refused")
	}

	_, m2, err := SignRound1(setups[2], "rejected-first", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = SignRound2(setups[1], st1, map[int]*Round1Msg{2: m2[1]})
	if err == nil {
		t.Fatal("a failed round 2 left the state usable, so a rejected attempt buys a retry")
	}
	if !strings.Contains(err.Error(), "single-use") {
		t.Fatalf("retry after a failure failed for the wrong reason: %v", err)
	}
}

// The marker has to survive serialization, or persisting a state and reading it
// back launders it into an unused one.
func TestTheRound2MarkerSurvivesSerialization(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	const sigID = "round-trip"
	st1, _, err := SignRound1(setups[1], sigID, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_, m2, err := SignRound1(setups[2], sigID, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{2: m2[1]}); err != nil {
		t.Fatal(err)
	}

	blob, err := json.Marshal(st1)
	if err != nil {
		t.Fatal(err)
	}
	var restored Round1State
	if err := json.Unmarshal(blob, &restored); err != nil {
		t.Fatal(err)
	}
	if !restored.round2Done.Load() {
		t.Fatal("the single-use marker was dropped in serialization")
	}
	if _, _, err := SignRound2(setups[1], &restored, map[int]*Round1Msg{2: m2[1]}); err == nil {
		t.Fatal("a state that was persisted and restored ran round 2 a second time")
	}
}
