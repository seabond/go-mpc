package dkls23

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// What refresh evicts, and what it does not, pinned as executable fact.
//
// The distinction is easy to lose: "proactive refresh" sounds like everything
// becomes new, and the share genuinely does. The base OT underneath does not —
// it is transformed by a public function of a seed every participant sees. A
// reader who assumes otherwise will wire refresh up believing it recovers from a
// compromise it cannot recover from.

// An attacker that took part in the refresh can recompute the transform, because
// combinedSeed is the XOR of contributions that are all published in round 2.
// Knowing the old choice vector is therefore knowing the new one.
//
// This is the property the doc comment on RefreshRound1 describes. If someone
// changes refreshBaseOT to sample fresh material, THIS TEST SHOULD FAIL — and
// the right response is to update the comment and this test together, not to
// make the test pass again.
func TestRefreshTransformsTheChoiceVectorRatherThanResamplingIt(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]bool(nil), setups[1].BaseOT[2].Sigma...)

	// A seed a participant would hold: refresh publishes every contribution, so
	// this is knowledge an attacker inside the ceremony has by construction.
	var combined [16]byte
	for i := range combined {
		combined[i] = byte(i * 7)
	}

	after, err := refreshBaseOT(setups[1].BaseOT[2], 1, 2, combined)
	if err != nil {
		t.Fatal(err)
	}

	// Predict the new vector from the old one and the published seed alone. If
	// this prediction holds, the refresh has not evicted anyone who was present.
	predicted := predictSigma(t, before, 1, 2, combined)
	wrong := 0
	for k := range after.Sigma {
		if after.Sigma[k] != predicted[k] {
			wrong++
		}
	}
	if wrong != 0 {
		t.Fatalf("the refreshed choice vector was NOT predictable from the old one and the "+
			"published seed (%d of %d bits differ). If refreshBaseOT now samples fresh "+
			"material, refresh evicts a resident attacker and the doc comment on "+
			"RefreshRound1 must be updated to say so", wrong, len(after.Sigma))
	}

	// And it genuinely did change — a no-op transform would satisfy the above
	// trivially and would be a different defect.
	same := 0
	for k := range after.Sigma {
		if after.Sigma[k] == before[k] {
			same++
		}
	}
	if same == len(before) {
		t.Fatal("refresh left the choice vector untouched, so it re-randomizes nothing at all")
	}
}

// predictSigma recomputes the transform from public inputs, exactly as a party
// that took part in the refresh could.
func predictSigma(t *testing.T, old []bool, myID, peerID int, combinedSeed [16]byte) []bool {
	t.Helper()
	// Run the transform against a material whose only meaningful field is Sigma;
	// the seeds are irrelevant to which bits flip.
	m := &BaseOTMaterial{
		BobSeeds0:  make([][]byte, LambdaC),
		BobSeeds1:  make([][]byte, LambdaC),
		AliceSeeds: make([][]byte, LambdaC),
		Sigma:      append([]bool(nil), old...),
	}
	for k := range m.BobSeeds0 {
		m.BobSeeds0[k] = make([]byte, baseOTSeedLen)
		m.BobSeeds1[k] = make([]byte, baseOTSeedLen)
		m.AliceSeeds[k] = make([]byte, baseOTSeedLen)
	}
	out, err := refreshBaseOT(m, myID, peerID, combinedSeed)
	if err != nil {
		t.Fatal(err)
	}
	return out.Sigma
}

// The share IS evicted, which is what refresh is for. Asserting it here keeps the
// test above from reading as "refresh does nothing" — the two halves are the
// whole statement.
func TestRefreshDoesReRandomizeTheShare(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2, 3}, 2)
	if err != nil {
		t.Fatal(err)
	}
	before := setups[1].Share

	r1 := map[int]*RefreshRound1Output{}
	r2 := map[int]*RefreshRound2Output{}
	coeffs := map[int][]btcec.ModNScalar{}
	seeds := map[int][16]byte{}
	for id := 1; id <= 3; id++ {
		out, c, s, err := RefreshRound1(setups[id])
		if err != nil {
			t.Fatal(err)
		}
		r1[id], coeffs[id], seeds[id] = out, c, s
	}
	for id := 1; id <= 3; id++ {
		out, err := RefreshRound2(setups[id], coeffs[id], seeds[id])
		if err != nil {
			t.Fatal(err)
		}
		r2[id] = out
	}
	if err := RefreshFinalize(setups[1], coeffs[1], seeds[1], r1, r2); err != nil {
		t.Fatal(err)
	}

	if setups[1].Share.Equals(&before) {
		t.Fatal("the share is unchanged after a refresh: an attacker holding it from the " +
			"previous epoch is not evicted, which is the one thing refresh must do")
	}
}
