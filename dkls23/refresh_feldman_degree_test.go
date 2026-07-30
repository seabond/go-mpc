package dkls23

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// A refresh participant must not be able to choose the DEGREE of the
// zero-constant polynomial it contributes.
//
// refreshFeldmanVerify reads the degree off the sender's own commitment vector —
// it ranges over nonConstFeldman — and refreshFinalize never compares that
// length against setup.Threshold-1. A party that broadcasts t commitments
// instead of t-1, with pairwise commitments and round-2 shares consistent with
// that degree-t polynomial, still satisfies f(0)=0, so every FCom, Feldman and
// seed check passes and the public key is preserved.
//
// The refreshed shares then lie on a degree-t polynomial while only t parties
// hold points on it, so Lagrange over the signers no longer returns the secret
// behind the unchanged public key. Refresh is the one operation that overwrites
// setup.Share in place, so by the time the next signature fails, the shares that
// did reconstruct are gone from every node that finalized.
//
// frost/refresh.go:279 already makes exactly this check; dkls23 does not.
func TestRefreshRejectsWrongDegreeFeldmanCommitments(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	const threshold = 3
	setups := fullSetup(t)

	// The secret as it stands. Refresh must leave this untouched — that is the
	// entire contract of a zero-constant contribution.
	before := lagrangeReconstructShares(allIDs, setups)

	allR1 := map[int]*RefreshRound1Output{}
	allCoeffs := map[int][]btcec.ModNScalar{}
	allSeeds := map[int][16]byte{}
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(setups[id])
		if err != nil {
			t.Fatal(err)
		}
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Party 3 contributes a degree-3 zero-constant polynomial where the threshold
	// fixes degree 2: one coefficient too many, one Feldman commitment too many,
	// pairwise commitments consistent with all of it. The seed commitment is
	// carried over untouched so that only the degree is under test.
	const badCoeffCount = threshold // honest parties send threshold-1
	badCoeffs := make([]btcec.ModNScalar, badCoeffCount)
	feldman := make([][]byte, badCoeffCount)
	for k := range badCoeffs {
		s, err := sampleScalar()
		if err != nil {
			t.Fatal(err)
		}
		badCoeffs[k] = s
		pt, err := scalarMulGCompressed(&badCoeffs[k])
		if err != nil {
			t.Fatal(err)
		}
		feldman[k] = pt
	}
	coms := map[int][32]byte{}
	salts := map[int][SaltLen]byte{}
	for _, j := range allIDs {
		if j == 3 {
			continue
		}
		v := evalZeroConstPoly(badCoeffs, uint32(j))
		arr := v.Bytes()
		com, salt, err := Commit(arr[:])
		if err != nil {
			t.Fatal(err)
		}
		coms[j] = com
		salts[j] = salt
	}
	allR1[3] = &RefreshRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: coms,
		PairwiseSalts:       salts,
		SeedCommitment:      allR1[3].SeedCommitment,
		SeedSalt:            allR1[3].SeedSalt,
	}
	allCoeffs[3] = badCoeffs

	// Round 2 decommits from the same coefficients, so party 3's revealed shares
	// match what it committed to.
	allR2 := map[int]*RefreshRound2Output{}
	for _, id := range allIDs {
		r2, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		if err != nil {
			t.Fatal(err)
		}
		allR2[id] = r2
	}

	// Party 3 is the cheater; what its own finalize returns is not the property
	// under test. Finalize everyone anyway so a failure reports the damage rather
	// than just the miss.
	errs := map[int]error{}
	for _, id := range allIDs {
		errs[id] = RefreshFinalize(setups[id], allCoeffs[id], allSeeds[id], allR1, allR2)
	}

	if errs[1] == nil && errs[2] == nil && errs[3] == nil {
		after := lagrangeReconstructShares(allIDs, setups)
		if !after.Equals(&before) {
			t.Errorf("refresh silently changed the secret behind an unchanged public key: "+
				"Lagrange over the shares gave %x before and gives %x now. All three parties "+
				"overwrote setup.Share and bumped Epoch, so no share that reconstructs the old "+
				"value exists any more",
				before.Bytes(), after.Bytes())
		}
	}

	for _, id := range []int{1, 2} {
		var cheat *CheatingPartyError
		if !errors.As(errs[id], &cheat) {
			t.Fatalf("party %d accepted a sender contributing a degree-%d zero-constant "+
				"polynomial when the threshold fixes degree %d: got err %v",
				id, badCoeffCount, threshold-1, errs[id])
		}
		found := false
		for _, bad := range cheat.PartyIDs {
			if bad == 3 {
				found = true
			}
		}
		if !found {
			t.Fatalf("party %d rejected the refresh but did not name party 3: %v", id, cheat.PartyIDs)
		}
	}
}

// lagrangeReconstructShares interpolates the shared secret at x=0 from every
// party's current share — the same computation signing relies on.
func lagrangeReconstructShares(ids []int, setups map[int]*SignerSetup) btcec.ModNScalar {
	var acc btcec.ModNScalar
	for _, id := range ids {
		lc := lagrangeCoeff(id, ids)
		var term btcec.ModNScalar
		term.Mul2(&setups[id].Share, &lc)
		acc.Add(&term)
	}
	return acc
}
