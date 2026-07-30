package dkls23

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// A DKG participant must not be able to choose the DEGREE of its polynomial.
//
// feldmanVerify reads the degree off the sender's own commitment vector —
// t := len(feldmanCommitments) — so a party that broadcasts t+1 commitments and
// shares consistent with a degree-t polynomial passes every check dkgFinalize
// makes. Nothing compares that length against the agreed threshold.
//
// The result is not a detected cheat, it is a wallet. Every party finalizes
// happily and derives the same public key, because pk = sum_j C_{j,0} and the
// constant term is honest. But the shares now lie on a degree-t polynomial while
// only t parties hold points on it, so Lagrange interpolation over the signers
// does not return the secret behind that public key. The key can never sign.
// Funds sent to the address are unrecoverable, and the only party who knows is
// the one who did it.
//
// One participant, or one buggy implementation of one participant, is enough.
func TestDKGRejectsWrongDegreeFeldmanCommitments(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	const threshold = 3
	configs := map[int]DKGPartyConfig{}
	for _, id := range allIDs {
		configs[id] = DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
	}

	coeffs := map[int][]btcec.ModNScalar{}
	r1 := map[int]*DKGRound1Output{}

	// Parties 1 and 2 play honestly.
	for _, id := range []int{1, 2} {
		out, c, err := DKGRound1(configs[id])
		if err != nil {
			t.Fatal(err)
		}
		r1[id] = out
		coeffs[id] = c
	}

	// Party 3 uses a degree-3 polynomial where the threshold calls for degree-2:
	// four coefficients, four Feldman commitments, and pairwise commitments that
	// are all internally consistent with it.
	const badDegreeCount = threshold + 1
	bad := make([]btcec.ModNScalar, badDegreeCount)
	for k := range bad {
		s, err := sampleScalar()
		if err != nil {
			t.Fatal(err)
		}
		bad[k] = s
	}
	feldman := make([][]byte, badDegreeCount)
	for k := range bad {
		pt, err := scalarMulGCompressed(&bad[k])
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
		share := evalPoly(bad, uint32(j))
		arr := share.Bytes()
		com, salt, err := Commit(arr[:])
		if err != nil {
			t.Fatal(err)
		}
		coms[j] = com
		salts[j] = salt
	}
	r1[3] = &DKGRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: coms,
		PairwiseSalts:       salts,
	}
	coeffs[3] = bad

	r2 := map[int]*DKGRound2Output{}
	for _, id := range allIDs {
		peers := map[int]*DKGRound1Output{}
		for _, j := range allIDs {
			if j != id {
				peers[j] = r1[j]
			}
		}
		out, err := DKGRound2(configs[id], coeffs[id], peers)
		if err != nil {
			t.Fatal(err)
		}
		r2[id] = out
	}

	// Every honest party must name party 3. Party 3 is the cheater; what its own
	// finalize returns is not the property under test. Show what finalizing anyway
	// produces before asserting, so a failure reports the damage rather than just
	// the miss.
	honest := []int{1, 2}
	shares := map[int]btcec.ModNScalar{}
	errs := map[int]error{}
	for _, id := range allIDs {
		share, _, err := DKGFinalize(configs[id], coeffs[id], r1, r2)
		errs[id] = err
		if err == nil {
			shares[id] = share
		}
	}

	if len(shares) == len(allIDs) {
		// The wallet exists and is dead. sk is the sum of the constant terms, which
		// is exactly what pk = sum_j C_{j,0} commits to; Lagrange over the three
		// shares is what signing reconstructs. They differ.
		var trueSK btcec.ModNScalar
		for _, id := range allIDs {
			trueSK.Add(&coeffs[id][0])
		}
		var reconstructed btcec.ModNScalar
		for _, id := range allIDs {
			lc := lagrangeCoeff(id, allIDs)
			s := shares[id]
			var term btcec.ModNScalar
			term.Mul2(&s, &lc)
			reconstructed.Add(&term)
		}
		if !reconstructed.Equals(&trueSK) {
			t.Errorf("DKG produced a public key whose secret cannot be reconstructed from "+
				"the %d shares: Lagrange gives %x, the key commits to %x. Any signature "+
				"attempt fails and funds sent to this address are unrecoverable",
				len(allIDs), reconstructed.Bytes(), trueSK.Bytes())
		}
	}

	for _, id := range honest {
		var cheat *CheatingPartyError
		if !errors.As(errs[id], &cheat) {
			t.Fatalf("party %d accepted a sender that committed to a degree-%d polynomial "+
				"when the threshold fixes degree %d: got err %v",
				id, badDegreeCount-1, threshold-1, errs[id])
		}
		found := false
		for _, bad := range cheat.PartyIDs {
			if bad == 3 {
				found = true
			}
		}
		if !found {
			t.Fatalf("party %d rejected the round but did not name party 3: %v", id, cheat.PartyIDs)
		}
	}
}
