package dkls23

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/seabond/go-mpc/internal/secretdo"
)

// lagrangeCoeff computes the Lagrange basis coefficient for party myID evaluating at x=0,
// over the field Zq, with the given set of party IDs.
//
// lagrange(myID, allIDs, 0) = prod_{j≠myID} (-j / (myID - j)) mod q
//
// This is used in DKG finalization and signing to reconstruct the secret
// from Shamir shares without actually computing the secret (only combined scalar multiplications).
// All arithmetic is constant-time via ModNScalar.
func lagrangeCoeff(myID int, allIDs []int) btcec.ModNScalar {
	var num, den btcec.ModNScalar
	num.SetInt(1)
	den.SetInt(1)
	var xI btcec.ModNScalar
	xI.SetInt(uint32(myID))
	for _, j := range allIDs {
		if j == myID {
			continue
		}
		var xJ btcec.ModNScalar
		xJ.SetInt(uint32(j))
		// num *= -xJ
		var negXJ btcec.ModNScalar
		negXJ.NegateVal(&xJ)
		num.Mul(&negXJ)
		// den *= (xI - xJ)
		var diff btcec.ModNScalar
		diff.NegateVal(&xJ)
		diff.Add(&xI)
		den.Mul(&diff)
	}
	// coeff = num * den^{-1} mod q
	denInv := scalarInverse(&den)
	var coeff btcec.ModNScalar
	coeff.Mul2(&num, &denInv)
	return coeff
}

// maxPartyID is the upper bound for party identifiers. IDs are stored in
// uint32 fields inside ModNScalar, so we cap well below 2^32 to prevent
// overflow in Lagrange coefficient arithmetic.
const maxPartyID = 1<<31 - 1

// validatePartyIDs checks that all IDs are positive, within bounds, and unique.
func validatePartyIDs(ids []int, phase string) error {
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || id > maxPartyID {
			return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("party ID %d out of range [1, %d]", id, maxPartyID)}
		}
		if seen[id] {
			return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("duplicate party ID %d", id)}
		}
		seen[id] = true
	}
	return nil
}

// --- πRelaxedKeyGen: Feldman VSS based DKG for secp256k1, t-of-n ---
// Paper Protocol 7.1 (simplified using standard Feldman VSS).
//
// Each party Pi samples a degree-(t-1) polynomial pi(x) over Zq and:
//   - Broadcasts Feldman commitments C_{i,k} = a_{i,k}·G for k=0..t-1
//   - Sends pi(j) to each other party Pj via pairwise commitment (commit-then-reveal)
//   - Verifies incoming shares against Feldman commitments

// DKGPartyConfig holds per-party configuration for the DKG protocol.
type DKGPartyConfig struct {
	// MyID is this party's identifier (1-indexed, must be in AllIDs).
	MyID int
	// AllIDs is the sorted list of all party identifiers (1-indexed).
	AllIDs []int
	// Threshold t: the reconstruction threshold (minimum signers needed).
	Threshold int
}

// DKGRound1Output is what Pi broadcasts or sends after DKG round 1.
type DKGRound1Output struct {
	// FeldmanCommitments are the t compressed curve points C_{i,0}...C_{i,t-1} (33 bytes each).
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is FCom commit(pi(j)) sent to Pj (commitment only, before reveal).
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the FCom salt used for the commitment to Pj's share.
	PairwiseSalts map[int][SaltLen]byte
}

// DKGRound2Output contains the decommitments Pi sends after receiving all round 1 messages.
type DKGRound2Output struct {
	// SecretShares[j] is the 32-byte big-endian encoding of pi(j) sent to party Pj.
	SecretShares map[int][]byte
}

// evalPoly evaluates the polynomial with coefficients (coeffs[0]+coeffs[1]*x+...+coeffs[t-1]*x^{t-1}) at x.
// All arithmetic is constant-time via ModNScalar.
func evalPoly(coeffs []btcec.ModNScalar, x uint32) btcec.ModNScalar {
	var result, xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(x)
	xPow.SetInt(1)
	for _, c := range coeffs {
		var term btcec.ModNScalar
		term.Mul2(&c, &xPow)
		result.Add(&term)
		xPow.Mul(&xScalar)
	}
	return result
}

// DKGRound1 executes the first round of the Feldman VSS DKG for party config.MyID.
// Pi samples a degree-(t-1) polynomial, broadcasts Feldman commitments,
// and commits (via FCom) to each other party's share.
// Returns the round 1 output and the polynomial coefficients (needed for round 2).
func DKGRound1(config DKGPartyConfig) (out *DKGRound1Output, coeffs []btcec.ModNScalar, err error) {
	secretdo.Do(func() {
		out, coeffs, err = dkgRound1(config)
	})
	return
}

func dkgRound1(config DKGPartyConfig) (*DKGRound1Output, []btcec.ModNScalar, error) {
	if err := validatePartyIDs(config.AllIDs, "DKGRound1"); err != nil {
		return nil, nil, err
	}
	if config.Threshold <= 0 {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: "threshold must be positive"}
	}
	if config.Threshold > len(config.AllIDs) {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: fmt.Sprintf("threshold %d exceeds party count %d", config.Threshold, len(config.AllIDs))}
	}
	found := false
	for _, id := range config.AllIDs {
		if id == config.MyID {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: fmt.Sprintf("myID %d not in AllIDs", config.MyID)}
	}
	t := config.Threshold

	// Sample polynomial coefficients a_{i,0}, ..., a_{i,t-1} ← Zq.
	coeffs := make([]btcec.ModNScalar, t)
	for k := 0; k < t; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: sample coefficient: %w", err)
		}
		coeffs[k] = c
	}
	// Note: coeffs are returned to the caller for use in DKGRound2/DKGFinalize.
	// The caller should zero them after DKGFinalize completes.

	// Compute Feldman commitments C_{i,k} = a_{i,k} * G.
	feldman := make([][]byte, t)
	for k := 0; k < t; k++ {
		pt, err := scalarMulGCompressed(&coeffs[k])
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: Feldman commitment: %w", err)
		}
		feldman[k] = pt
	}

	// Commit to pi(j) for each other party j.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := shareArr[:]

		com, salt, err := Commit(shareBytes)
		for i := range shareArr {
			shareArr[i] = 0
		}
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	out := &DKGRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: pairwiseComs,
		PairwiseSalts:       pairwiseSalts,
	}
	return out, coeffs, nil
}

// DKGRound2 decommits pairwise shares after receiving round 1 messages from all parties.
// myCoeffs are the polynomial coefficients sampled in round 1.
// theirRound1 is a map of other parties' round 1 outputs (Feldman commitments and pairwise commitments).
// Returns the decommitments (plaintext shares) to send to each other party.
func DKGRound2(config DKGPartyConfig, myCoeffs []btcec.ModNScalar, theirRound1 map[int]*DKGRound1Output) (out *DKGRound2Output, err error) {
	secretdo.Do(func() {
		out, err = dkgRound2(config, myCoeffs, theirRound1)
	})
	return
}

func dkgRound2(config DKGPartyConfig, myCoeffs []btcec.ModNScalar, theirRound1 map[int]*DKGRound1Output) (*DKGRound2Output, error) {
	secretShares := make(map[int][]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(myCoeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := make([]byte, 32)
		copy(shareBytes, shareArr[:])
		share.Zero()
		for i := range shareArr {
			shareArr[i] = 0
		}
		secretShares[j] = shareBytes
	}
	return &DKGRound2Output{SecretShares: secretShares}, nil
}

// feldmanVerify checks that share·G == sum_{k=0}^{t-1} C_{i,k} * x^k.
// This is the standard Feldman VSS verification equation.
func feldmanVerify(share *btcec.ModNScalar, x int, feldmanCommitments [][]byte) error {
	t := len(feldmanCommitments)
	var xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(uint32(x))
	xPow.SetInt(1)

	// Compute RHS = sum_{k=0}^{t-1} C_{i,k} * x^k (as EC points).
	var rhs btcec.JacobianPoint
	for k := 0; k < t; k++ {
		Cik, err := compressedToPoint(feldmanCommitments[k])
		if err != nil {
			return fmt.Errorf("dkls23: parse Feldman commitment: %w", err)
		}
		scaled := scalarMul(&xPow, Cik)
		btcec.AddNonConst(&rhs, scaled, &rhs)
		xPow.Mul(&xScalar)
	}
	rhs.ToAffine()

	// Compute LHS = share * G.
	var lhs btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(share, &lhs)
	lhs.ToAffine()

	if lhs.X.IsZero() && lhs.Y.IsZero() {
		return errors.New("dkls23: LHS is point at infinity")
	}
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return errors.New("dkls23: Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// DKGFinalize verifies all received shares and computes the final key share.
// For each sender j:
//  1. Verifies pairwise commitment: Open(pi_j(myID), com_{j,myID}, salt_{j,myID})
//  2. Verifies Feldman check: pi_j(myID)*G == sum_k C_{j,k}*myID^k
//
// Returns the final share p(myID) = sum_j pj(myID) mod q and the master public key pk.
// Returns error (listing bad senders) if any check fails.
func DKGFinalize(
	config DKGPartyConfig,
	myCoeffs []btcec.ModNScalar,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (share btcec.ModNScalar, publicKey []byte, err error) {
	secretdo.Do(func() {
		share, publicKey, err = dkgFinalize(config, myCoeffs, allRound1, allRound2)
	})
	return
}

func dkgFinalize(
	config DKGPartyConfig,
	myCoeffs []btcec.ModNScalar,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (share btcec.ModNScalar, publicKey []byte, err error) {
	var badSenders []int

	var finalShare btcec.ModNScalar

	for _, j := range config.AllIDs {
		if j == config.MyID {
			// My own share: evaluate my polynomial at myID.
			myShare := evalPoly(myCoeffs, uint32(config.MyID))
			finalShare.Add(&myShare)
			continue
		}

		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// The commitment vector fixes the DEGREE of j's polynomial, and
		// feldmanVerify reads that degree off the vector itself rather than off the
		// threshold. Unchecked, j picks its own degree: with t+1 commitments every
		// pairwise and Feldman check below still passes, and pk = sum_j C_{j,0} is
		// still the honest constant term, so the DKG succeeds for everyone. But the
		// shares then lie on a degree-t polynomial while only t parties hold points
		// on it, so Lagrange over the signers does not return the secret behind that
		// public key. The wallet is created and can never sign.
		if len(r1j.FeldmanCommitments) != config.Threshold {
			badSenders = append(badSenders, j)
			continue
		}

		// Get the share pj(myID) sent by party j.
		shareBytes := r2j.SecretShares[config.MyID]
		if len(shareBytes) != 32 {
			badSenders = append(badSenders, j)
			continue
		}
		var shareVal btcec.ModNScalar
		shareVal.SetByteSlice(shareBytes)

		// Verify FCom: Open(share, com, salt).
		com, ok1 := r1j.PairwiseCommitments[config.MyID]
		salt, ok2 := r1j.PairwiseSalts[config.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err2 := Open(shareBytes, com, salt); err2 != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify Feldman check: pj(myID)*G == sum_k C_{j,k} * myID^k.
		if err2 := feldmanVerify(&shareVal, config.MyID, r1j.FeldmanCommitments); err2 != nil {
			badSenders = append(badSenders, j)
			continue
		}

		finalShare.Add(&shareVal)
	}

	if len(badSenders) > 0 {
		return btcec.ModNScalar{}, nil, &CheatingPartyError{PartyIDs: badSenders, Phase: "DKGFinalize", Detail: "share or Feldman verification failed"}
	}

	// Compute master public key: pk = sum_j C_{j,0} (EC point addition).
	//
	// Own entry included, and it is the one the loop above never checked: the
	// per-sender validation skips j == MyID. A caller that passes only its peers'
	// round 1 outputs would otherwise index into a nil message here.
	var pk btcec.JacobianPoint
	for _, j := range config.AllIDs {
		r1j := allRound1[j]
		if r1j == nil || len(r1j.FeldmanCommitments) != config.Threshold {
			return btcec.ModNScalar{}, nil, &InvalidInputError{
				Phase:  "DKGFinalize",
				Detail: fmt.Sprintf("party %d: expected %d Feldman commitments", j, config.Threshold),
			}
		}
		C_j0, err2 := compressedToPoint(r1j.FeldmanCommitments[0])
		if err2 != nil {
			return btcec.ModNScalar{}, nil, fmt.Errorf("dkls23: parse C_{%d,0}: %w", j, err2)
		}
		btcec.AddNonConst(&pk, C_j0, &pk)
	}

	pkBytes, err2 := pointToCompressed(&pk)
	if err2 != nil {
		return btcec.ModNScalar{}, nil, fmt.Errorf("dkls23: serialize public key: %w", err2)
	}

	return finalShare, pkBytes, nil
}
