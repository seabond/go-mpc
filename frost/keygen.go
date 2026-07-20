package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sort"

	"filippo.io/edwards25519"
	"github.com/seabond/go-mpc/internal/secretdo"
)

// --- Feldman VSS Distributed Key Generation ---
//
// Each party Pi samples a degree-(t-1) polynomial pi(x) over the Ed25519
// scalar field and:
//   - Broadcasts Feldman commitments A_{i,k} = a_{i,k}·B for k=0..t-1
//   - Commits (via hash commitment) to each other party's share
//   - Verifies incoming shares against Feldman commitments
//
// The DKG produces shares compatible with FROST signing (RFC 9591).

// DKGPartyConfig holds per-party configuration for the DKG protocol.
type DKGPartyConfig struct {
	// MyID is this party's identifier (1-indexed, must be in AllIDs).
	MyID int
	// AllIDs is the sorted list of all party identifiers (1-indexed).
	AllIDs []int
	// Threshold t: the reconstruction threshold (minimum signers needed).
	Threshold int
}

// KeyShare holds a single participant's secret share and the group public key.
type KeyShare struct {
	// ID is the participant identifier (1-indexed).
	ID int
	// SecretShare is the participant's secret scalar s_i = f(i) (32 bytes LE).
	SecretShare []byte
	// PublicKey is the group verification key (32-byte compressed Edwards point).
	PublicKey []byte
	// VerificationShare is s_i * B (32-byte compressed Edwards point).
	VerificationShare []byte
	// GroupCommitments are the aggregated Feldman VSS commitments A_0, ..., A_{t-1}.
	// A_0 is the group public key.
	GroupCommitments [][]byte
	// Threshold is the signing threshold t.
	Threshold int
	// AllIDs lists all participant identifiers.
	AllIDs []int
}

// DKGRound1Output is what Pi broadcasts after DKG round 1.
type DKGRound1Output struct {
	// FeldmanCommitments are the t compressed Edwards points A_{i,0}...A_{i,t-1} (32 bytes each).
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is the hash commitment to pi(j) sent to Pj.
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the salt used for the commitment to Pj's share.
	PairwiseSalts map[int][SaltLen]byte
}

// DKGRound2Output contains the decommitted shares Pi sends after receiving all round 1 messages.
type DKGRound2Output struct {
	// SecretShares[j] is the 32-byte little-endian encoding of pi(j) sent to party Pj.
	SecretShares map[int][]byte
}

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

// commit creates a hash commitment to msg using a freshly sampled random salt.
// commitment = SHA-256(msg || salt), where salt is SaltLen random bytes.
func commit(msg []byte) (com [32]byte, salt [SaltLen]byte, err error) {
	if _, err = rand.Read(salt[:]); err != nil {
		return
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	copy(com[:], h.Sum(nil))
	return
}

// openCommitment verifies a hash commitment in constant time.
func openCommitment(msg []byte, com [32]byte, salt [SaltLen]byte) error {
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	expected := h.Sum(nil)
	if subtle.ConstantTimeCompare(expected, com[:]) != 1 {
		return fmt.Errorf("frost: commitment verification failed")
	}
	return nil
}

// sampleScalar samples a uniformly random scalar from the Ed25519 field.
// The probability of sampling zero is ~2^{-252}, which is negligible.
func sampleScalar() (*edwards25519.Scalar, error) {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		return nil, err
	}
	return s, nil
}

// evalPoly evaluates the polynomial f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[t-1]*x^{t-1} at x.
func evalPoly(coeffs []*edwards25519.Scalar, x int) *edwards25519.Scalar {
	xScalar := scalarFromInt(x)
	result := edwards25519.NewScalar()
	xPow := scalarFromUint64(1) // x^0 = 1

	for _, c := range coeffs {
		term := edwards25519.NewScalar().Multiply(c, xPow)
		result.Add(result, term)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}
	return result
}

// lagrangeCoeff computes the Lagrange basis coefficient for party myID evaluating at x=0,
// over the Ed25519 scalar field, with the given set of party IDs.
//
// lagrange(myID, allIDs, 0) = prod_{j≠myID} (-j / (myID - j)) mod L
func lagrangeCoeff(myID int, allIDs []int) *edwards25519.Scalar {
	num := scalarFromUint64(1)
	den := scalarFromUint64(1)
	xI := scalarFromInt(myID)
	zero := edwards25519.NewScalar()

	for _, j := range allIDs {
		if j == myID {
			continue
		}
		xJ := scalarFromInt(j)
		// num *= (0 - xJ) = -xJ
		negXJ := edwards25519.NewScalar().Subtract(zero, xJ)
		num = edwards25519.NewScalar().Multiply(num, negXJ)
		// den *= (xI - xJ)
		diff := edwards25519.NewScalar().Subtract(xI, xJ)
		den = edwards25519.NewScalar().Multiply(den, diff)
	}

	denInv := scalarInverse(den)
	return edwards25519.NewScalar().Multiply(num, denInv)
}

// DKGRound1 executes the first round of the Feldman VSS DKG for party config.MyID.
// Pi samples a degree-(t-1) polynomial, broadcasts Feldman commitments,
// and commits (via hash commitment) to each other party's share.
// Returns the round 1 output and the polynomial coefficients (needed for round 2).
func DKGRound1(config DKGPartyConfig) (out *DKGRound1Output, coeffs []*edwards25519.Scalar, err error) {
	secretdo.Do(func() {
		out, coeffs, err = dkgRound1(config)
	})
	return
}

func dkgRound1(config DKGPartyConfig) (*DKGRound1Output, []*edwards25519.Scalar, error) {
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

	// Sample polynomial coefficients a_{i,0}, ..., a_{i,t-1}.
	coeffs := make([]*edwards25519.Scalar, t)
	for k := 0; k < t; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, fmt.Errorf("frost DKGRound1: sample coefficient: %w", err)
		}
		coeffs[k] = c
	}

	// Compute Feldman commitments A_{i,k} = a_{i,k} * B.
	feldman := make([][]byte, t)
	for k := 0; k < t; k++ {
		pt := edwards25519.NewGeneratorPoint().ScalarBaseMult(coeffs[k])
		feldman[k] = pt.Bytes()
	}

	// Commit to pi(j) for each other party j.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(coeffs, j)
		shareBytes := share.Bytes()

		com, salt, err := commit(shareBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("frost DKGRound1: commit share for %d: %w", j, err)
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
// Returns the decommitments (plaintext shares) to send to each other party.
func DKGRound2(config DKGPartyConfig, myCoeffs []*edwards25519.Scalar) (out *DKGRound2Output, err error) {
	secretdo.Do(func() {
		out, err = dkgRound2(config, myCoeffs)
	})
	return
}

func dkgRound2(config DKGPartyConfig, myCoeffs []*edwards25519.Scalar) (*DKGRound2Output, error) {
	secretShares := make(map[int][]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(myCoeffs, j)
		shareBytes := make([]byte, ScalarLen)
		copy(shareBytes, share.Bytes())
		secretShares[j] = shareBytes
	}
	return &DKGRound2Output{SecretShares: secretShares}, nil
}

// feldmanVerify checks that share·B == sum_{k=0}^{t-1} A_{i,k} * x^k.
// This is the standard Feldman VSS verification equation.
func feldmanVerify(share *edwards25519.Scalar, x int, feldmanCommitments [][]byte) error {
	t := len(feldmanCommitments)
	xScalar := scalarFromInt(x)
	xPow := scalarFromUint64(1)

	// Compute RHS = sum_{k=0}^{t-1} A_{i,k} * x^k.
	rhs := edwards25519.NewIdentityPoint()
	for k := 0; k < t; k++ {
		Aik, err := edwards25519.NewIdentityPoint().SetBytes(feldmanCommitments[k])
		if err != nil {
			return fmt.Errorf("frost: parse Feldman commitment [%d]: %w", k, err)
		}
		scaled := edwards25519.NewIdentityPoint().ScalarMult(xPow, Aik)
		rhs.Add(rhs, scaled)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}

	// Compute LHS = share * B.
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(share)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("frost: Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// DKGFinalize verifies all received shares and computes the final key share.
// For each sender j:
//  1. Verifies hash commitment: Open(pi_j(myID), com_{j,myID}, salt_{j,myID})
//  2. Verifies Feldman check: pi_j(myID)·B == sum_k A_{j,k}·myID^k
//
// Returns the final KeyShare or error (listing bad senders).
func DKGFinalize(
	config DKGPartyConfig,
	myCoeffs []*edwards25519.Scalar,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (ks *KeyShare, err error) {
	secretdo.Do(func() {
		ks, err = dkgFinalize(config, myCoeffs, allRound1, allRound2)
	})
	return
}

func dkgFinalize(
	config DKGPartyConfig,
	myCoeffs []*edwards25519.Scalar,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (*KeyShare, error) {
	var badSenders []int

	finalShare := edwards25519.NewScalar()

	for _, j := range config.AllIDs {
		if j == config.MyID {
			// My own share: evaluate my polynomial at myID.
			myShare := evalPoly(myCoeffs, config.MyID)
			finalShare.Add(finalShare, myShare)
			continue
		}

		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify Feldman commitment count matches threshold.
		if len(r1j.FeldmanCommitments) != config.Threshold {
			badSenders = append(badSenders, j)
			continue
		}

		// Get the share pj(myID) sent by party j.
		shareBytes := r2j.SecretShares[config.MyID]
		if len(shareBytes) != ScalarLen {
			badSenders = append(badSenders, j)
			continue
		}
		shareVal, err := edwards25519.NewScalar().SetCanonicalBytes(shareBytes)
		if err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify hash commitment.
		com, ok1 := r1j.PairwiseCommitments[config.MyID]
		salt, ok2 := r1j.PairwiseSalts[config.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err := openCommitment(shareBytes, com, salt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify Feldman check: pj(myID)·B == sum_k A_{j,k}·myID^k.
		if err := feldmanVerify(shareVal, config.MyID, r1j.FeldmanCommitments); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		finalShare.Add(finalShare, shareVal)
	}

	if len(badSenders) > 0 {
		return nil, &CheatingPartyError{PartyIDs: badSenders, Phase: "DKGFinalize", Detail: "share or Feldman verification failed"}
	}

	// Compute aggregated Feldman commitments: A_k = sum_j A_{j,k} for each coefficient index.
	t := config.Threshold
	groupCommitments := make([][]byte, t)
	for k := 0; k < t; k++ {
		sumPt := edwards25519.NewIdentityPoint()
		for _, j := range config.AllIDs {
			Ajk, err := edwards25519.NewIdentityPoint().SetBytes(allRound1[j].FeldmanCommitments[k])
			if err != nil {
				return nil, fmt.Errorf("frost DKGFinalize: parse A_{%d,%d}: %w", j, k, err)
			}
			sumPt.Add(sumPt, Ajk)
		}
		groupCommitments[k] = sumPt.Bytes()
	}

	// Group public key is A_0 = sum_j A_{j,0}.
	publicKey := groupCommitments[0]

	// Verification share: s_i * B.
	verificationShare := edwards25519.NewGeneratorPoint().ScalarBaseMult(finalShare).Bytes()

	// Sort AllIDs for deterministic output.
	allIDsSorted := make([]int, len(config.AllIDs))
	copy(allIDsSorted, config.AllIDs)
	sort.Ints(allIDsSorted)

	ks := &KeyShare{
		ID:                config.MyID,
		SecretShare:       finalShare.Bytes(),
		PublicKey:         publicKey,
		VerificationShare: verificationShare,
		GroupCommitments:  groupCommitments,
		Threshold:         config.Threshold,
		AllIDs:            allIDsSorted,
	}
	return ks, nil
}
