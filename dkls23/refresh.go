package dkls23

// Proactive share refresh for DKLS23 (online variant).
//
// Based on KMOS21: "Refresh When You Wake Up: Proactive Threshold Wallets with
// Offline Devices" (Kondi/Magri/Orlandi/Shlomovits, IEEE S&P 2021).
// https://eprint.iacr.org/2019/1328
//
// # Protocol summary (all parties online)
//
// Each party Pi samples a zero-constant degree-(t-1) polynomial:
//
//	f_i(x) = δ_{i,1}·x + δ_{i,2}·x² + … + δ_{i,t-1}·x^{t-1}
//
// so f_i(0) = 0.  Each Pj receives f_i(j) from Pi via FCom (commit-then-reveal)
// and verifies consistency with the Feldman commitments {C_{i,k} = δ_{i,k}·G}.
//
// New Shamir share for Pj:
//
//	share_j' = share_j + Σ_i f_i(j)  mod q
//
// Secret preserved: Lagrange(share', 0) = Lagrange(share, 0) since Σ_i f_i(0) = 0.
//
// Base OT re-randomization (KMOS21 §4 – Beaver OT re-randomization):
// A public SHAKE-256 stream seeded from a collectively committed combined seed
// drives per-instance bit flips and mask XORs that maintain the OT correlation
// invariant, now one level down: the receiver's seed stays the sender's seed for
// its choice bit, a_k' = s'_{sigma_k',k}. Signing derives its VOLE fresh from this
// base OT every session, so there is no long-lived correlation left to refresh.
//
// FZero seed refresh: per-pair seeds re-derived from the combined seed so that
// zero-sharing remains unbiased in future signing sessions.
//
// Impossibility note: for n=3, t=3, t_rho ≥ 2(t-1) = 4 > n, so all three
// parties must be online (proactive security requires full participation).

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/seabond/go-mpc/internal/secretdo"
	"golang.org/x/crypto/sha3"
)

// RefreshRound1Output is broadcast by each party Pi in refresh round 1.
// It contains Feldman commitments for a zero-constant polynomial and FCom
// commitments to the pairwise evaluations and a fresh per-party seed.
type RefreshRound1Output struct {
	// FeldmanCommitments are the t-1 compressed EC points C_{i,k} = δ_{i,k}·G
	// for k = 1..t-1.  No k=0 term: the polynomial is zero-constant, so f_i(0)=0.
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is FCom(f_i(j)) for peer j.
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the FCom salt for the commitment to f_i(j).
	PairwiseSalts map[int][SaltLen]byte
	// SeedCommitment is FCom of this party's 16-byte seed contribution.
	SeedCommitment [32]byte
	// SeedSalt is the FCom salt for the seed commitment.
	SeedSalt [SaltLen]byte
}

// RefreshRound2Output contains the decommitments Pi broadcasts in refresh round 2.
type RefreshRound2Output struct {
	// SecretShares[j] is f_i(j) encoded as 32-byte big-endian for each peer j.
	SecretShares map[int][]byte
	// Seed is the 16-byte seed Pi contributed in round 1.
	Seed [16]byte
}

// RefreshRound1 executes round 1 of the proactive refresh protocol for setup.MyID.
//
// Pi samples a zero-constant polynomial f_i(x) = δ_1·x + … + δ_{t-1}·x^{t-1},
// broadcasts Feldman commitments C_{i,k} = δ_k·G for k = 1..t-1, commits to
// f_i(j) for each peer j via FCom, and commits to a fresh 16-byte seed that will
// be used to re-randomize VOLE and FZero state in RefreshFinalize.
//
// Returns the broadcast output, the polynomial coefficients (kept private until
// RefreshRound2), and the seed (kept private until RefreshRound2).
func RefreshRound1(setup *SignerSetup) (out *RefreshRound1Output, coeffs []btcec.ModNScalar, seed [16]byte, err error) {
	secretdo.Do(func() {
		out, coeffs, seed, err = refreshRound1(setup)
	})
	return
}

func refreshRound1(setup *SignerSetup) (*RefreshRound1Output, []btcec.ModNScalar, [16]byte, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	t := setup.Threshold

	// Sample t-1 coefficients δ_1, …, δ_{t-1} for the zero-constant polynomial.
	// coeffs[k] = δ_{k+1} (the coefficient of x^{k+1}), so f(x) = Σ coeffs[k]·x^{k+1}.
	coeffs := make([]btcec.ModNScalar, t-1)
	for k := 0; k < t-1; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: sample coeff %d: %w", k+1, err)
		}
		coeffs[k] = c
	}

	// Compute Feldman commitments C_{i,k} = δ_k · G for k = 1..t-1.
	feldman := make([][]byte, t-1)
	for k := 0; k < t-1; k++ {
		pt, err := scalarMulGCompressed(&coeffs[k])
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: Feldman commitment k=%d: %w", k+1, err)
		}
		feldman[k] = pt
	}

	// Commit to f_i(j) for each peer j via FCom.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		share := evalZeroConstPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := shareArr[:]

		com, salt, err := Commit(shareBytes)
		for i := range shareArr {
			shareArr[i] = 0
		}
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	// Sample a fresh 16-byte seed and commit to it.
	var mySeed [16]byte
	if _, err := rand.Read(mySeed[:]); err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: sample seed: %w", err)
	}
	seedCom, seedSalt, err := Commit(mySeed[:])
	if err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: commit seed: %w", err)
	}

	out := &RefreshRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: pairwiseComs,
		PairwiseSalts:       pairwiseSalts,
		SeedCommitment:      seedCom,
		SeedSalt:            seedSalt,
	}
	return out, coeffs, mySeed, nil
}

// RefreshRound2 decommits pairwise evaluations and reveals the seed.
// coeffs and mySeed must be the values returned by RefreshRound1.
func RefreshRound2(setup *SignerSetup, coeffs []btcec.ModNScalar, mySeed [16]byte) (out *RefreshRound2Output, err error) {
	secretdo.Do(func() {
		out, err = refreshRound2(setup, coeffs, mySeed)
	})
	return
}

func refreshRound2(setup *SignerSetup, coeffs []btcec.ModNScalar, mySeed [16]byte) (*RefreshRound2Output, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	secretShares := make(map[int][]byte)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		share := evalZeroConstPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := make([]byte, 32)
		copy(shareBytes, shareArr[:])
		for i := range shareArr {
			shareArr[i] = 0
		}
		secretShares[j] = shareBytes
	}
	return &RefreshRound2Output{SecretShares: secretShares, Seed: mySeed}, nil
}

// RefreshFinalize verifies all received round 1/2 messages and, if all checks
// pass, mutates setup in place:
//
//  1. Verifies FCom decommitment of f_j(myID) for each sender j.
//  2. Verifies Feldman consistency: f_j(myID)·G = Σ_{k=1}^{t-1} C_{j,k}·myID^k.
//  3. Verifies seed FCom decommitment.
//  4. Derives combinedSeed = XOR of all n party seeds.
//  5. Updates the Shamir share: share += Σ_j f_j(myID) mod q.
//  6. Re-randomizes the pairwise base OT via Beaver OT refresh (KMOS21 §4).
//  7. Derives new per-pair FZero seeds from combinedSeed.
//  8. Increments setup.Epoch.
//
// Returns an error naming all bad senders if any verification fails; setup is
// NOT modified in that case.
func RefreshFinalize(
	setup *SignerSetup,
	coeffs []btcec.ModNScalar,
	mySeed [16]byte,
	allRound1 map[int]*RefreshRound1Output,
	allRound2 map[int]*RefreshRound2Output,
) (err error) {
	secretdo.Do(func() {
		err = refreshFinalize(setup, coeffs, mySeed, allRound1, allRound2)
	})
	return
}

func refreshFinalize(
	setup *SignerSetup,
	coeffs []btcec.ModNScalar,
	mySeed [16]byte,
	allRound1 map[int]*RefreshRound1Output,
	allRound2 map[int]*RefreshRound2Output,
) error {
	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := checkBlacklist(setup, setup.AllIDs, "RefreshFinalize"); err != nil {
		return err
	}
	var badSenders []int

	// Validate messages and accumulate share additions from peers.
	// We separate validation from mutation so setup is unchanged on error.
	type peerContrib struct {
		shareVal btcec.ModNScalar
		seed     [16]byte
	}
	peerContribs := make(map[int]peerContrib, len(setup.AllIDs)-1)

	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 1: Verify FCom decommitment of f_j(myID).
		shareBytes := r2j.SecretShares[setup.MyID]
		if len(shareBytes) != 32 {
			badSenders = append(badSenders, j)
			continue
		}
		com, ok1 := r1j.PairwiseCommitments[setup.MyID]
		salt, ok2 := r1j.PairwiseSalts[setup.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err := Open(shareBytes, com, salt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 2: Feldman verification: f_j(myID)·G = Σ_{k=1}^{t-1} C_{j,k}·myID^k.
		var shareVal btcec.ModNScalar
		shareVal.SetByteSlice(shareBytes)
		if err := refreshFeldmanVerify(&shareVal, setup.MyID, r1j.FeldmanCommitments); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 3: Verify seed FCom decommitment.
		if err := Open(r2j.Seed[:], r1j.SeedCommitment, r1j.SeedSalt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		peerContribs[j] = peerContrib{shareVal: shareVal, seed: r2j.Seed}
	}

	if len(badSenders) > 0 {
		return &CheatingPartyError{PartyIDs: badSenders, Phase: "RefreshFinalize", Detail: "share, Feldman, or seed verification failed"}
	}

	// Step 4: Derive combinedSeed = XOR of all n party seeds (including mine).
	combinedSeed := mySeed
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		pc := peerContribs[j]
		for b := 0; b < 16; b++ {
			combinedSeed[b] ^= pc.seed[b]
		}
	}

	// Step 5: Update Shamir share.
	// new_share = old_share + f_i(myID) + Σ_{j≠i} f_j(myID)  mod q.
	myContrib := evalZeroConstPoly(coeffs, uint32(setup.MyID))
	var shareAdd btcec.ModNScalar
	shareAdd.Set(&myContrib)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		pc := peerContribs[j]
		shareAdd.Add(&pc.shareVal)
	}
	var newShare btcec.ModNScalar
	newShare.Add2(&setup.Share, &shareAdd)

	// Step 6: Re-randomize the base OT into a temporary map.
	// Built separately so setup is untouched if any step fails.
	//
	// This used to re-randomize stored VOLE correlations. There are none any more —
	// each signing session derives its own from this base OT — so refresh operates one
	// level down, on the base OT itself.
	newBaseOT := make(map[int]*BaseOTMaterial, len(setup.AllIDs)-1)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		m, err := refreshBaseOT(setup.BaseOT[j], setup.MyID, j, combinedSeed)
		if err != nil {
			return fmt.Errorf("dkls23 RefreshFinalize: refreshBaseOT(%d↔%d): %w", setup.MyID, j, err)
		}
		newBaseOT[j] = m
	}

	// Step 7: Derive new FZero seeds from combinedSeed.
	newFZeroSeeds := make(map[int][16]byte, len(setup.AllIDs)-1)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		newFZeroSeeds[j] = deriveFZeroSeed(combinedSeed, setup.MyID, j)
	}

	myContrib.Zero()
	shareAdd.Zero()

	// All mutations succeed atomically from this point.
	setup.Share = newShare
	setup.BaseOT = newBaseOT
	setup.FZeroSeeds = newFZeroSeeds
	setup.Epoch++
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// evalZeroConstPoly evaluates the zero-constant polynomial
//
//	f(x) = coeffs[0]·x + coeffs[1]·x² + … + coeffs[t-2]·x^{t-1}
//
// at x.  The polynomial has no constant term, so f(0) = 0.
// All arithmetic is constant-time via ModNScalar.
func evalZeroConstPoly(coeffs []btcec.ModNScalar, x uint32) btcec.ModNScalar {
	var result, xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(x)
	xPow.Set(&xScalar) // x^1
	for _, c := range coeffs {
		var term btcec.ModNScalar
		term.Mul2(&c, &xPow)
		result.Add(&term)
		xPow.Mul(&xScalar)
	}
	return result
}

// refreshFeldmanVerify checks that share·G = Σ_{k=1}^{t-1} C_{i,k} · x^k
// for a zero-constant polynomial (no constant term commitment).
// nonConstFeldman[k] is the compressed point for the (k+1)-th coefficient.
func refreshFeldmanVerify(share *btcec.ModNScalar, x int, nonConstFeldman [][]byte) error {
	if len(nonConstFeldman) == 0 {
		// t = 1: the zero-constant polynomial is f(x) = 0 for all x.
		if !share.IsZero() {
			return errors.New("dkls23: refresh Feldman failed: nonzero share for zero-degree polynomial")
		}
		return nil
	}

	var xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(uint32(x))
	xPow.Set(&xScalar) // x^1

	// RHS = Σ_{k=1}^{t-1} C_{i,k} · x^k.
	var rhs btcec.JacobianPoint
	for _, commitBytes := range nonConstFeldman {
		Cik, err := compressedToPoint(commitBytes)
		if err != nil {
			return fmt.Errorf("dkls23: parse refresh Feldman commitment: %w", err)
		}
		scaled := scalarMul(&xPow, Cik)
		btcec.AddNonConst(&rhs, scaled, &rhs)
		xPow.Mul(&xScalar)
	}
	rhs.ToAffine()

	// LHS = share · G.
	var lhs btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(share, &lhs)
	lhs.ToAffine()

	// Both sides must be the point at infinity (zero share) or equal affine points.
	lhsInf := lhs.X.IsZero() && lhs.Y.IsZero()
	rhsInf := rhs.X.IsZero() && rhs.Y.IsZero()
	if lhsInf != rhsInf {
		return errors.New("dkls23: refresh Feldman verification failed: point at infinity mismatch")
	}
	if lhsInf {
		return nil
	}
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return errors.New("dkls23: refresh Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// refreshBaseOT re-randomizes one party's base-OT material toward a single
// counterparty, in both directions. It returns a new value; the original is not
// modified.
//
// Both parties derive the same per-direction stream from combinedSeed and apply
// MATCHED transforms, so the base OT stays consistent across the pair without any
// extra messages:
//
//	shared per index k:  a bit c_k, and two 32-byte masks m0_k, m1_k
//	sender (VOLE Bob) side, holding (s0_k, s1_k):
//	    s0_k' = (c_k ? s1_k : s0_k) XOR m0_k
//	    s1_k' = (c_k ? s0_k : s1_k) XOR m1_k
//	receiver (VOLE Alice) side, holding sigma_k and a_k = s_{sigma_k,k}:
//	    sigma_k' = sigma_k XOR c_k
//	    a_k'     = a_k XOR m_{sigma_k',k}
//
// The receiver's invariant a_k' = s'_{sigma_k',k} holds in all four (c_k, sigma_k)
// cases, which is what makes the pair still able to run OT extension afterwards.
//
// HONEST LIMITATION, unchanged from the VOLE re-randomization this replaces:
// combinedSeed is derived from every party's contributed seed, so a party that
// PARTICIPATED in the refresh can recompute the transform and track the material
// across epochs. Refresh therefore protects against an attacker who held material
// from an earlier epoch and was absent from the refresh — not against a resident one.
// Evicting a resident attacker requires a fresh base OT, i.e. re-pairing.
func refreshBaseOT(m *BaseOTMaterial, myID, peerID int, combinedSeed [16]byte) (*BaseOTMaterial, error) {
	if m == nil {
		return nil, &CorruptStateError{
			Phase:  "RefreshFinalize",
			Detail: fmt.Sprintf("missing base OT material for party %d", peerID),
		}
	}
	if len(m.BobSeeds0) != LambdaC || len(m.BobSeeds1) != LambdaC ||
		len(m.AliceSeeds) != LambdaC || len(m.Sigma) != LambdaC {
		return nil, &CorruptStateError{
			Phase: "RefreshFinalize",
			Detail: fmt.Sprintf("base OT material for party %d has lengths %d/%d/%d/%d, want %d each",
				peerID, len(m.BobSeeds0), len(m.BobSeeds1), len(m.AliceSeeds), len(m.Sigma), LambdaC),
		}
	}

	out := &BaseOTMaterial{
		BobSeeds0:  make([][]byte, LambdaC),
		BobSeeds1:  make([][]byte, LambdaC),
		AliceSeeds: make([][]byte, LambdaC),
		Sigma:      make([]bool, LambdaC),
	}

	// I am VOLE Bob in the direction (peer -> me), so my sender seeds are refreshed
	// under that direction's stream. The swap bit c is derived from combinedSeed and
	// is therefore known to every party — branching on it leaks nothing, unlike sigma
	// below.
	bobXOF := newBaseOTRefreshStream(combinedSeed, peerID, myID)
	for k := 0; k < LambdaC; k++ {
		c, mask0, mask1 := readRefreshStep(bobXOF)
		src0, src1 := m.BobSeeds0[k], m.BobSeeds1[k]
		if c {
			src0, src1 = src1, src0
		}
		out.BobSeeds0[k] = xorBytes(src0, mask0[:])
		out.BobSeeds1[k] = xorBytes(src1, mask1[:])
	}

	// I am VOLE Alice in the direction (me -> peer). sigma is secret, so the mask
	// choice it drives must be branchless — same treatment the VOLE re-randomization
	// this replaced gave it.
	aliceXOF := newBaseOTRefreshStream(combinedSeed, myID, peerID)
	for k := 0; k < LambdaC; k++ {
		c, mask0, mask1 := readRefreshStep(aliceXOF)
		newSigma := m.Sigma[k] != c // XOR
		mask := mask0
		subtle.ConstantTimeCopy(int(condUint32(newSigma)), mask[:], mask1[:])
		out.Sigma[k] = newSigma
		out.AliceSeeds[k] = xorBytes(m.AliceSeeds[k], mask[:])
	}

	return out, nil
}

// readRefreshStep draws one index's worth of shared randomness: the swap bit and the
// two seed masks. Both sides of a directed pair must consume the stream in exactly
// this order for the transforms to match.
func readRefreshStep(xof sha3.ShakeHash) (c bool, mask0, mask1 [baseOTSeedLen]byte) {
	var bit [1]byte
	xof.Read(bit[:])
	c = (bit[0] & 1) == 1
	xof.Read(mask0[:])
	xof.Read(mask1[:])
	return c, mask0, mask1
}

// xorBytes returns src XOR mask, truncating the mask to len(src).
func xorBytes(src, mask []byte) []byte {
	out := make([]byte, len(src))
	for i := range src {
		out[i] = src[i] ^ mask[i]
	}
	return out
}

// newBaseOTRefreshStream returns a SHAKE-256 XOF for re-randomizing the directed
// base OT (aliceID -> bobID), where aliceID is the OTE sender / VOLE Alice.
func newBaseOTRefreshStream(combinedSeed [16]byte, aliceID, bobID int) sha3.ShakeHash {
	return newVOLERefreshStream(combinedSeed, aliceID, bobID)
}

// newVOLERefreshStream returns a SHAKE-256 XOF for re-randomizing the directed
// VOLE pair (aliceID → bobID).
func newVOLERefreshStream(combinedSeed [16]byte, aliceID, bobID int) sha3.ShakeHash {
	xof := sha3.NewShake256()
	xof.Write([]byte(domainVOLERefresh))
	xof.Write(combinedSeed[:])
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(aliceID))
	xof.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:], uint32(bobID))
	xof.Write(buf[:])
	return xof
}

// deriveFZeroSeed derives a new per-pair FZero seed from the combined refresh seed.
func deriveFZeroSeed(combinedSeed [16]byte, myID, peerID int) [16]byte {
	lo, hi := myID, peerID
	if lo > hi {
		lo, hi = hi, lo
	}
	xof := sha3.NewShake256()
	xof.Write([]byte(domainFZeroRefresh))
	xof.Write(combinedSeed[:])
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(lo))
	xof.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:], uint32(hi))
	xof.Write(buf[:])
	var seed [16]byte
	xof.Read(seed[:])
	return seed
}
