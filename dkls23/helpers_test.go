package dkls23

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// buildSetups constructs a complete SignerSetup for each party: DKG + pairwise
// VOLE/FZero, with pairwise work parallelised across goroutines.
func buildSetups(allIDs []int, threshold int) (map[int]*SignerSetup, error) {
	// ---- Phase 1: DKG (sequential, fast) ----
	configs := map[int]DKGPartyConfig{}
	coeffs := map[int][]btcec.ModNScalar{}
	r1 := map[int]*DKGRound1Output{}
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		if err != nil {
			return nil, err
		}
		r1[id] = out
		coeffs[id] = c
	}
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
			return nil, err
		}
		r2[id] = out
	}

	setups := map[int]*SignerSetup{}
	for _, id := range allIDs {
		share, pk, err := DKGFinalize(configs[id], coeffs[id], r1, r2)
		if err != nil {
			return nil, err
		}
		setups[id] = &SignerSetup{
			MyID: id, AllIDs: allIDs, Share: share, PubKey: pk,
			Threshold:  threshold,
			BaseOT:     make(map[int]*BaseOTMaterial),
			FZeroSeeds: make(map[int][16]byte),
			Blacklist:  make(map[int]bool),
		}
	}

	// ---- Phase 2: Pairwise VOLE + FZero (parallel) ----
	type pair struct{ i, j int }
	var pairs []pair
	for pi := 0; pi < len(allIDs); pi++ {
		for pj := pi + 1; pj < len(allIDs); pj++ {
			pairs = append(pairs, pair{allIDs[pi], allIDs[pj]})
		}
	}

	type direction struct {
		bobSeeds0, bobSeeds1, aliceSeeds [][]byte
		sigma                            []bool
	}
	type pairResult struct {
		ij, ji           direction
		fzeroIJ, fzeroJI [16]byte
		err              error
	}

	results := make([]pairResult, len(pairs))
	var wg sync.WaitGroup
	for idx := range pairs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := &results[idx]

			r.ij.bobSeeds0, r.ij.bobSeeds1, r.ij.aliceSeeds, r.ij.sigma, r.err = runBaseOTOneDirection()
			if r.err != nil {
				return
			}
			r.ji.bobSeeds0, r.ji.bobSeeds1, r.ji.aliceSeeds, r.ji.sigma, r.err = runBaseOTOneDirection()
			if r.err != nil {
				return
			}

			com1, salt1, seed1, err := FZeroSetupRound1()
			if err != nil {
				r.err = err
				return
			}
			com2, salt2, seed2, err := FZeroSetupRound1()
			if err != nil {
				r.err = err
				return
			}
			r.fzeroIJ, err = FZeroSetupFinalize(seed1, com2, salt2, seed2)
			if err != nil {
				r.err = err
				return
			}
			r.fzeroJI, err = FZeroSetupFinalize(seed2, com1, salt1, seed1)
			if err != nil {
				r.err = err
				return
			}
		}(idx)
	}
	wg.Wait()

	for idx, p := range pairs {
		r := results[idx]
		if r.err != nil {
			return nil, r.err
		}
		// i is VOLE Alice in direction i→j and VOLE Bob in direction j→i.
		matI, err := NewBaseOTMaterial(r.ji.bobSeeds0, r.ji.bobSeeds1, r.ij.aliceSeeds, r.ij.sigma)
		if err != nil {
			return nil, err
		}
		matJ, err := NewBaseOTMaterial(r.ij.bobSeeds0, r.ij.bobSeeds1, r.ji.aliceSeeds, r.ji.sigma)
		if err != nil {
			return nil, err
		}
		setups[p.i].BaseOT[p.j] = matI
		setups[p.j].BaseOT[p.i] = matJ
		setups[p.i].FZeroSeeds[p.j] = r.fzeroIJ
		setups[p.j].FZeroSeeds[p.i] = r.fzeroJI
	}

	return setups, nil
}

// ---- Cached 3-of-3 setup ----

var (
	cached3of3Once sync.Once
	cached3of3JSON map[int][]byte
	cached3of3Err  error
)

// fullSetup returns a 3-of-3 SignerSetup per party. The expensive crypto setup
// runs once and is cached; each call returns an independent deep copy.
func fullSetup(t testing.TB) map[int]*SignerSetup {
	t.Helper()
	cached3of3Once.Do(func() {
		setups, err := buildSetups([]int{1, 2, 3}, 3)
		if err != nil {
			cached3of3Err = err
			return
		}
		cached3of3JSON = make(map[int][]byte)
		for id, s := range setups {
			b, err := json.Marshal(s)
			if err != nil {
				cached3of3Err = err
				return
			}
			cached3of3JSON[id] = b
		}
	})
	require.NoError(t, cached3of3Err)
	result := make(map[int]*SignerSetup)
	for id, b := range cached3of3JSON {
		var s SignerSetup
		err := json.Unmarshal(b, &s)
		require.NoError(t, err)
		result[id] = &s
	}
	return result
}

// fullSign runs a 3-of-3 signing session and returns all intermediate state.
func fullSign(t testing.TB, setups map[int]*SignerSetup, msg []byte) (
	r1States map[int]*Round1State,
	r1Msgs map[int]map[int]*Round1Msg,
	r2States map[int]*Round2State,
	r2Msgs map[int]map[int]*Round2Msg,
	r3Frags map[int]map[int]*Round3Msg,
) {
	t.Helper()
	signers := []int{1, 2, 3}
	sigID := "test-encoding-sig"

	r1States = make(map[int]*Round1State)
	r1Msgs = make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1States[id] = st
		r1Msgs[id] = msgs
	}

	r2States = make(map[int]*Round2State)
	r2Msgs = make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		inbound := map[int]*Round1Msg{}
		for _, j := range signers {
			if j != id {
				inbound[j] = r1Msgs[j][id]
			}
		}
		st, msgs, err := SignRound2(setups[id], r1States[id], inbound)
		require.NoError(t, err)
		r2States[id] = st
		r2Msgs[id] = msgs
	}

	r3Frags = make(map[int]map[int]*Round3Msg)
	for _, id := range signers {
		inbound := map[int]*Round2Msg{}
		for _, j := range signers {
			if j != id {
				inbound[j] = r2Msgs[j][id]
			}
		}
		frags, err := SignRound3(setups[id], r2States[id], msg, inbound)
		require.NoError(t, err)
		r3Frags[id] = frags
	}
	return
}

// computeRxFromStates computes rx = (Σ R_j).x mod q from Round2State R_iPoint values.
func computeRxFromStates(signers []int, states map[int]*Round2State) btcec.ModNScalar {
	var R btcec.JacobianPoint
	for _, id := range signers {
		pt, err := compressedToPoint(states[id].R_iPoint)
		if err != nil {
			panic(err)
		}
		btcec.AddNonConst(&R, pt, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx
}

// roundTrip marshals v to JSON, unmarshals into a new value of the same type,
// then marshals again and asserts the two JSON outputs are byte-equal.
func roundTrip[T any](t *testing.T, name string, v *T) *T {
	t.Helper()
	b1, err := json.Marshal(v)
	require.NoError(t, err, "%s: first marshal", name)
	require.NotEmpty(t, b1)

	var out T
	err = json.Unmarshal(b1, &out)
	require.NoError(t, err, "%s: unmarshal", name)

	b2, err := json.Marshal(&out)
	require.NoError(t, err, "%s: second marshal", name)
	require.JSONEq(t, string(b1), string(b2), "%s: round-trip JSON mismatch", name)
	return &out
}

// failingEncryptor always returns errors, used to test error paths.
type failingEncryptor struct{}

func (f *failingEncryptor) Encrypt([]byte) ([]byte, error) {
	return nil, errors.New("encrypt failed")
}
func (f *failingEncryptor) Decrypt([]byte) ([]byte, error) {
	return nil, errors.New("decrypt failed")
}

// runBaseOTOneDirection runs one directed base OT and returns both halves: the
// sender seed pairs the OTE receiver (VOLE Bob) needs, and the receiver seeds plus
// choice bits the OTE sender (VOLE Alice) needs.
func runBaseOTOneDirection() (bobSeeds0, bobSeeds1, aliceSeeds [][]byte, sigma []bool, err error) {
	bobPrivKeys, bobPubKeys, err := BaseSenderRound1(LambdaC)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sigmaBytes := make([]byte, (LambdaC+7)/8)
	if _, err = rand.Read(sigmaBytes); err != nil {
		return nil, nil, nil, nil, err
	}
	sigma = make([]bool, LambdaC)
	for k := 0; k < LambdaC; k++ {
		sigma[k] = (sigmaBytes[k/8]>>(uint(k)%8))&1 == 1
	}
	responses, aliceSeeds, err := BaseReceiverRound1(bobPubKeys, sigma)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	bobSeeds0, bobSeeds1, err = BaseSenderFinalize(bobPrivKeys, bobPubKeys, responses)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return bobSeeds0, bobSeeds1, aliceSeeds, sigma, nil
}

// runVOLEPairwise is a helper for the VOLE unit tests: runs a full OTE+VOLE setup
// between Alice and Bob. Note this produces a ONE-SHOT correlation — the signing
// protocol derives its own per session and never stores one.
// Returns (aliceState, bobState) ready for VOLEAliceMultiply / VOLEBobReceive.
func runVOLEPairwise() (*VOLEAliceState, *VOLEBobState, error) {
	// Bob plays base OT sender; Alice plays base OT receiver.
	bobPrivKeys, bobPubKeys, err := BaseSenderRound1(LambdaC)
	if err != nil {
		return nil, nil, err
	}

	// Alice's choices sigma.
	sigmaBytes := make([]byte, (LambdaC+7)/8)
	if _, err = rand.Read(sigmaBytes); err != nil {
		return nil, nil, err
	}
	sigma := make([]bool, LambdaC)
	for k := 0; k < LambdaC; k++ {
		sigma[k] = (sigmaBytes[k/8]>>(uint(k)%8))&1 == 1
	}

	responses, aliceSeeds, err := BaseReceiverRound1(bobPubKeys, sigma)
	if err != nil {
		return nil, nil, err
	}
	bobSeeds0, bobSeeds1, err := BaseSenderFinalize(bobPrivKeys, bobPubKeys, responses)
	if err != nil {
		return nil, nil, err
	}

	// Bob's random beta.
	betaBytes := make([]byte, (Xi+7)/8)
	if _, err = rand.Read(betaBytes); err != nil {
		return nil, nil, err
	}
	var beta [Xi]bool
	for j := 0; j < Xi; j++ {
		beta[j] = (betaBytes[j/8]>>(uint(j)%8))&1 == 1
	}

	corrections, err := OTExtReceiverCorrections(testSID, bobSeeds0, bobSeeds1, beta)
	if err != nil {
		return nil, nil, err
	}

	alpha0, alpha1, err := OTExtSenderExpand(testSID, aliceSeeds, sigma, corrections)
	if err != nil {
		return nil, nil, err
	}

	gamma, err := OTExtReceiverExpand(testSID, bobSeeds0, beta, corrections)
	if err != nil {
		return nil, nil, err
	}

	aliceState, err := VOLEAliceSetup(alpha0, alpha1)
	if err != nil {
		return nil, nil, err
	}

	bobState, err := VOLEBobSample(gamma, beta)
	if err != nil {
		return nil, nil, err
	}

	return aliceState, bobState, nil
}

// testSID stands in for a signing session's directed-pair id. Production derives
// it from voleSIDForPair; tests that exercise the OT extension in isolation only
// need both sides to agree on the same string.
const testSID = "test-session:vole:1->2"
