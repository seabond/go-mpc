// Package node wraps the dkls23 package into a self-contained Node that
// models a single party in a threshold ECDSA deployment.
package node

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/seabond/go-mpc/dkls23"
)

// Node is a single DKLS23 party.
type Node struct {
	ID        int
	AllIDs    []int
	Threshold int
	Setup     *dkls23.SignerSetup

	dkgCoeffs []btcec.ModNScalar
	dkgRound1 *dkls23.DKGRound1Output

	refreshCoeffs []btcec.ModNScalar
	refreshSeed   [16]byte
}

// New creates a Node for the given party ID.
func New(id int, allIDs []int, threshold int) *Node {
	return &Node{ID: id, AllIDs: allIDs, Threshold: threshold}
}

// SessionID returns a fresh random session identifier.
func SessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ── Key Generation ──────────────────────────────────────────────

func (n *Node) DKGRound1() (*dkls23.DKGRound1Output, error) {
	cfg := dkls23.DKGPartyConfig{MyID: n.ID, AllIDs: n.AllIDs, Threshold: n.Threshold}
	out, coeffs, err := dkls23.DKGRound1(cfg)
	if err != nil {
		return nil, fmt.Errorf("node %d DKGRound1: %w", n.ID, err)
	}
	n.dkgCoeffs = coeffs
	n.dkgRound1 = out
	return out, nil
}

func (n *Node) DKGRound2(allRound1 map[int]*dkls23.DKGRound1Output) (*dkls23.DKGRound2Output, error) {
	cfg := dkls23.DKGPartyConfig{MyID: n.ID, AllIDs: n.AllIDs, Threshold: n.Threshold}
	peers := make(map[int]*dkls23.DKGRound1Output, len(allRound1)-1)
	for id, r := range allRound1 {
		if id != n.ID {
			peers[id] = r
		}
	}
	out, err := dkls23.DKGRound2(cfg, n.dkgCoeffs, peers)
	if err != nil {
		return nil, fmt.Errorf("node %d DKGRound2: %w", n.ID, err)
	}
	return out, nil
}

// DKGFinalize verifies shares, computes the Shamir share, and returns the
// 33-byte compressed master public key.
func (n *Node) DKGFinalize(
	allRound1 map[int]*dkls23.DKGRound1Output,
	allRound2 map[int]*dkls23.DKGRound2Output,
) (pubKey []byte, err error) {
	cfg := dkls23.DKGPartyConfig{MyID: n.ID, AllIDs: n.AllIDs, Threshold: n.Threshold}
	share, pk, err := dkls23.DKGFinalize(cfg, n.dkgCoeffs, allRound1, allRound2)
	if err != nil {
		return nil, fmt.Errorf("node %d DKGFinalize: %w", n.ID, err)
	}
	n.Setup = &dkls23.SignerSetup{
		MyID:       n.ID,
		AllIDs:     n.AllIDs,
		Share:      share,
		PubKey:     pk,
		Threshold:  n.Threshold,
		VoleAlice:  make(map[int]*dkls23.VOLEAliceState),
		VoleBob:    make(map[int]*dkls23.VOLEBobState),
		FZeroSeeds: make(map[int][16]byte),
		Blacklist:  make(map[int]bool),
	}
	n.dkgCoeffs = nil
	n.dkgRound1 = nil
	return pk, nil
}

// PublicKey returns the master public key (33-byte compressed secp256k1).
func (n *Node) PublicKey() []byte {
	if n.Setup == nil {
		return nil
	}
	return n.Setup.PubKey
}

// ── Pairwise Setup ──────────────────────────────────────────────

// SetupPairwiseWith establishes VOLE and FZero state between two nodes.
// Must be called after DKGFinalize on both sides.
func (n *Node) SetupPairwiseWith(peer *Node) error {
	if err := n.setupVOLEPair(peer); err != nil {
		return err
	}
	return n.setupFZeroPair(peer)
}

func (n *Node) setupVOLEPair(peer *Node) error {
	// Direction: n → peer (n is Alice, peer is Bob)
	aliceAB, bobAB, err := setupVOLEOneDirection()
	if err != nil {
		return fmt.Errorf("VOLE %d→%d: %w", n.ID, peer.ID, err)
	}
	n.Setup.VoleAlice[peer.ID] = aliceAB
	peer.Setup.VoleBob[n.ID] = bobAB

	// Direction: peer → n (peer is Alice, n is Bob)
	aliceBA, bobBA, err := setupVOLEOneDirection()
	if err != nil {
		return fmt.Errorf("VOLE %d→%d: %w", peer.ID, n.ID, err)
	}
	peer.Setup.VoleAlice[n.ID] = aliceBA
	n.Setup.VoleBob[peer.ID] = bobBA

	return nil
}

// setupVOLEOneDirection runs the full base OT → OT extension → VOLE flow
// and returns the Alice and Bob states.
func setupVOLEOneDirection() (*dkls23.VOLEAliceState, *dkls23.VOLEBobState, error) {
	// Base OT
	senderPriv, senderPub, err := dkls23.BaseSenderRound1(dkls23.LambdaC)
	if err != nil {
		return nil, nil, err
	}
	sigma := randomBools(dkls23.LambdaC)
	resp, recvSeeds, err := dkls23.BaseReceiverRound1(senderPub, sigma)
	if err != nil {
		return nil, nil, err
	}
	s0, s1, err := dkls23.BaseSenderFinalize(senderPriv, senderPub, resp)
	if err != nil {
		return nil, nil, err
	}

	// OT Extension
	beta := randomBetaXi()
	corr, err := dkls23.OTExtReceiverCorrections(s0, s1, beta)
	if err != nil {
		return nil, nil, err
	}
	a0, a1, err := dkls23.OTExtSenderExpand(recvSeeds, sigma, corr)
	if err != nil {
		return nil, nil, err
	}
	gam, err := dkls23.OTExtReceiverExpand(s0, beta, corr)
	if err != nil {
		return nil, nil, err
	}

	// VOLE
	alice, err := dkls23.VOLEAliceSetup(a0, a1)
	if err != nil {
		return nil, nil, err
	}
	bob, err := dkls23.VOLEBobSample(gam, beta)
	if err != nil {
		return nil, nil, err
	}
	return alice, bob, nil
}

func (n *Node) setupFZeroPair(peer *Node) error {
	comN, saltN, seedN, err := dkls23.FZeroSetupRound1()
	if err != nil {
		return err
	}
	comP, saltP, seedP, err := dkls23.FZeroSetupRound1()
	if err != nil {
		return err
	}
	sharedNP, err := dkls23.FZeroSetupFinalize(seedN, comP, saltP, seedP)
	if err != nil {
		return err
	}
	sharedPN, err := dkls23.FZeroSetupFinalize(seedP, comN, saltN, seedN)
	if err != nil {
		return err
	}
	n.Setup.FZeroSeeds[peer.ID] = sharedNP
	peer.Setup.FZeroSeeds[n.ID] = sharedPN
	return nil
}

// ── Signing ─────────────────────────────────────────────────────

func (n *Node) SignRound1(sigID string, signers []int) (*dkls23.Round1State, map[int]*dkls23.Round1Msg, error) {
	return dkls23.SignRound1(n.Setup, sigID, signers)
}

func (n *Node) SignRound2(state *dkls23.Round1State, allRound1 map[int]*dkls23.Round1Msg) (*dkls23.Round2State, map[int]*dkls23.Round2Msg, error) {
	return dkls23.SignRound2(n.Setup, state, allRound1)
}

func (n *Node) SignRound3(state *dkls23.Round2State, message []byte, allRound2 map[int]*dkls23.Round2Msg) (map[int]*dkls23.Round3Msg, error) {
	return dkls23.SignRound3(n.Setup, state, message, allRound2)
}

func (n *Node) SignCombine(rx *btcec.ModNScalar, myW, myU *btcec.ModNScalar, allRound3 map[int]*dkls23.Round3Msg, message []byte) (r, s []byte, err error) {
	return dkls23.SignCombine(n.Setup, rx, myW, myU, allRound3, message)
}

// ── Key Refresh ─────────────────────────────────────────────────

func (n *Node) RefreshRound1() (*dkls23.RefreshRound1Output, error) {
	out, coeffs, seed, err := dkls23.RefreshRound1(n.Setup)
	if err != nil {
		return nil, fmt.Errorf("node %d RefreshRound1: %w", n.ID, err)
	}
	n.refreshCoeffs = coeffs
	n.refreshSeed = seed
	return out, nil
}

func (n *Node) RefreshRound2(allRound1 map[int]*dkls23.RefreshRound1Output) (*dkls23.RefreshRound2Output, error) {
	_ = allRound1
	out, err := dkls23.RefreshRound2(n.Setup, n.refreshCoeffs, n.refreshSeed)
	if err != nil {
		return nil, fmt.Errorf("node %d RefreshRound2: %w", n.ID, err)
	}
	return out, nil
}

func (n *Node) RefreshFinalize(
	allRound1 map[int]*dkls23.RefreshRound1Output,
	allRound2 map[int]*dkls23.RefreshRound2Output,
) error {
	err := dkls23.RefreshFinalize(n.Setup, n.refreshCoeffs, n.refreshSeed, allRound1, allRound2)
	n.refreshCoeffs = nil
	n.refreshSeed = [16]byte{}
	if err != nil {
		return fmt.Errorf("node %d RefreshFinalize: %w", n.ID, err)
	}
	return nil
}

// Epoch returns the current refresh epoch (0 before any refresh).
func (n *Node) Epoch() int {
	if n.Setup == nil {
		return 0
	}
	return n.Setup.Epoch
}

// ── Utilities ───────────────────────────────────────────────────

// ComputeRx reconstructs R = Σ R_j and returns rx = R.x mod q.
func ComputeRx(signers []int, r2States map[int]*dkls23.Round2State) btcec.ModNScalar {
	var R btcec.JacobianPoint
	for _, id := range signers {
		pk, err := btcec.ParsePubKey(r2States[id].R_iPoint)
		if err != nil {
			panic(fmt.Sprintf("ComputeRx: parse R_%d: %v", id, err))
		}
		var pt btcec.JacobianPoint
		pk.AsJacobian(&pt)
		btcec.AddNonConst(&R, &pt, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx
}

// VerifySignature performs standalone ECDSA verification.
func VerifySignature(pubKeyBytes, message, r, s []byte) bool {
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false
	}
	msgHash := sha256.Sum256(message)
	var rS, sS btcec.ModNScalar
	rS.SetByteSlice(r)
	sS.SetByteSlice(s)
	return ecdsa.NewSignature(&rS, &sS).Verify(msgHash[:], pubKey)
}

func randomBools(n int) []bool {
	buf := make([]byte, (n+7)/8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	out := make([]bool, n)
	for k := 0; k < n; k++ {
		out[k] = (buf[k/8]>>(uint(k)%8))&1 == 1
	}
	return out
}

func randomBetaXi() [dkls23.Xi]bool {
	buf := make([]byte, (dkls23.Xi+7)/8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	var beta [dkls23.Xi]bool
	for j := 0; j < dkls23.Xi; j++ {
		beta[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return beta
}
