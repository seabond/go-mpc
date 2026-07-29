package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/seabond/go-mpc/internal/secretdo"
)

// --- πECDSA: 3-round threshold signing protocol (DKLS23 Protocol 3.6) ---
//
// The signing protocol uses VOLE for distributed multiplication,
// FZero for zero-sharing of key shares, and FCom for commitment to nonce points.
//
// Correctness argument:
//   sum_i u_i = sum_i r_i * eff_phi_i + sum_{i,j} (c^u_{i,j} + d^u_{i,j})
//             = phi * R_scalar   (since sum VOLE outputs cancel mod q)
//   sum_i w_i = hash * phi + rx * sk * phi
//   s = sum(w) / sum(u) = (hash + rx*sk) / R_scalar = standard ECDSA s.

// SignerSetup holds per-signer persistent state initialized once during pairing setup.
// It is reused across signing sessions, but note carefully WHAT is reused: the Shamir
// share, the FZero seeds, and the base OT. The VOLE correlations built on top of the
// base OT are single-use and never live here — see BaseOTMaterial for why.
//
// SignerSetup is safe for concurrent use: read-only operations (signing) acquire
// a read lock, while mutating operations (refresh, blacklisting) acquire a write lock.
// A SignerSetup must not be copied after first use.
type SignerSetup struct {
	// mu protects all mutable fields below. Unexported so it is excluded from
	// JSON serialization and cannot be misused by callers.
	mu sync.RWMutex
	// MyID is this party's identifier (1-indexed).
	MyID int
	// AllIDs is the sorted list of all DKG participant identifiers.
	AllIDs []int
	// Share is this party's Shamir share p(myID) from DKG.
	Share btcec.ModNScalar
	// PubKey is the master public key (33-byte compressed).
	PubKey []byte
	// Threshold is the signing threshold t.
	Threshold int
	// BaseOT[j] holds the reusable base-OT outputs shared with party j. The VOLE
	// correlations themselves are NOT stored here: they are derived fresh for every
	// signing session from this material. See BaseOTMaterial.
	BaseOT map[int]*BaseOTMaterial
	// FZeroSeeds[j] is the shared FZero seed between this party and party j.
	FZeroSeeds map[int][16]byte
	// Blacklist records parties detected cheating; they are excluded from future sessions.
	Blacklist map[int]bool
	// Epoch is the proactive refresh epoch counter, starting at 0 and incremented on each RefreshFinalize.
	Epoch int
	// SignCounter is a monotonic counter incremented on each SignRound1 call.
	// It exists so an operator can notice a state-snapshot rollback: a restored
	// SignerSetup with a lower counter than expected has lost signing history.
	//
	// It is NOT what prevents VOLE correlation reuse — nothing stored here is
	// reused across sessions any more, so a rollback replays no correlation. The
	// counter is a detection signal, and go-mpc does not enforce it; a caller that
	// wants rollback detection must compare it itself.
	SignCounter uint64
}

// BaseOTMaterial holds one party's half of the base OT run against a single
// counterparty, in both directions. It is the ONLY long-lived pairwise secret the
// signing protocol keeps.
//
// Why this exists instead of a stored VOLEAliceState/VOLEBobState: the RVOLE of
// Protocol 5.2 supplies Ell=2 inputs PER SIGNING SESSION and its correlation must be
// fresh each time. A stored correlation makes Bob's beta — and therefore
// chi = GadgetInnerProduct(beta) — a constant across sessions, at which point each
// session's round-3 fragment is an affine equation in the same two unknowns
// (the counterparty's chi and its Shamir share). Three sessions then give a 3x3
// linear system over Zq with an exact solution, so a single honest-looking party
// recovers its counterparty's share and reconstructs the group private key. Do not
// reintroduce a persisted VOLE state as an optimisation.
//
// Base OT, by contrast, is legitimately reusable: IKNP extends a fixed set of base
// OTs into arbitrarily many extended OTs, and only the extension must be fresh. That
// is also the cheap half — the base OT costs ~40ms while a fresh extension costs
// ~2.6ms, so per-session freshness is affordable.
type BaseOTMaterial struct {
	// BobSeeds0 and BobSeeds1 are the base-OT SENDER seed pairs (K^0_k, K^1_k) for
	// k∈[LambdaC], used when I act as the OTE receiver — i.e. VOLE Bob, the party
	// holding beta — toward this counterparty.
	BobSeeds0 [][]byte
	BobSeeds1 [][]byte
	// AliceSeeds are the base-OT RECEIVER seeds K^{sigma_k}_k and Sigma the matching
	// choice bits, used when I act as the OTE sender — i.e. VOLE Alice — toward this
	// counterparty.
	AliceSeeds [][]byte
	Sigma      []bool
}

// sampleBeta draws a fresh OTE receiver input for one signing session.
//
// This MUST come from the CSPRNG. Deriving it from sigID, an epoch counter, or any
// seed shared with the counterparty would make it predictable to exactly the party it
// must be hidden from, which restores the correlation-reuse break in full.
func sampleBeta() (beta [Xi]bool, err error) {
	buf := make([]byte, (Xi+7)/8)
	if _, err = rand.Read(buf); err != nil {
		return beta, fmt.Errorf("dkls23 sampleBeta: %w", err)
	}
	for j := 0; j < Xi; j++ {
		beta[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return beta, nil
}

// freshBobForSession derives a single-use VOLE Bob state, plus the OTE corrections
// that must be handed to the counterparty so it can derive the matching Alice state.
//
// sid is the DIRECTED-pair session id for the direction in which this party is
// Bob. It must equal the sid the counterparty uses as Alice for the same
// direction, or the correlation will not cancel. Both sides derive it from
// voleSIDForPair, so they agree by construction.
//
// Passing sid is not bookkeeping: without it the OT extension expands a fixed
// base-OT seed to a fixed pad, and a fresh beta only re-selects among those
// fixed pads. See prg in ot_extension.go for what that costs.
func freshBobForSession(sid string, m *BaseOTMaterial) (*VOLEBobState, [][Xi / 8]byte, oteConsistencyProof, error) {
	beta, err := sampleBeta()
	if err != nil {
		return nil, nil, oteConsistencyProof{}, err
	}
	corrections, proof, err := OTExtReceiverCorrections(sid, m.BobSeeds0, m.BobSeeds1, beta)
	if err != nil {
		return nil, nil, oteConsistencyProof{}, fmt.Errorf("dkls23 freshBobForSession: corrections: %w", err)
	}
	gamma, err := OTExtReceiverExpand(sid, m.BobSeeds0, beta, corrections)
	if err != nil {
		return nil, nil, oteConsistencyProof{}, fmt.Errorf("dkls23 freshBobForSession: expand: %w", err)
	}
	bob, err := VOLEBobSample(gamma, beta)
	if err != nil {
		return nil, nil, oteConsistencyProof{}, fmt.Errorf("dkls23 freshBobForSession: sample: %w", err)
	}
	return bob, corrections, proof, nil
}

// freshAliceForSession derives a single-use VOLE Alice state from the corrections the
// counterparty produced as Bob for this session.
func freshAliceForSession(sid string, m *BaseOTMaterial, theirCorrections [][Xi / 8]byte, proof oteConsistencyProof) (*VOLEAliceState, error) {
	alpha0, alpha1, err := OTExtSenderExpand(sid, m.AliceSeeds, m.Sigma, theirCorrections, proof)
	if err != nil {
		return nil, fmt.Errorf("dkls23 freshAliceForSession: expand: %w", err)
	}
	alice, err := VOLEAliceSetup(alpha0, alpha1)
	if err != nil {
		return nil, fmt.Errorf("dkls23 freshAliceForSession: setup: %w", err)
	}
	return alice, nil
}

// NewBaseOTMaterial assembles one party's reusable base-OT state toward one
// counterparty and validates its shape. It replaces the former SignSetupPairwise,
// which assembled a long-lived VOLE correlation — the thing that must no longer
// exist.
//
// The caller runs the two directed base OTs and supplies both halves. Note IKNP's
// role reversal: the base-OT *sender* becomes the OTE *receiver* (VOLE Bob, the side
// holding beta), and the base-OT *receiver* becomes the OTE *sender* (VOLE Alice).
//
// Parameters:
//   - bobSeeds0, bobSeeds1: base-OT sender seed pairs (K^0_k, K^1_k) from the base OT
//     in which I was the sender. Used when I am VOLE Bob toward this counterparty.
//   - aliceSeeds, sigma: base-OT receiver seeds K^{sigma_k}_k and the matching choice
//     bits, from the base OT in which I was the receiver. Used when I am VOLE Alice.
func NewBaseOTMaterial(bobSeeds0, bobSeeds1, aliceSeeds [][]byte, sigma []bool) (*BaseOTMaterial, error) {
	if len(bobSeeds0) != LambdaC || len(bobSeeds1) != LambdaC {
		return nil, &InvalidInputError{
			Phase:  "NewBaseOTMaterial",
			Detail: fmt.Sprintf("bob seeds must have %d entries, got %d/%d", LambdaC, len(bobSeeds0), len(bobSeeds1)),
		}
	}
	if len(aliceSeeds) != LambdaC || len(sigma) != LambdaC {
		return nil, &InvalidInputError{
			Phase:  "NewBaseOTMaterial",
			Detail: fmt.Sprintf("alice seeds and sigma must have %d entries, got %d/%d", LambdaC, len(aliceSeeds), len(sigma)),
		}
	}
	return &BaseOTMaterial{
		BobSeeds0:  bobSeeds0,
		BobSeeds1:  bobSeeds1,
		AliceSeeds: aliceSeeds,
		Sigma:      sigma,
	}, nil
}

// voleSIDForPair constructs a deterministic VOLE session ID from signing session ID and party pair.
func voleSIDForPair(sigID string, aliceID, bobID int) string {
	return fmt.Sprintf("%s:vole:%d->%d", sigID, aliceID, bobID)
}

// Round1State holds Pi's private state after signing round 1.
type Round1State struct {
	// SigID uniquely identifies this signing session.
	SigID string
	// Signers are the party IDs participating in this signing session.
	Signers []int
	// R_i is the nonce scalar sampled by Pi.
	R_i btcec.ModNScalar
	// Phi_i is the inversion mask scalar sampled by Pi.
	Phi_i btcec.ModNScalar
	// R_iPoint is R_i*G (33-byte compressed).
	R_iPoint []byte
	// Com[j] is the FCom commitment Pi sends to Pj, over R_iPoint || Psi[j]. It is
	// keyed by counterparty because psi is pairwise; see signRound1 for why psi is
	// inside the commitment at all.
	Com map[int][32]byte
	// Salt is the FCom salt, shared by every entry of Com.
	Salt [SaltLen]byte
	// Psi[j] is psi_{i,j} = phi_i - chi_{j->i} mod q, the value round 2 sends to
	// Pj. It is fixed here in round 1 — both inputs are round-1 quantities — which
	// is what makes it committable before it is ever sent.
	Psi map[int][32]byte
	// ZetaI is Pi's FZero zero-sharing value for this session.
	ZetaI btcec.ModNScalar
	// VoleBobForRound2 holds Pi's VOLE Bob state per counterparty j (Pi is Bob, j is Alice).
	// Used in round 3 to run VOLEBobReceive against j's VOLE multiply message.
	VoleBobForRound2 map[int]*VOLEBobState
	// round2Done marks the state spent, exactly as round3Done does for Round2State.
	// Unexported so no caller can clear it, and carried through the JSON encoding
	// so a state that is persisted and restored stays spent.
	round2Done atomic.Bool
}

// Round1Msg is Pi's round 1 broadcast/send to each counterparty.
type Round1Msg struct {
	// Commitment is FCom commitment to R_i*G; sent to all counterparties.
	Commitment [32]byte
	// OTECorrections are Pi's IKNP correction vectors for THIS session, computed as
	// the OTE receiver (VOLE Bob) in the j→i direction. Pj feeds them to
	// OTExtSenderExpand to derive its matching single-use VOLE Alice state.
	//
	// These are per-recipient, not broadcast: each counterparty gets corrections
	// derived from an independently sampled beta.
	OTECorrections [][Xi / 8]byte
	// OTECheckT and OTECheckX are the OT-extension consistency proof for the
	// corrections above: sum_j chi_j*t^j and sum_j chi_j*beta_j over GF(2^128).
	// They travel with the corrections because they are what makes them usable —
	// the recipient refuses corrections it cannot check, so this is not an
	// optional annex to the message.
	OTECheckT [16]byte
	OTECheckX [16]byte
}

// checkBlacklist returns a BlacklistedPartyError if any of the given party IDs
// appear in setup.Blacklist.
func checkBlacklist(setup *SignerSetup, partyIDs []int, phase string) error {
	var bad []int
	for _, id := range partyIDs {
		if setup.Blacklist[id] {
			bad = append(bad, id)
		}
	}
	if len(bad) > 0 {
		return &BlacklistedPartyError{PartyIDs: bad, Phase: phase}
	}
	return nil
}

// SignRound1 executes round 1 of the threshold signing protocol (paper §3.6, step 1).
// Pi samples r_i, phi_i, computes R_i = r_i*G and commits to it.
// Pi also computes its FZero zero-sharing value zeta_i.
//
// Pi also derives a SINGLE-USE VOLE Bob correlation per counterparty from the
// reusable base OT, and publishes the resulting OTE corrections in its round 1
// message. The correlation is never carried over from a previous session; see
// BaseOTMaterial for what goes wrong when it is.
func SignRound1(setup *SignerSetup, sigID string, signers []int) (state *Round1State, msgs map[int]*Round1Msg, err error) {
	secretdo.Do(func() {
		state, msgs, err = signRound1(setup, sigID, signers)
	})
	return
}

func signRound1(setup *SignerSetup, sigID string, signers []int) (*Round1State, map[int]*Round1Msg, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if err := validatePartyIDs(signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if err := checkBlacklist(setup, signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if len(signers) < setup.Threshold {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), setup.Threshold)}
	}
	myIDFound := false
	for _, id := range signers {
		if id == setup.MyID {
			myIDFound = true
			break
		}
	}
	if !myIDFound {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: "myID not in signers list"}
	}
	// Increment monotonic sign counter (atomic, safe under RLock).
	atomic.AddUint64(&setup.SignCounter, 1)

	// Sample nonce and inversion mask.
	r_i, err := sampleScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: sample r_i: %w", err)
	}
	phi_i, err := sampleScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: sample phi_i: %w", err)
	}

	// R_i = r_i * G.
	R_iPoint, err := scalarMulGCompressed(&r_i)
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: R_i: %w", err)
	}

	// One FCom salt for every per-counterparty commitment below. The commitments
	// differ (each covers that pair's psi) but round 2 carries a single salt, and
	// hiding comes from the salt's entropy rather than from a fresh salt per
	// message.
	var salt [SaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: salt: %w", err)
	}

	// FZero sample: restrict seeds to this signing session's counterparties.
	signerSeeds := map[int][16]byte{}
	for _, j := range signers {
		if j == setup.MyID {
			continue
		}
		if seed, ok := setup.FZeroSeeds[j]; ok {
			signerSeeds[j] = seed
		}
	}
	zetaI := FZeroSample(signerSeeds, setup.MyID, []byte(sigID))

	// Derive a SINGLE-USE VOLE Bob correlation per counterparty from the reusable
	// base OT, and ship the resulting OTE corrections in this round's message so the
	// counterparty can derive its matching Alice state in round 2. Reusing one
	// correlation across sessions is a key-recovery break — see BaseOTMaterial.
	//
	// This rides on round 1, which already sends a message to every counterparty, so
	// per-session freshness costs no extra round trip.
	bobStates := make(map[int]*VOLEBobState)
	psis := make(map[int][32]byte)
	coms := make(map[int][32]byte)
	outMsgs := make(map[int]*Round1Msg)
	for _, j := range signers {
		if j == setup.MyID {
			continue
		}
		material := setup.BaseOT[j]
		if material == nil {
			return nil, nil, &CorruptStateError{
				Phase:  "SignRound1",
				Detail: fmt.Sprintf("missing base OT material for party %d", j),
			}
		}
		bob, corrections, oteProof, err := freshBobForSession(voleSIDForPair(sigID, j, setup.MyID), material)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound1: fresh VOLE Bob for %d: %w", j, err)
		}
		bobStates[j] = bob

		// psi_{i,j} = phi_i - chi_{j->i} mod q is already determined: phi_i was
		// sampled above and chi comes out of Pi's own Bob state. Commit to it here,
		// alongside R_i, so that the value round 2 puts on the wire is BOUND before
		// anything from another party has been seen.
		//
		// Without that binding psi is just attacker-chosen bytes by the time round 3
		// folds it into eff_phi, and round 3 becomes an oracle: run it twice with
		// psi and psi', and (u_i - u_i')/(psi - psi') = r_i while
		// (w_i - w_i')/(psi - psi') = rx*sk_i. That recovers the party's
		// rerandomized share, and summed over the signers, the group private key.
		// A relay that holds no share at all can do it.
		var negChi, psi btcec.ModNScalar
		negChi.NegateVal(&bob.Chi)
		psi.Add2(&phi_i, &negChi)
		psiArr := psi.Bytes()
		psis[j] = psiArr

		com := commitWithSalt(commitMsgForPeer(R_iPoint, psiArr[:]), salt)
		coms[j] = com
		outMsgs[j] = &Round1Msg{
			Commitment:     com,
			OTECorrections: corrections,
			OTECheckT:      oteProof.TTilde,
			OTECheckX:      oteProof.XTilde,
		}
	}

	state := &Round1State{
		SigID:            sigID,
		Signers:          signers,
		R_i:              r_i,
		Phi_i:            phi_i,
		R_iPoint:         R_iPoint,
		Com:              coms,
		Salt:             salt,
		Psi:              psis,
		ZetaI:            zetaI,
		VoleBobForRound2: bobStates,
	}
	return state, outMsgs, nil
}

// Round-1 commitment message widths. They are enforced before Open because a
// hash over a concatenation only binds the pair if the split is unambiguous:
// unchecked, a peer could move bytes across the boundary and open the same
// commitment to a different (R_j, psi) pair, which is the whole point of the
// commitment.
const (
	compressedPointLen = 33
	psiLen             = 32
)

// commitMsgForPeer is the byte string Pi commits to in round 1 for one
// counterparty: its nonce point followed by that pair's psi.
func commitMsgForPeer(rPoint, psi []byte) []byte {
	msg := make([]byte, 0, len(rPoint)+len(psi))
	msg = append(msg, rPoint...)
	msg = append(msg, psi...)
	return msg
}

// Round2State holds Pi's private state after signing round 2.
//
// It is SINGLE-USE: exactly one SignRound3 may consume it. See signRound3 for
// what a second one hands the caller. A Round2State must not be copied after
// first use.
type Round2State struct {
	*Round1State
	// round3Done marks the state spent. Unexported so no caller can clear it, but
	// carried through the JSON encoding so a state that is persisted and restored
	// stays spent — a rollback must not resurrect a used one.
	round3Done atomic.Bool
	// SK_i is Pi's rerandomized Shamir share: share*lagrange(signers,myID,0) + zeta_i mod q.
	SK_i btcec.ModNScalar
	// C_u[j] is Pi's VOLE Alice output share for the nonce correlation with Pj.
	C_u map[int]btcec.ModNScalar
	// C_v[j] is Pi's VOLE Alice output share for the key correlation with Pj.
	C_v map[int]btcec.ModNScalar
	// Round1Commits[j] stores j's round 1 commitment for verification in round 3.
	Round1Commits map[int][32]byte
}

// Round2Msg is Pi's message to each counterparty Pj in round 2.
type Round2Msg struct {
	// Decommitment is R_i (33-byte compressed point), revealing the committed nonce.
	Decommitment []byte
	// Salt is the FCom salt for the round 1 commitment.
	Salt [SaltLen]byte
	// VoleMsg is Pi's VOLE multiply message (Pi as Alice, Pj as Bob).
	VoleMsg *VOLEMultiplyMsg
	// GammaU = c^u_{i,j}*G (compressed 33 bytes); used for check 1 in round 3.
	GammaU []byte
	// GammaV = c^v_{i,j}*G (compressed 33 bytes); used for check 2 in round 3.
	GammaV []byte
	// Psi = phi_i - chi_{j->i} mod q (32 bytes big-endian); used for inversion.
	// chi_{j->i} is the VOLE Bob chi where Pi is Bob and Pj is Alice.
	//
	// It is covered by the round 1 commitment together with Decommitment, so the
	// recipient verifies it rather than trusting it. It reaches round 3 through
	// whatever relays the ceremony, and round 3 folds it straight into eff_phi.
	Psi []byte
	// PKi = sk_i*G (compressed 33 bytes); for public key consistency check.
	PKi []byte
}

// SignRound2 executes round 2 of the threshold signing protocol (paper §3.6, step 2).
// Pi decommits R_i, runs VOLE multiply with each counterparty (Pi as Alice),
// and sends gamma, psi, and pki for round 3 verification.
func SignRound2(setup *SignerSetup, r1state *Round1State, allRound1 map[int]*Round1Msg) (r2state *Round2State, msgs map[int]*Round2Msg, err error) {
	secretdo.Do(func() {
		r2state, msgs, err = signRound2(setup, r1state, allRound1)
	})
	return
}

func signRound2(setup *SignerSetup, state *Round1State, allRound1 map[int]*Round1Msg) (*Round2State, map[int]*Round2Msg, error) {
	// A Round1State is single-use, for the same reason a Round2State is, and the
	// consequence of missing it here is worse.
	//
	// Round 2 runs the OTE sender expansion over corrections the COUNTERPARTY
	// supplies, against this party's long-lived base-OT choice vector sigma. Alice's
	// pad in column j changes under a flipped correction bit exactly when
	// sigma[j] = 1, and aTilde carries the difference. Run round 2 twice on one
	// Round1State — same r_i, same sk_i, same sigma — and comparing the two aTilde
	// matrices reads sigma off directly: 128 bits from two calls, no error.
	//
	// sigma is not session material. It lives in BaseOTMaterial and is reused with
	// that peer forever, so this is not a leak within one signature but the
	// permanent loss of the pairwise OT setup. Marked spent on ENTRY, before any
	// check that could fail, so a rejected attempt buys no retry.
	if !state.round2Done.CompareAndSwap(false, true) {
		return nil, nil, &InvalidInputError{
			Phase:  "SignRound2",
			Detail: fmt.Sprintf("round 2 already ran for session %q: a Round1State is single-use", state.SigID),
		}
	}

	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if err := checkBlacklist(setup, state.Signers, "SignRound2"); err != nil {
		return nil, nil, err
	}

	// Rerandomize share: sk_i = share * lagrange(signers, myID, 0) + zeta_i mod q.
	lc := lagrangeCoeff(setup.MyID, state.Signers)
	defer lc.Zero()
	var sk_i btcec.ModNScalar
	sk_i.Mul2(&setup.Share, &lc)
	sk_i.Add(&state.ZetaI)

	// sk_i * G for public key consistency check.
	pkiBytes, err := scalarMulGCompressed(&sk_i)
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound2: compute PKi: %w", err)
	}

	c_u := make(map[int]btcec.ModNScalar)
	c_v := make(map[int]btcec.ModNScalar)
	outMsgs := make(map[int]*Round2Msg)
	round1Commits := make(map[int][32]byte)

	for _, j := range state.Signers {
		if j == setup.MyID {
			continue
		}

		// Record j's round 1 commitment for later verification in round 3.
		msg1 := allRound1[j]
		if msg1 == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing round 1 message from party %d", j)}
		}
		round1Commits[j] = msg1.Commitment

		// Pi is Alice in the i→j VOLE direction. The correlation is derived fresh for
		// this session from j's round-1 corrections; there is deliberately no stored
		// Alice state to fall back on, because reusing one would be a key-recovery
		// break (see BaseOTMaterial). A missing or malformed correction vector must
		// therefore abort, never degrade.
		material := setup.BaseOT[j]
		if material == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing base OT material for party %d", j)}
		}
		if len(msg1.OTECorrections) != LambdaC {
			return nil, nil, &InvalidInputError{
				Phase:  "SignRound2",
				Detail: fmt.Sprintf("party %d sent %d OTE correction vectors, want %d", j, len(msg1.OTECorrections), LambdaC),
			}
		}
		aliceState, err := freshAliceForSession(voleSIDForPair(state.SigID, setup.MyID, j), material,
			msg1.OTECorrections, oteConsistencyProof{TTilde: msg1.OTECheckT, XTilde: msg1.OTECheckX})
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: fresh VOLE Alice for %d: %w", j, err)
		}
		sid := voleSIDForPair(state.SigID, setup.MyID, j)
		cu, cv, voleMsg, err := VOLEAliceMultiply(aliceState, sid, &state.R_i, &sk_i)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: VOLE multiply with %d: %w", j, err)
		}
		c_u[j] = cu
		c_v[j] = cv

		// GammaU = c^u * G, GammaV = c^v * G.
		gammaU, err := scalarMulGCompressed(&cu)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: GammaU for %d: %w", j, err)
		}
		gammaV, err := scalarMulGCompressed(&cv)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: GammaV for %d: %w", j, err)
		}

		// psi_{i,j} was fixed and committed to in round 1. Sending the stored value
		// rather than recomputing it is what makes "what was committed" and "what
		// was sent" the same object by construction.
		psiArr, ok := state.Psi[j]
		if !ok {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing psi for party %d", j)}
		}
		if state.VoleBobForRound2[j] == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing VOLE Bob state for party %d", j)}
		}

		outMsgs[j] = &Round2Msg{
			Decommitment: state.R_iPoint,
			Salt:         state.Salt,
			VoleMsg:      voleMsg,
			GammaU:       gammaU,
			GammaV:       gammaV,
			Psi:          psiArr[:],
			PKi:          pkiBytes,
		}
	}

	state2 := &Round2State{
		Round1State:   state,
		SK_i:          sk_i,
		C_u:           c_u,
		C_v:           c_v,
		Round1Commits: round1Commits,
	}
	return state2, outMsgs, nil
}

// Round3Msg contains Pi's signature fragment, broadcast to all parties for combining.
type Round3Msg struct {
	// W_i is Pi's w contribution: SHA256(msg)*phi_i + rx*v_i mod q.
	W_i []byte // 32-byte big-endian
	// U_i is Pi's u contribution: r_i*eff_phi_i + sum_j (c^u + d^u) mod q.
	U_i []byte // 32-byte big-endian
}

// SignRound3 executes round 3 of the threshold signing protocol (paper §3.6, step 3).
// Pi receives all round 2 messages, verifies checks 1-3, and outputs signature fragments.
//
// Verification checks per counterparty j:
//  1. FCom decommitment: Open(R_j, com_j from round1, salt from round2).
//  2. VOLE Bob receive: d^u_{i,j}, d^v_{i,j} = VOLEBobReceive(state, voleMsg from j).
//  3. Check 1: chi_{j->i} * R_j - Gamma^u_{j,i} == d^u_{i,j} * G
//  4. Check 2: chi_{j->i} * pk_j - Gamma^v_{j,i} == d^v_{i,j} * G
//  5. Check 3: sum_k pk_k == master_pk
//
// If any check fails for party j: blacklist j and return error.
func SignRound3(setup *SignerSetup, state2 *Round2State, message []byte, allRound2 map[int]*Round2Msg) (msgs map[int]*Round3Msg, err error) {
	h := sha256.Sum256(message)
	return SignRound3Prehashed(setup, state2, h, allRound2)
}

// SignRound3Prehashed is like SignRound3 but accepts a pre-computed 32-byte message hash.
// Use this when the caller has already hashed the message (e.g. Ethereum's Keccak-256).
func SignRound3Prehashed(setup *SignerSetup, state2 *Round2State, msgHash [32]byte, allRound2 map[int]*Round2Msg) (msgs map[int]*Round3Msg, err error) {
	secretdo.Do(func() {
		msgs, err = signRound3(setup, state2, msgHash, allRound2)
	})
	return
}

func signRound3(setup *SignerSetup, state2 *Round2State, msgHash [32]byte, allRound2 map[int]*Round2Msg) (map[int]*Round3Msg, error) {
	// Round 3 is single-shot per Round2State. A second run is a key-recovery
	// break, not a protocol nuisance: eff_phi folds in the counterparties' psi
	// values, so a caller that runs round 3 twice with psi and then psi' gets
	// (u_i - u_i')/(psi - psi') = r_i and (w_i - w_i')/(psi - psi') = rx*sk_i.
	// That is this party's nonce and its rerandomized share; summed over the
	// signers it is the group private key.
	//
	// Marked spent on ENTRY, before any check that could fail, so a rejected
	// attempt buys no retry. The fragments are what must never exist twice for one
	// nonce, and a caller that wants another signature must run a new session.
	if !state2.round3Done.CompareAndSwap(false, true) {
		return nil, &InvalidInputError{
			Phase:  "SignRound3",
			Detail: fmt.Sprintf("round 3 already ran for session %q: a Round2State is single-use", state2.SigID),
		}
	}

	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := checkBlacklist(setup, state2.Signers, "SignRound3"); err != nil {
		return nil, err
	}

	// Collect R_j and pk_j from all parties.
	RPoints := make(map[int]*btcec.JacobianPoint)
	pkjPoints := make(map[int]*btcec.JacobianPoint)
	duMap := make(map[int]btcec.ModNScalar)
	dvMap := make(map[int]btcec.ModNScalar)

	// My own contributions.
	myRPt, err := compressedToPoint(state2.R_iPoint)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse my R_i: %w", err)
	}
	RPoints[setup.MyID] = myRPt

	myPKiBytes, err := scalarMulGCompressed(&state2.SK_i)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: my PKi: %w", err)
	}
	myPKiPt, err := compressedToPoint(myPKiBytes)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse my PKi: %w", err)
	}
	pkjPoints[setup.MyID] = myPKiPt

	var badParties []int

	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		r2j := allRound2[j]
		if r2j == nil {
			badParties = append(badParties, j)
			continue
		}

		// Step 1: Verify the FCom decommitment of R_j AND of psi_{j,i}, which round 1
		// committed to as one message. psi is otherwise unauthenticated bytes that a
		// relay can rewrite on their way here, and eff_phi below adds them in
		// unconditionally; opening them against the round 1 commitment is what turns
		// a rewrite into an abort instead of a silently different signature.
		//
		// The widths are checked first so the concatenation cannot be re-split.
		if len(r2j.Decommitment) != compressedPointLen || len(r2j.Psi) != psiLen {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		comJ := state2.Round1Commits[j]
		if err := Open(commitMsgForPeer(r2j.Decommitment, r2j.Psi), comJ, r2j.Salt); err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}

		Rj, err := compressedToPoint(r2j.Decommitment)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		RPoints[j] = Rj

		pkj, err := compressedToPoint(r2j.PKi)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		pkjPoints[j] = pkj

		// A relay can strip vole_msg from an otherwise genuine round 2 message and
		// the round 1 commitment will not notice: it covers R_j and psi, not this.
		// A missing multiply message is a party failing to play its part, which is
		// what the blacklist is for — it must not be a nil dereference that takes
		// the node down instead.
		if r2j.VoleMsg == nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}

		// Step 2: VOLE Bob receive. Pi is Bob in the j→i VOLE direction.
		bobState := state2.VoleBobForRound2[j]
		if bobState == nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		sidJI := voleSIDForPair(state2.SigID, j, setup.MyID)
		du, dv, err := VOLEBobReceive(bobState, sidJI, r2j.VoleMsg)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		duMap[j] = du
		dvMap[j] = dv

		// chi_{j->i} = Bob state Chi (Pi is Bob, j is Alice).
		chiJI := bobState.Chi

		// Step 3: Check 1: chi_{j->i} * R_j - Gamma^u_{j,i} == d^u_{i,j} * G
		gammaUJI, err := compressedToPoint(r2j.GammaU)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		chiRj := scalarMul(&chiJI, Rj)
		negGammaU := pointNeg(gammaUJI)
		lhs1 := pointAdd(chiRj, negGammaU)
		lhs1.ToAffine()

		var rhs1 btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&du, &rhs1)
		rhs1.ToAffine()

		if !lhs1.X.Equals(&rhs1.X) || !lhs1.Y.Equals(&rhs1.Y) {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}

		// Step 4: Check 2: chi_{j->i} * pk_j - Gamma^v_{j,i} == d^v_{i,j} * G
		gammaVJI, err := compressedToPoint(r2j.GammaV)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		chiPKj := scalarMul(&chiJI, pkj)
		negGammaV := pointNeg(gammaVJI)
		lhs2 := pointAdd(chiPKj, negGammaV)
		lhs2.ToAffine()

		var rhs2 btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&dv, &rhs2)
		rhs2.ToAffine()

		if !lhs2.X.Equals(&rhs2.X) || !lhs2.Y.Equals(&rhs2.Y) {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
	}

	if len(badParties) > 0 {
		return nil, &CheatingPartyError{PartyIDs: badParties, Phase: "SignRound3", Detail: "verification checks failed"}
	}

	// Step 5: Check 3: sum_k pk_k == master_pk.
	var sumPK btcec.JacobianPoint
	for _, j := range state2.Signers {
		btcec.AddNonConst(&sumPK, pkjPoints[j], &sumPK)
	}
	sumPK.ToAffine()

	masterPK, err := compressedToPoint(setup.PubKey)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse master pubkey: %w", err)
	}
	masterPK.ToAffine()
	if !sumPK.X.Equals(&masterPK.X) || !sumPK.Y.Equals(&masterPK.Y) {
		return nil, &CorruptStateError{Phase: "SignRound3", Detail: "public key consistency check failed: sum(pk_k) != master_pk"}
	}

	// Compute R = sum of all R_j.
	var R btcec.JacobianPoint
	for _, j := range state2.Signers {
		btcec.AddNonConst(&R, RPoints[j], &R)
	}
	R.ToAffine()

	// rx = x-coordinate of R mod q.
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)

	// eff_phi_i = phi_i + sum_{j∈signers, j≠i} psi_{j,i}
	//
	// Every psi added here has been opened against j's round 1 commitment above, so
	// this is j's committed value and not whatever arrived on the wire.
	var effPhi btcec.ModNScalar
	effPhi.Set(&state2.Phi_i)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		r2j := allRound2[j]
		var psiJI btcec.ModNScalar
		if psiJI.SetByteSlice(r2j.Psi) {
			// Honest psi is q-reduced by construction, so an overflowing one means the
			// committer chose a non-canonical encoding. Reducing it silently would let
			// two encodings satisfy one commitment.
			return nil, &CheatingPartyError{PartyIDs: []int{j}, Phase: "SignRound3", Detail: "psi is not a canonical scalar"}
		}
		effPhi.Add(&psiJI)
	}

	// u_i = r_i * eff_phi_i + sum_j (c^u_{i,j} + d^u_{i,j}) mod q.
	var u_i btcec.ModNScalar
	u_i.Mul2(&state2.R_i, &effPhi)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		cu := state2.C_u[j]
		u_i.Add(&cu)
		du := duMap[j]
		u_i.Add(&du)
	}

	// v_i = sk_i * eff_phi_i + sum_j (c^v_{i,j} + d^v_{i,j}) mod q.
	var v_i btcec.ModNScalar
	v_i.Mul2(&state2.SK_i, &effPhi)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		cv := state2.C_v[j]
		v_i.Add(&cv)
		dv := dvMap[j]
		v_i.Add(&dv)
	}

	// w_i = H(message)*phi_i + rx*v_i mod q.
	var hashScalar btcec.ModNScalar
	hashScalar.SetByteSlice(msgHash[:])

	var w_i btcec.ModNScalar
	w_i.Mul2(&hashScalar, &state2.Phi_i)
	var rxV btcec.ModNScalar
	rxV.Mul2(&rx, &v_i)
	w_i.Add(&rxV)

	defer effPhi.Zero()
	defer u_i.Zero()
	defer v_i.Zero()
	defer w_i.Zero()

	// Build round 3 messages (same fragment broadcast to all).
	wArr := w_i.Bytes()
	uArr := u_i.Bytes()

	outMsgs := make(map[int]*Round3Msg)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		outMsgs[j] = &Round3Msg{W_i: wArr[:], U_i: uArr[:]}
	}

	// Also return rx through the "self" entry (key = myID).
	outMsgs[setup.MyID] = &Round3Msg{W_i: wArr[:], U_i: uArr[:]}

	return outMsgs, nil
}

// ComputeRx computes rx = (Σ R_j).x mod q from each signer's decommitted nonce point.
//
// In a distributed setting, each node knows its own R_iPoint (from Round2State)
// and receives the other signers' R_j values as Round2Msg.Decommitment.  This
// function accepts both: pass a map from party ID to the 33-byte compressed
// nonce point for every signer (including yourself).
//
// Example:
//
//	points := map[int][]byte{myID: myR2State.R_iPoint}
//	for j, msg := range inboundRound2 {
//	    points[j] = msg.Decommitment
//	}
//	rx, err := dkls23.ComputeRx(points)
func ComputeRx(noncePoints map[int][]byte) (btcec.ModNScalar, error) {
	if len(noncePoints) == 0 {
		return btcec.ModNScalar{}, &InvalidInputError{Phase: "ComputeRx", Detail: "no nonce points provided"}
	}
	var R btcec.JacobianPoint
	for id, pt := range noncePoints {
		Rj, err := compressedToPoint(pt)
		if err != nil {
			return btcec.ModNScalar{}, &InvalidInputError{
				Phase:  "ComputeRx",
				Detail: fmt.Sprintf("invalid nonce point for party %d: %v", id, err),
			}
		}
		btcec.AddNonConst(&R, Rj, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx, nil
}

// SignCombine collects round 3 fragments and outputs the final ECDSA (r, s) signature.
// s = sum(w_j) / sum(u_j) mod q; r = rx.
// Verifies the signature against the master public key before returning.
func SignCombine(setup *SignerSetup, rx *btcec.ModNScalar, myW, myU *btcec.ModNScalar, allRound3 map[int]*Round3Msg, message []byte) (r, s []byte, err error) {
	h := sha256.Sum256(message)
	return SignCombinePrehashed(setup, rx, myW, myU, allRound3, h)
}

// SignCombinePrehashed is like SignCombine but accepts a pre-computed 32-byte message hash.
func SignCombinePrehashed(setup *SignerSetup, rx *btcec.ModNScalar, myW, myU *btcec.ModNScalar, allRound3 map[int]*Round3Msg, msgHash [32]byte) (r, s []byte, err error) {
	secretdo.Do(func() {
		r, s, err = signCombine(setup, rx, myW, myU, allRound3, msgHash)
	})
	return
}

func signCombine(setup *SignerSetup, rx *btcec.ModNScalar, myW, myU *btcec.ModNScalar, allRound3 map[int]*Round3Msg, msgHash [32]byte) (r, s []byte, err error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()

	var sumW, sumU btcec.ModNScalar
	sumW.Set(myW)
	sumU.Set(myU)

	for _, r3j := range allRound3 {
		var wj, uj btcec.ModNScalar
		wj.SetByteSlice(r3j.W_i)
		uj.SetByteSlice(r3j.U_i)
		sumW.Add(&wj)
		sumU.Add(&uj)
	}

	// s = sumW * sumU^{-1} mod q.
	if sumU.IsZero() {
		return nil, nil, errors.New("dkls23 SignCombine: sumU is not invertible (nonce sum is zero)")
	}
	sumUInv := scalarInverse(&sumU)
	var sVal btcec.ModNScalar
	sVal.Mul2(&sumW, &sumUInv)

	// Low-S normalization (BIP340 / standard ECDSA): s > q/2 → s = q - s.
	if sVal.IsOverHalfOrder() {
		sVal.Negate()
	}

	rArr := rx.Bytes()
	sArr := sVal.Bytes()
	rBytes := rArr[:]
	sBytes := sArr[:]

	// Verify the signature against the master public key.
	pubKey, err2 := btcec.ParsePubKey(setup.PubKey)
	if err2 != nil {
		return nil, nil, fmt.Errorf("dkls23 SignCombine: parse pubkey: %w", err2)
	}
	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(rBytes)
	sScalar.SetByteSlice(sBytes)
	ecdsaSig := ecdsa.NewSignature(&rScalar, &sScalar)
	if !ecdsaSig.Verify(msgHash[:], pubKey) {
		return nil, nil, errors.New("dkls23 SignCombine: final signature verification failed")
	}

	return rBytes, sBytes, nil
}
