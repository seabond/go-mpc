package frost

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"filippo.io/edwards25519"
	"github.com/seabond/go-mpc/internal/secretdo"
)

// --- FROST 2-round threshold signing protocol (RFC 9591 Section 5.2) ---
//
// The signing protocol uses Schnorr's linearity: each signer contributes a
// partial signature z_i that is summed to produce the final (R, z) signature.
// No OT or VOLE is needed. The protocol detects misbehaving signers via
// individual share verification (identifiable abort).

// SignerState holds a signer's persistent state for signing sessions.
// It wraps a KeyShare and tracks blacklisted parties.
//
// SignerState is safe for concurrent use: read-only operations (signing round 1/2)
// acquire a read lock, while mutating operations (blacklisting) acquire a write lock.
type SignerState struct {
	mu sync.RWMutex
	// KeyShare is this signer's key material from DKG.
	KeyShare *KeyShare
	// Blacklist records parties detected cheating.
	Blacklist map[int]bool
	// Epoch is the proactive refresh epoch counter, starting at 0 and
	// incremented on each RefreshFinalize.
	Epoch int
}

// NewSignerState creates a SignerState from a KeyShare.
func NewSignerState(ks *KeyShare) *SignerState {
	return &SignerState{
		KeyShare:  ks,
		Blacklist: make(map[int]bool),
	}
}

// NonceCommitment is a signer's round 1 output: hiding and binding nonce commitments.
// (RFC 9591 Section 5.2, Round One)
type NonceCommitment struct {
	// HidingNonceCommitment is D_i = hiding_nonce_i * B (32 bytes).
	HidingNonceCommitment []byte
	// BindingNonceCommitment is E_i = binding_nonce_i * B (32 bytes).
	BindingNonceCommitment []byte
}

// Round1State holds Pi's private nonce state after round 1.
// This state is consumed exactly once in round 2; nonces are zeroized after use.
type Round1State struct {
	// Signers are the party IDs participating in this signing session.
	Signers []int
	// HidingNonce is d_i (secret, zeroized after round 2).
	HidingNonce *edwards25519.Scalar
	// BindingNonce is e_i (secret, zeroized after round 2).
	BindingNonce *edwards25519.Scalar
	// Commitment is this signer's (D_i, E_i) pair.
	Commitment *NonceCommitment
	// consumed tracks whether this state has been used.
	consumed bool
}

// Round2Input bundles the data each signer needs for round 2.
type Round2Input struct {
	// Message is the message to sign.
	Message []byte
	// AllCommitments maps signer ID to their round 1 nonce commitments.
	AllCommitments map[int]*NonceCommitment
}

// SignatureShare is a signer's round 2 output: the partial signature scalar z_i.
// (RFC 9591 Section 5.2, Round Two)
type SignatureShare struct {
	// SignerID identifies which signer produced this share.
	SignerID int
	// Zi is the signature share scalar (32 bytes little-endian).
	Zi []byte
}

// Signature is a complete Ed25519 signature (R, z) in 64 bytes.
type Signature struct {
	// R is the group commitment (32-byte compressed Edwards point).
	R []byte
	// Z is the aggregate signature scalar (32-byte little-endian).
	Z []byte
}

// Bytes returns the 64-byte encoding R || z.
func (sig *Signature) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], sig.R)
	copy(out[32:], sig.Z)
	return out
}

// checkBlacklist returns a BlacklistedPartyError if any of the given party IDs
// appear in the signer's blacklist.
func checkBlacklist(signer *SignerState, partyIDs []int, phase string) error {
	var bad []int
	for _, id := range partyIDs {
		if signer.Blacklist[id] {
			bad = append(bad, id)
		}
	}
	if len(bad) > 0 {
		return &BlacklistedPartyError{PartyIDs: bad, Phase: phase}
	}
	return nil
}

// SignRound1 generates a (hiding_nonce, binding_nonce) pair and their commitments.
// The nonces are generated from a CSPRNG mixed with the secret key for hedging
// against bad RNG (RFC 9591 Section 5.2, nonce_generate).
//
// Nonce reuse across signing sessions is fatal: it enables full key recovery.
func SignRound1(signer *SignerState, signers []int) (state *Round1State, com *NonceCommitment, err error) {
	secretdo.Do(func() {
		state, com, err = signRound1(signer, signers)
	})
	return
}

func signRound1(signer *SignerState, signers []int) (*Round1State, *NonceCommitment, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	if err := validatePartyIDs(signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if err := checkBlacklist(signer, signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if len(signers) < signer.KeyShare.Threshold {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), signer.KeyShare.Threshold)}
	}
	myIDFound := false
	for _, id := range signers {
		if id == signer.KeyShare.ID {
			myIDFound = true
			break
		}
	}
	if !myIDFound {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: "myID not in signers list"}
	}

	// nonce_generate per RFC 9591: H3(random_bytes(32) || secret_key)
	hidingNonce, err := nonceGenerate(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, nil, fmt.Errorf("frost SignRound1: generate hiding nonce: %w", err)
	}
	bindingNonce, err := nonceGenerate(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, nil, fmt.Errorf("frost SignRound1: generate binding nonce: %w", err)
	}

	// D_i = d_i * B, E_i = e_i * B
	hidingCommitment := edwards25519.NewGeneratorPoint().ScalarBaseMult(hidingNonce).Bytes()
	bindingCommitment := edwards25519.NewGeneratorPoint().ScalarBaseMult(bindingNonce).Bytes()

	commitment := &NonceCommitment{
		HidingNonceCommitment:  hidingCommitment,
		BindingNonceCommitment: bindingCommitment,
	}

	state := &Round1State{
		Signers:      signers,
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitment:   commitment,
	}

	return state, commitment, nil
}

// nonceGenerate implements RFC 9591 nonce_generate:
//
//	H3(random_bytes(32) || secret)
//
// This hedges against bad RNG by mixing in the secret key.
func nonceGenerate(secret []byte) (*edwards25519.Scalar, error) {
	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return nil, err
	}
	input := make([]byte, 32+len(secret))
	copy(input[:32], randomBytes[:])
	copy(input[32:], secret)
	nonce := H3(input)
	// Zeroize: input contains randomBytes || secret (plaintext key material).
	for i := range randomBytes {
		randomBytes[i] = 0
	}
	for i := range input {
		input[i] = 0
	}
	return nonce, nil
}

// SignRound2 computes signer i's signature share.
//
// Steps per RFC 9591 Section 5.2:
//  1. Encode commitment list, compute binding factors via H1.
//  2. Compute group commitment R = sum(D_i + rho_i * E_i).
//  3. Compute challenge c = H2(R || PK || msg).
//  4. Compute z_i = d_i + rho_i * e_i + lambda_i * s_i * c.
//  5. Zeroize d_i and e_i.
func SignRound2(signer *SignerState, r1state *Round1State, input *Round2Input) (share *SignatureShare, err error) {
	secretdo.Do(func() {
		share, err = signRound2(signer, r1state, input)
	})
	return
}

func signRound2(signer *SignerState, state *Round1State, input *Round2Input) (*SignatureShare, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	if state.consumed {
		return nil, &CorruptStateError{Phase: "SignRound2", Detail: "round 1 state already consumed (nonce reuse prevented)"}
	}

	// Verify all signers have commitments.
	for _, id := range state.Signers {
		if _, ok := input.AllCommitments[id]; !ok {
			return nil, &InvalidInputError{Phase: "SignRound2", Detail: fmt.Sprintf("missing commitment for signer %d", id)}
		}
	}

	// Sort signers for deterministic encoding.
	signersSorted := make([]int, len(state.Signers))
	copy(signersSorted, state.Signers)
	sort.Ints(signersSorted)

	// Step 1: Compute binding factors.
	bindingFactors := computeBindingFactors(signer.KeyShare.PublicKey, input.AllCommitments, input.Message, signersSorted)

	// Step 2: Compute group commitment R.
	groupCommitment, err := computeGroupCommitment(input.AllCommitments, bindingFactors, signersSorted)
	if err != nil {
		return nil, &InvalidInputError{Phase: "SignRound2", Detail: err.Error()}
	}

	// Step 3: Compute challenge c = H2(R || PK || msg).
	challenge := computeChallenge(groupCommitment, signer.KeyShare.PublicKey, input.Message)

	// Step 4: Compute z_i = d_i + rho_i * e_i + lambda_i * s_i * c.
	myID := signer.KeyShare.ID
	rhoI := bindingFactors[myID]
	lambdaI := lagrangeCoeff(myID, signersSorted)

	sk, err := edwards25519.NewScalar().SetCanonicalBytes(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, &CorruptStateError{Phase: "SignRound2", Detail: "invalid secret share"}
	}

	// z_i = d_i + rho_i * e_i + lambda_i * s_i * c
	rhoE := edwards25519.NewScalar().Multiply(rhoI, state.BindingNonce)
	lambdaSC := edwards25519.NewScalar().Multiply(lambdaI, sk)
	lambdaSC.Multiply(lambdaSC, challenge)

	zi := edwards25519.NewScalar()
	zi.Add(zi, state.HidingNonce)
	zi.Add(zi, rhoE)
	zi.Add(zi, lambdaSC)

	// Step 5: Zeroize nonces.
	zeroScalar := edwards25519.NewScalar()
	state.HidingNonce.Set(zeroScalar)
	state.BindingNonce.Set(zeroScalar)
	state.consumed = true

	return &SignatureShare{
		SignerID: myID,
		Zi:       zi.Bytes(),
	}, nil
}

// Aggregate collects signature shares and produces the final 64-byte Ed25519 signature.
//
// Steps per RFC 9591 Section 5.3:
//  1. Recompute group commitment R and challenge c.
//  2. Optionally verify each signature share.
//  3. z = sum(z_i).
//  4. Return (R, z) as a 64-byte signature.
//  5. Verify the final signature against the group public key.
//
// verificationShares maps signer ID to their verification share (s_i * B, 32 bytes).
// If non-nil, individual shares are verified and misbehaving signers are identified.
func Aggregate(
	allCommitments map[int]*NonceCommitment,
	allShares map[int]*SignatureShare,
	message []byte,
	groupPublicKey []byte,
	verificationShares map[int][]byte,
	signers []int,
) (sig *Signature, err error) {
	secretdo.Do(func() {
		sig, err = aggregate(allCommitments, allShares, message, groupPublicKey, verificationShares, signers)
	})
	return
}

func aggregate(
	allCommitments map[int]*NonceCommitment,
	allShares map[int]*SignatureShare,
	message []byte,
	groupPublicKey []byte,
	verificationShares map[int][]byte,
	signers []int,
) (*Signature, error) {
	// Sort signers for deterministic encoding.
	signersSorted := make([]int, len(signers))
	copy(signersSorted, signers)
	sort.Ints(signersSorted)

	// Step 1: Recompute binding factors and group commitment.
	bindingFactors := computeBindingFactors(groupPublicKey, allCommitments, message, signersSorted)
	groupCommitment, err := computeGroupCommitment(allCommitments, bindingFactors, signersSorted)
	if err != nil {
		return nil, &InvalidInputError{Phase: "Aggregate", Detail: err.Error()}
	}
	challenge := computeChallenge(groupCommitment, groupPublicKey, message)

	// Step 2: Verify individual shares if verification shares are provided.
	if verificationShares != nil {
		var badSigners []int
		for _, id := range signersSorted {
			share, ok := allShares[id]
			if !ok {
				badSigners = append(badSigners, id)
				continue
			}
			if err := verifySignatureShare(share, allCommitments[id], bindingFactors[id], challenge, id, signersSorted, verificationShares[id]); err != nil {
				badSigners = append(badSigners, id)
			}
		}
		if len(badSigners) > 0 {
			return nil, &CheatingPartyError{PartyIDs: badSigners, Phase: "Aggregate", Detail: "signature share verification failed"}
		}
	}

	// Step 3: z = sum(z_i).
	z := edwards25519.NewScalar()
	for _, id := range signersSorted {
		share := allShares[id]
		zi, err := edwards25519.NewScalar().SetCanonicalBytes(share.Zi)
		if err != nil {
			return nil, &InvalidInputError{Phase: "Aggregate", Detail: fmt.Sprintf("invalid signature share from signer %d", id)}
		}
		z.Add(z, zi)
	}

	// Step 4: Build signature.
	sig := &Signature{
		R: groupCommitment.Bytes(),
		Z: z.Bytes(),
	}

	// Step 5: Verify the final signature.
	if !Verify(groupPublicKey, message, sig) {
		return nil, &CorruptStateError{Phase: "Aggregate", Detail: "final signature verification failed"}
	}

	return sig, nil
}

// computeBindingFactors computes the binding factor rho_i for each signer.
// (RFC 9591 Section 4.3)
func computeBindingFactors(
	groupPublicKey []byte,
	allCommitments map[int]*NonceCommitment,
	msg []byte,
	signersSorted []int,
) map[int]*edwards25519.Scalar {
	// rho_input_prefix = SerializeElement(group_public_key) || H4(msg) || H5(encode_group_commitment_list)
	encodedCommitments := encodeCommitmentList(allCommitments, signersSorted)
	msgHash := H4(msg)
	comHash := H5(encodedCommitments)

	prefix := make([]byte, 0, len(groupPublicKey)+len(msgHash)+len(comHash))
	prefix = append(prefix, groupPublicKey...)
	prefix = append(prefix, msgHash...)
	prefix = append(prefix, comHash...)

	factors := make(map[int]*edwards25519.Scalar, len(signersSorted))
	for _, id := range signersSorted {
		// binding_factor = H1(rho_input_prefix || SerializeScalar(identifier))
		idBytes := serializeScalarID(id)
		input := make([]byte, len(prefix)+len(idBytes))
		copy(input, prefix)
		copy(input[len(prefix):], idBytes)
		factors[id] = H1(input)
	}
	return factors
}

// computeGroupCommitment computes R = sum(D_i + rho_i * E_i) for all signers.
func computeGroupCommitment(
	allCommitments map[int]*NonceCommitment,
	bindingFactors map[int]*edwards25519.Scalar,
	signersSorted []int,
) (*edwards25519.Point, error) {
	R := edwards25519.NewIdentityPoint()
	for _, id := range signersSorted {
		comm := allCommitments[id]
		Di, err := edwards25519.NewIdentityPoint().SetBytes(comm.HidingNonceCommitment)
		if err != nil {
			return nil, fmt.Errorf("frost: invalid hiding nonce commitment for signer %d: %w", id, err)
		}
		Ei, err := edwards25519.NewIdentityPoint().SetBytes(comm.BindingNonceCommitment)
		if err != nil {
			return nil, fmt.Errorf("frost: invalid binding nonce commitment for signer %d: %w", id, err)
		}
		rhoEi := edwards25519.NewIdentityPoint().ScalarMult(bindingFactors[id], Ei)
		contrib := edwards25519.NewIdentityPoint().Add(Di, rhoEi)
		R.Add(R, contrib)
	}
	return R, nil
}

// computeChallenge computes c = H2(R || PK || msg) per RFC 9591 / RFC 8032.
func computeChallenge(groupCommitment *edwards25519.Point, groupPublicKey []byte, msg []byte) *edwards25519.Scalar {
	rBytes := groupCommitment.Bytes()
	input := make([]byte, 0, ElementLen+ElementLen+len(msg))
	input = append(input, rBytes...)
	input = append(input, groupPublicKey...)
	input = append(input, msg...)
	return H2(input)
}

// encodeCommitmentList encodes the list of (id, D_i, E_i) in canonical order.
// Each entry: identifier (ScalarLen bytes LE) || D_i (ElementLen bytes) || E_i (ElementLen bytes).
// (RFC 9591 Section 4.3)
func encodeCommitmentList(allCommitments map[int]*NonceCommitment, signersSorted []int) []byte {
	entrySize := ScalarLen + 2*ElementLen
	buf := make([]byte, 0, len(signersSorted)*entrySize)
	for _, id := range signersSorted {
		comm := allCommitments[id]
		idBytes := serializeScalarID(id)
		buf = append(buf, idBytes...)
		buf = append(buf, comm.HidingNonceCommitment...)
		buf = append(buf, comm.BindingNonceCommitment...)
	}
	return buf
}

// serializeScalarID serializes a party identifier as a ScalarLen-byte little-endian value.
// (RFC 9591 uses Scalar serialization for identifiers.)
func serializeScalarID(id int) []byte {
	var buf [ScalarLen]byte
	binary.LittleEndian.PutUint64(buf[:8], uint64(id))
	return buf[:]
}

// verifySignatureShare verifies a single share:
//
//	z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i
//
// (RFC 9591 Section 5.4)
func verifySignatureShare(
	share *SignatureShare,
	commitment *NonceCommitment,
	bindingFactor *edwards25519.Scalar,
	challenge *edwards25519.Scalar,
	signerID int,
	allSigners []int,
	verificationShareBytes []byte,
) error {
	zi, err := edwards25519.NewScalar().SetCanonicalBytes(share.Zi)
	if err != nil {
		return fmt.Errorf("frost: invalid signature share scalar")
	}
	PKi, err := edwards25519.NewIdentityPoint().SetBytes(verificationShareBytes)
	if err != nil {
		return fmt.Errorf("frost: invalid verification share point")
	}
	Di, err := edwards25519.NewIdentityPoint().SetBytes(commitment.HidingNonceCommitment)
	if err != nil {
		return fmt.Errorf("frost: invalid hiding nonce commitment")
	}
	Ei, err := edwards25519.NewIdentityPoint().SetBytes(commitment.BindingNonceCommitment)
	if err != nil {
		return fmt.Errorf("frost: invalid binding nonce commitment")
	}

	// LHS = z_i * B
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(zi)

	// RHS = D_i + rho_i * E_i + c * lambda_i * PK_i
	lambdaI := lagrangeCoeff(signerID, allSigners)
	cLambda := edwards25519.NewScalar().Multiply(challenge, lambdaI)

	rhoEi := edwards25519.NewIdentityPoint().ScalarMult(bindingFactor, Ei)
	cLambdaPKi := edwards25519.NewIdentityPoint().ScalarMult(cLambda, PKi)

	rhs := edwards25519.NewIdentityPoint().Add(Di, rhoEi)
	rhs.Add(rhs, cLambdaPKi)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("frost: signature share verification failed for signer %d", signerID)
	}
	return nil
}
