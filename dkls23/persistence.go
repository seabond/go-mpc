package dkls23

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SetupEncryptor is the interface callers must implement to provide
// at-rest encryption for SignerSetup persistence.
//
// Implementations might use AES-GCM with a key from an HSM, an envelope
// encryption scheme, or a platform keychain.  The dkls23 package does not
// prescribe a specific cipher.
type SetupEncryptor interface {
	// Encrypt takes plaintext JSON and returns an opaque ciphertext blob.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt reverses Encrypt, returning the original plaintext JSON.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// MarshalSetup serializes a SignerSetup to JSON.
// The output contains the Shamir share in plaintext — callers should
// encrypt the result before writing to disk. Use MarshalEncrypted for
// a one-step encrypt-and-serialize flow.
//
// Safe for concurrent use: acquires a read lock on setup.mu.
func MarshalSetup(setup *SignerSetup) ([]byte, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	return json.Marshal(setup)
}

// UnmarshalSetup deserializes a SignerSetup from JSON.
// Use UnmarshalEncrypted if the data was produced by MarshalEncrypted.
func UnmarshalSetup(data []byte) (*SignerSetup, error) {
	var s SignerSetup
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalSetup: %w", err)
	}
	return &s, nil
}

// MarshalEncrypted serializes and encrypts a SignerSetup in one step.
// The returned blob is safe to write to disk or send over the network.
func MarshalEncrypted(setup *SignerSetup, enc SetupEncryptor) ([]byte, error) {
	plaintext, err := MarshalSetup(setup)
	if err != nil {
		return nil, fmt.Errorf("dkls23 MarshalEncrypted: marshal: %w", err)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("dkls23 MarshalEncrypted: encrypt: %w", err)
	}
	return ciphertext, nil
}

// UnmarshalEncrypted decrypts and deserializes a SignerSetup in one step.
func UnmarshalEncrypted(ciphertext []byte, enc SetupEncryptor) (*SignerSetup, error) {
	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalEncrypted: decrypt: %w", err)
	}
	return UnmarshalSetup(plaintext)
}

// UnmarshalLegacySetup decodes a setup written BEFORE per-session VOLE, extracting
// only the fields that survive a re-pairing: MyID, AllIDs, Share, PubKey, Threshold
// and Epoch. The stored VOLE correlations are deliberately dropped — they are the
// defect (see BaseOTMaterial) — and BaseOT is left nil, so the returned setup cannot
// sign until the caller runs a fresh pairing setup for it.
//
// This exists solely so an operator can migrate wallets already on disk. Pairing is
// key-independent, so re-pairing preserves the Shamir sharing, the group public key
// and therefore the address. Nothing else should call it.
func UnmarshalLegacySetup(data []byte) (*SignerSetup, error) {
	var j struct {
		MyID       int             `json:"my_id"`
		AllIDs     []int           `json:"all_ids"`
		Share      string          `json:"share"`
		PubKey     string          `json:"pub_key"`
		Threshold  int             `json:"threshold"`
		Epoch      int             `json:"epoch"`
		BaseOT     json.RawMessage `json:"base_ot"`
		LegacyVole json.RawMessage `json:"vole_bob"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacySetup: %w", err)
	}
	if len(j.BaseOT) > 0 {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacySetup: setup already has base OT material; it does not need repairing")
	}
	if len(j.LegacyVole) == 0 {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacySetup: setup has neither base OT nor legacy VOLE state; refusing to guess its format")
	}

	share, err := hexToScalar(j.Share)
	if err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacySetup: share: %w", err)
	}
	pub, err := hex.DecodeString(j.PubKey)
	if err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacySetup: pub_key: %w", err)
	}
	return &SignerSetup{
		MyID:       j.MyID,
		AllIDs:     j.AllIDs,
		Share:      share,
		PubKey:     pub,
		Threshold:  j.Threshold,
		Epoch:      j.Epoch,
		BaseOT:     make(map[int]*BaseOTMaterial),
		FZeroSeeds: make(map[int][16]byte),
		Blacklist:  make(map[int]bool),
	}, nil
}

// UnmarshalLegacyEncrypted is UnmarshalLegacySetup over an encrypted blob.
func UnmarshalLegacyEncrypted(ciphertext []byte, enc SetupEncryptor) (*SignerSetup, error) {
	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalLegacyEncrypted: decrypt: %w", err)
	}
	return UnmarshalLegacySetup(plaintext)
}
