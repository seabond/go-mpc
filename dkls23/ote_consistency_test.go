package dkls23

import (
	"strings"
	"testing"
)

// The attack the check exists to stop.
//
// Bob builds honest corrections, then flips one bit of one row — using beta xor
// delta in that row alone. Alice's Q moves away from his prediction exactly when
// sigma_k = 1, so his own downstream check passing or failing tells him sigma_k.
// One bit per session, chosen by him, with no error, against a choice vector
// that is reused with that peer forever.
//
// With the consistency check the tampered corrections are refused before Alice
// derives a single pad, so there is no downstream check to read an answer from.
func TestTamperedCorrectionsAreRefusedBeforeAnyPadIsDerived(t *testing.T) {
	t.Parallel()
	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	beta := mustBeta(t)
	const sid = "selective-failure"

	corr, proof, err := OTExtReceiverCorrections(sid, bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: honest corrections must pass, or this test would "succeed" for the
	// wrong reason.
	if _, _, err := OTExtSenderExpand(sid, aliceSeeds, sigma, corr, proof); err != nil {
		t.Fatalf("honest corrections were refused: %v", err)
	}

	// One flipped bit in one row is the whole attack.
	for _, k := range []int{0, 1, 63, 64, 127} {
		tampered := make([][Xi / 8]byte, len(corr))
		copy(tampered, corr)
		tampered[k][k/8] ^= 1 << (uint(k) % 8)

		_, _, err := OTExtSenderExpand(sid, aliceSeeds, sigma, tampered, proof)
		if err == nil {
			t.Fatalf("a correction row tampered at k=%d was accepted: that is one bit of "+
				"the sender's long-term sigma, and the bits accumulate", k)
		}
		if !strings.Contains(err.Error(), "consistency check failed") {
			t.Fatalf("k=%d refused for the wrong reason: %v", k, err)
		}
	}
}

// Bob's other move is to keep the corrections and forge the proof to match. He
// does not know sigma, so he cannot: the verification equation he must satisfy
// has sigma in it.
func TestAForgedProofDoesNotPass(t *testing.T) {
	t.Parallel()
	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	beta := mustBeta(t)
	const sid = "forged-proof"

	corr, proof, err := OTExtReceiverCorrections(sid, bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}

	for name, forged := range map[string]oteConsistencyProof{
		"zeroed":         {},
		"flipped t":      {TTilde: flip16(proof.TTilde), XTilde: proof.XTilde},
		"flipped x":      {TTilde: proof.TTilde, XTilde: flip16(proof.XTilde)},
		"halves swapped": {TTilde: proof.XTilde, XTilde: proof.TTilde},
	} {
		if _, _, err := OTExtSenderExpand(sid, aliceSeeds, sigma, corr, forged); err == nil {
			t.Fatalf("a %s proof was accepted", name)
		}
	}
}

// A proof is bound to its session. Lifting one from an earlier session — where
// it was genuinely valid — must not authorize this session's corrections, or the
// binding that keeps the pads fresh is worked around at this layer instead.
func TestAProofFromAnotherSessionDoesNotTransfer(t *testing.T) {
	t.Parallel()
	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	beta := mustBeta(t)

	_, proofA, err := OTExtReceiverCorrections("session-A", bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}
	corrB, _, err := OTExtReceiverCorrections("session-B", bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OTExtSenderExpand("session-B", aliceSeeds, sigma, corrB, proofA); err == nil {
		t.Fatal("a proof from another session authorized these corrections")
	}
}

// The challenge is derived from the corrections themselves, so a proof cannot be
// computed before they are fixed. Swapping in a different honest correction set
// under a proof built for the first one must fail — otherwise Bob could choose
// his rows after seeing which combination he would be asked for.
func TestCorrectionsCannotBeSwappedUnderAValidProof(t *testing.T) {
	t.Parallel()
	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	const sid = "swap"

	_, proof1, err := OTExtReceiverCorrections(sid, bob0, bob1, mustBeta(t))
	if err != nil {
		t.Fatal(err)
	}
	corr2, _, err := OTExtReceiverCorrections(sid, bob0, bob1, mustBeta(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OTExtSenderExpand(sid, aliceSeeds, sigma, corr2, proof1); err == nil {
		t.Fatal("corrections were swapped under a proof built for a different set")
	}
}

func flip16(a [16]byte) [16]byte {
	a[0] ^= 1
	return a
}
