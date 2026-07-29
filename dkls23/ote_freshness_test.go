package dkls23

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// The OT-extension pads must differ between sessions EVEN WHERE beta AGREES.
//
// This is the property the first attempt at per-session VOLE missed. That change
// sampled a fresh beta each session, which made chi differ — and a test that only
// checked chi passed — while the pads beta selects between stayed fixed, because
// prg() was a pure function of a base-OT seed that is reused by design.
//
// The consequence was total: alpha0/alpha1 collapsed to four fixed values per
// index, so any two sessions agreeing at index j reused that pad exactly. Since
// VOLEAliceMultiply sends aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i],
// subtracting two such sessions cancels the pad and hands the counterparty the
// difference of Alice's inputs. a[0] is her nonce share, so two ordinary
// signatures yielded the difference of two ECDSA nonces and, from that, the
// group private key.
//
// Testing "chi differs" is therefore not enough, and this test exists because
// that weaker assertion is what let the break survive a fix.
func TestOTEPadsDifferAcrossSessionsEvenWhereBetaAgrees(t *testing.T) {
	t.Parallel()

	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	m := &BaseOTMaterial{BobSeeds0: bob0, BobSeeds1: bob1, AliceSeeds: aliceSeeds, Sigma: sigma}

	const sidA = "session-A:vole:2->1"
	const sidB = "session-B:vole:2->1"

	// Two sessions with a DELIBERATELY IDENTICAL beta. If freshness came only from
	// resampling beta, these two would be byte-identical everywhere — which is
	// exactly the case the attack exploited, just made total instead of partial.
	beta := mustBeta(t)

	corrA, err := OTExtReceiverCorrections(sidA, m.BobSeeds0, m.BobSeeds1, beta)
	if err != nil {
		t.Fatal(err)
	}
	corrB, err := OTExtReceiverCorrections(sidB, m.BobSeeds0, m.BobSeeds1, beta)
	if err != nil {
		t.Fatal(err)
	}

	a0A, a1A, err := OTExtSenderExpand(sidA, m.AliceSeeds, m.Sigma, corrA)
	if err != nil {
		t.Fatal(err)
	}
	a0B, a1B, err := OTExtSenderExpand(sidB, m.AliceSeeds, m.Sigma, corrB)
	if err != nil {
		t.Fatal(err)
	}

	repeats := 0
	for j := range a0A {
		for i := range a0A[j] {
			if a0A[j][i] == a0B[j][i] || a1A[j][i] == a1B[j][i] {
				repeats++
			}
		}
	}
	if repeats != 0 {
		t.Fatalf("%d OTE pads repeated across sessions despite different session ids; "+
			"subtracting two such sessions cancels the pad and leaks Alice's inputs", repeats)
	}

	// The masking value the attack actually subtracts is alpha0 - alpha1. Even if
	// the individual pads changed but their DIFFERENCE did not, the break would
	// survive, so check the difference directly.
	sameDiff := 0
	for j := range a0A {
		for i := range a0A[j] {
			dA := subMod(a0A[j][i], a1A[j][i])
			dB := subMod(a0B[j][i], a1B[j][i])
			if dA == dB {
				sameDiff++
			}
		}
	}
	if sameDiff != 0 {
		t.Fatalf("the alpha0-alpha1 masking difference repeated at %d positions; "+
			"that is the exact quantity the two-time-pad attack cancels", sameDiff)
	}
}

// Correctness must survive the change: Bob's gamma still has to equal the alpha
// he chose with beta, or nothing signs.
func TestOTECorrectnessHoldsWithSessionBinding(t *testing.T) {
	t.Parallel()

	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	const sid = "session-C:vole:2->1"
	beta := mustBeta(t)

	corr, err := OTExtReceiverCorrections(sid, bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}
	alpha0, alpha1, err := OTExtSenderExpand(sid, aliceSeeds, sigma, corr)
	if err != nil {
		t.Fatal(err)
	}
	gamma, err := OTExtReceiverExpand(sid, bob0, beta, corr)
	if err != nil {
		t.Fatal(err)
	}

	for j := range gamma {
		want := alpha0[j]
		if beta[j] {
			want = alpha1[j]
		}
		for i := range gamma[j] {
			if gamma[j][i] != want[i] {
				t.Fatalf("OTE correctness broken at j=%d i=%d", j, i)
			}
		}
	}
}

// Both sides of a directed pair must derive the SAME session id, or the
// correlation does not cancel and no signature is produced. A mismatch must fail
// loudly here rather than as an unexplained signing error in production.
func TestMismatchedSessionIDBreaksTheCorrelation(t *testing.T) {
	t.Parallel()

	bob0, bob1, aliceSeeds, sigma := buildBaseOTPair(t)
	beta := mustBeta(t)

	corr, err := OTExtReceiverCorrections("session-D:vole:2->1", bob0, bob1, beta)
	if err != nil {
		t.Fatal(err)
	}
	// Alice uses a DIFFERENT sid — the shape a wiring bug would take.
	alpha0, alpha1, err := OTExtSenderExpand("session-E:vole:2->1", aliceSeeds, sigma, corr)
	if err != nil {
		t.Fatal(err)
	}
	gamma, err := OTExtReceiverExpand("session-D:vole:2->1", bob0, beta, corr)
	if err != nil {
		t.Fatal(err)
	}

	matches := 0
	for j := range gamma {
		want := alpha0[j]
		if beta[j] {
			want = alpha1[j]
		}
		if gamma[j][0] == want[0] {
			matches++
		}
	}
	if matches != 0 {
		t.Fatalf("mismatched session ids still produced %d agreeing OTE outputs; "+
			"the binding is not actually load-bearing", matches)
	}
}

// buildBaseOTPair runs one directed base OT and returns both halves.
func buildBaseOTPair(t *testing.T) (bobSeeds0, bobSeeds1, aliceSeeds [][]byte, sigma []bool) {
	t.Helper()
	priv, pub, err := BaseSenderRound1(LambdaC)
	if err != nil {
		t.Fatal(err)
	}
	sigma = randomBools(t, LambdaC)
	resp, aliceSeeds, err := BaseReceiverRound1(pub, sigma)
	if err != nil {
		t.Fatal(err)
	}
	bobSeeds0, bobSeeds1, err = BaseSenderFinalize(priv, pub, resp)
	if err != nil {
		t.Fatal(err)
	}
	return bobSeeds0, bobSeeds1, aliceSeeds, sigma
}

func mustBeta(t *testing.T) [Xi]bool {
	t.Helper()
	buf := make([]byte, (Xi+7)/8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	var beta [Xi]bool
	for j := 0; j < Xi; j++ {
		beta[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return beta
}

// subMod subtracts two 32-byte scalars modulo the group order, matching how the
// VOLE layer combines them.
func subMod(a, b [32]byte) [32]byte {
	var x, y btcec.ModNScalar
	x.SetBytes(&a)
	y.SetBytes(&b)
	y.Negate()
	x.Add(&y)
	return x.Bytes()
}
