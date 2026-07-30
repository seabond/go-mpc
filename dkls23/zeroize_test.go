package dkls23

import (
	"bytes"
	"testing"
)

// A test that only checked "Zero() was called" would pass against a Zero() that
// did nothing. These read the bytes back out of the struct instead, so what is
// asserted is erasure rather than intent.

func liveRound2State(t *testing.T) *Round2State {
	t.Helper()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	st1, msgs1, err := SignRound1(setups[1], "sig-zeroize", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	st2, msgs2, err := SignRound1(setups[2], "sig-zeroize", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	_ = msgs1
	r2, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{2: msgs2[1]})
	if err != nil {
		t.Fatal(err)
	}
	_ = st2
	return r2
}

// SK_i is the rerandomized Shamir share and R_i is the nonce. Either one, read
// out of freed heap next to the signature it produced, gives up the share: for
// the nonce it is one division.
func TestZeroErasesTheShareAndTheNonce(t *testing.T) {
	t.Parallel()
	st := liveRound2State(t)

	skBefore := st.SK_i.Bytes()
	nonceBefore := st.R_i.Bytes()
	if bytes.Equal(skBefore[:], make([]byte, 32)) {
		t.Fatal("SK_i was already zero before Zero(); the test proves nothing")
	}
	if bytes.Equal(nonceBefore[:], make([]byte, 32)) {
		t.Fatal("R_i was already zero before Zero(); the test proves nothing")
	}

	st.Zero()

	if got := st.SK_i.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("SK_i survived Zero(): %x", got)
	}
	if got := st.R_i.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("R_i survived Zero(): %x", got)
	}
	if got := st.Phi_i.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("Phi_i survived Zero(): %x", got)
	}
	if got := st.ZetaI.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("ZetaI survived Zero(): %x", got)
	}
}

// Round2State embeds *Round1State, so a Zero that forgot to descend would leave
// the whole first round intact while looking like it had worked.
func TestZeroOnRound2DescendsIntoRound1AndItsVOLEState(t *testing.T) {
	t.Parallel()
	st := liveRound2State(t)

	if len(st.Psi) == 0 {
		t.Fatal("no psi values to erase; the test proves nothing")
	}
	if len(st.VoleBobForRound2) == 0 {
		t.Fatal("no VOLE Bob state to erase; the test proves nothing")
	}
	bobs := make([]*VOLEBobState, 0, len(st.VoleBobForRound2))
	for _, b := range st.VoleBobForRound2 {
		bobs = append(bobs, b)
	}
	chiBefore := bobs[0].Chi.Bytes()
	if bytes.Equal(chiBefore[:], make([]byte, 32)) {
		t.Fatal("chi was already zero; the test proves nothing")
	}

	st.Zero()

	if len(st.Psi) != 0 {
		t.Fatalf("%d psi value(s) survived Zero()", len(st.Psi))
	}
	if len(st.VoleBobForRound2) != 0 {
		t.Fatalf("%d VOLE Bob state(s) survived Zero()", len(st.VoleBobForRound2))
	}
	// The map entries are gone, but the states they pointed at are what held the
	// secret — dropping the map without erasing them would be the same mistake one
	// level down.
	if got := bobs[0].Chi.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("VOLE Bob chi survived Zero(): %x", got)
	}
	var zeroBeta [Xi]bool
	if bobs[0].Beta != zeroBeta {
		t.Fatal("VOLE Bob beta survived Zero()")
	}
}

// Every path that ends a ceremony calls this, including the ones where it failed
// partway and the ones that run twice because a defer and an error path both
// fire. None may panic.
func TestZeroIsSafeOnNilAndOnAnAlreadyZeroedState(t *testing.T) {
	t.Parallel()
	var r1 *Round1State
	var r2 *Round2State
	var bob *VOLEBobState
	var alice *VOLEAliceState
	r1.Zero()
	r2.Zero()
	bob.Zero()
	alice.Zero()

	st := liveRound2State(t)
	st.Zero()
	st.Zero()

	// A half-built state: round 1 reached, round 2 never did.
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	only1, _, err := SignRound1(setups[1], "sig-partial", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	only1.Zero()
	if got := only1.R_i.Bytes(); !bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatalf("R_i survived Zero() on a round-1-only state: %x", got)
	}
}

// Alice's pads are what the per-session sid binding keeps fresh. A pair
// recovered from memory is as usable as one reused on the wire, so they are
// erased with the rest.
func TestZeroErasesAliceSenderPads(t *testing.T) {
	t.Parallel()
	a := &VOLEAliceState{
		Alpha0: make([][Ell + Rho][32]byte, 2),
		Alpha1: make([][Ell + Rho][32]byte, 2),
	}
	a.Alpha0[0][0] = [32]byte{1, 2, 3}
	a.Alpha1[1][0] = [32]byte{4, 5, 6}
	pads0, pads1 := a.Alpha0, a.Alpha1

	a.Zero()

	if a.Alpha0 != nil || a.Alpha1 != nil {
		t.Fatal("pad slices were not released")
	}
	// The backing arrays are what an attacker would read; dropping the slice
	// header alone leaves them intact.
	var zero [32]byte
	if pads0[0][0] != zero {
		t.Fatalf("alpha0 backing array survived Zero(): %x", pads0[0][0])
	}
	if pads1[1][0] != zero {
		t.Fatalf("alpha1 backing array survived Zero(): %x", pads1[1][0])
	}
}
