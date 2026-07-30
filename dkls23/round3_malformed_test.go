package dkls23

import (
	"strings"
	"testing"
)

// A round 2 message travels through the proposer. Its round 1 commitment covers
// R_j and psi — not the VOLE multiply message — so a relay can strip vole_msg
// from an otherwise genuine message and the open still succeeds.
//
// That has to land as cheating by party j, because that is what it is. It used
// to land as a nil dereference, which in a gRPC handler is the whole process:
// one forwarded message with a field removed, and every ceremony on the node
// goes with it.
func TestRound3TreatsAMissingVOLEMessageAsCheatingNotAsAPanic(t *testing.T) {
	t.Parallel()
	setups, err := buildSetups([]int{1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	const sigID = "stripped-vole"
	signers := []int{1, 2}

	st1, m1, err := SignRound1(setups[1], sigID, signers)
	if err != nil {
		t.Fatal(err)
	}
	st2, m2, err := SignRound1(setups[2], sigID, signers)
	if err != nil {
		t.Fatal(err)
	}
	r2a, _, err := SignRound2(setups[1], st1, map[int]*Round1Msg{2: m2[1]})
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := SignRound2(setups[2], st2, map[int]*Round1Msg{1: m1[2]})
	if err != nil {
		t.Fatal(err)
	}

	stripped := *out2[1]
	stripped.VoleMsg = nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a stripped vole_msg panicked the receiving party: %v", r)
		}
	}()

	_, err = SignRound3(setups[1], r2a, make([]byte, 32), map[int]*Round2Msg{2: &stripped})
	if err == nil {
		t.Fatal("a round 2 message with no VOLE multiply message was accepted")
	}
	// It must be attributed to party 2 rather than reported as a local fault: the
	// blacklist is how a node stops working with a party that does this.
	if !strings.Contains(err.Error(), "cheating") {
		t.Fatalf("a stripped vole_msg was not attributed as cheating: %v", err)
	}
	if !setups[1].Blacklist[2] {
		t.Fatal("party 2 was not blacklisted for sending a message with no VOLE part")
	}
}
