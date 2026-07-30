package dkls23

import (
	"encoding/json"
	"testing"
)

// Round1Msg's wire format must carry the OT-extension consistency proof.
//
// The proof is not an optional annex to the corrections: OTExtSenderExpand
// refuses corrections it cannot check, so a Round1Msg that survives JSON without
// its proof is a round-1 message no counterparty can use. Signing over the
// package's own wire format stops working entirely.
//
// The existing round-trip tests cannot see this. roundTrip marshals, unmarshals
// and marshals again, then compares the two JSON documents — a field the encoder
// drops is absent from BOTH documents and compares equal. Only feeding the
// decoded message back into SignRound2 shows it.
func TestRound1MsgWireFormatCarriesOTEConsistencyProof(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	const sigID = "round1msg-wire"

	states := map[int]*Round1State{}
	msgs := map[int]map[int]*Round1Msg{}
	for _, id := range signers {
		st, m, err := SignRound1(setups[id], sigID, signers)
		if err != nil {
			t.Fatal(err)
		}
		states[id] = st
		msgs[id] = m
	}

	// Party 1 receives round 1 the way a networked node does: encoded, shipped,
	// decoded. Nothing else about the session changes.
	inbound := map[int]*Round1Msg{}
	for _, j := range signers {
		if j == 1 {
			continue
		}
		raw, err := json.Marshal(msgs[j][1])
		if err != nil {
			t.Fatal(err)
		}
		var decoded Round1Msg
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.OTECheckT != msgs[j][1].OTECheckT || decoded.OTECheckX != msgs[j][1].OTECheckX {
			t.Errorf("party %d: OTE consistency proof did not survive JSON: "+
				"got T=%x X=%x, want T=%x X=%x", j,
				decoded.OTECheckT, decoded.OTECheckX,
				msgs[j][1].OTECheckT, msgs[j][1].OTECheckX)
		}
		inbound[j] = &decoded
	}

	if _, _, err := SignRound2(setups[1], states[1], inbound); err != nil {
		t.Fatalf("SignRound2 rejected wire-decoded round 1 messages: %v", err)
	}
}
