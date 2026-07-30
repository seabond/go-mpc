package dkls23

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Round 3 is where psi stops being an inert wire value and becomes leverage.
//
// eff_phi_i = phi_i + sum_j psi_{j,i}, and the fragments are
// u_i = r_i*eff_phi_i + (VOLE terms) and w_i = h*phi_i + rx*(sk_i*eff_phi_i + ...).
// Run round 3 twice over the same Round2State with psi and then psi', and the
// VOLE terms — which do not depend on psi — cancel in the difference:
//
//	(u_i - u_i') / (psi - psi') = r_i
//	(w_i - w_i') / (psi - psi') = rx * sk_i
//
// psi and psi' are the attacker's own choice, so both divisions are computable by
// a party that holds no share at all: the relay driving the ceremony. sk_i is the
// signer's rerandomized Shamir share, and summed over the signers that is the
// group private key.
//
// Two independent things have to hold for that to be impossible, and these tests
// check them separately so that losing either one is visible:
//   - round 3 runs at most once per Round2State, and
//   - the psi it consumes is the one its sender committed to in round 1.

// signThroughRound2 runs rounds 1 and 2 of a 3-of-3 and returns the per-party
// round 2 state along with the round 2 messages, keyed [sender][recipient].
func signThroughRound2(t *testing.T, sigID string) (map[int]*SignerSetup, []int, map[int]*Round2State, map[int]map[int]*Round2Msg) {
	t.Helper()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	r1States := make(map[int]*Round1State)
	r1Msgs := make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1States[id] = st
		r1Msgs[id] = msgs
	}

	r2States := make(map[int]*Round2State)
	r2Msgs := make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		st, msgs, err := SignRound2(setups[id], r1States[id], inboundFor(signers, id, r1Msgs))
		require.NoError(t, err)
		r2States[id] = st
		r2Msgs[id] = msgs
	}
	return setups, signers, r2States, r2Msgs
}

// inboundFor picks out the messages addressed to myID, the way a relay would
// route them.
func inboundFor[T any](signers []int, myID int, all map[int]map[int]T) map[int]T {
	m := make(map[int]T, len(signers)-1)
	for _, j := range signers {
		if j != myID {
			m[j] = all[j][myID]
		}
	}
	return m
}

// copyRound2Msg clones a round 2 message so a test can tamper with the copy
// without disturbing the sender's own view of what it sent — exactly the
// position a relay is in.
func copyRound2Msg(m *Round2Msg) *Round2Msg {
	out := *m
	out.Decommitment = append([]byte(nil), m.Decommitment...)
	out.Psi = append([]byte(nil), m.Psi...)
	out.GammaU = append([]byte(nil), m.GammaU...)
	out.GammaV = append([]byte(nil), m.GammaV...)
	return &out
}

func TestSignRound3IsSingleShotPerSession(t *testing.T) {
	t.Parallel()

	setups, signers, r2States, r2Msgs := signThroughRound2(t, "round3-single-shot")
	msg := []byte("round 3 must run once per session")
	inbound := inboundFor(signers, 1, r2Msgs)

	frags, err := SignRound3(setups[1], r2States[1], msg, inbound)
	require.NoError(t, err)
	require.NotEmpty(t, frags)

	// A verbatim replay is refused. Nothing about the input has changed, so the
	// only thing that can refuse it is the state knowing it is spent.
	_, err = SignRound3(setups[1], r2States[1], msg, inbound)
	require.Error(t, err, "a second round 3 over the same Round2State must be refused")
	var inputErr *InvalidInputError
	require.ErrorAs(t, err, &inputErr, "the replay must fail as a caller error, not silently produce a fragment")

	// The replay that actually recovers the share carries a different psi. It must
	// be refused for the same reason, before any fragment exists to subtract.
	tampered := inboundFor(signers, 1, r2Msgs)
	tampered[2] = copyRound2Msg(tampered[2])
	tampered[2].Psi[31] ^= 0x01
	_, err = SignRound3(setups[1], r2States[1], msg, tampered)
	require.Error(t, err, "a second round 3 under a different psi must be refused")

	// A different digest on the replay must not open a way through either: the
	// share falls out of the psi difference regardless of what is being signed.
	_, err = SignRound3(setups[1], r2States[1], []byte("some other message"), inbound)
	require.Error(t, err)
}

func TestSignRound3RejectsMutatedPsi(t *testing.T) {
	t.Parallel()

	setups, signers, r2States, r2Msgs := signThroughRound2(t, "round3-mutated-psi")
	msg := []byte("psi must match its round 1 commitment")

	// Party 2's psi is rewritten in flight, on its FIRST and only trip to party 1.
	// Nothing has been replayed here — this is the single-shot guard's blind spot,
	// and only the round 1 commitment covers it.
	inbound := inboundFor(signers, 1, r2Msgs)
	inbound[2] = copyRound2Msg(inbound[2])
	inbound[2].Psi[0] ^= 0xff

	_, err := SignRound3(setups[1], r2States[1], msg, inbound)
	require.Error(t, err, "a psi that does not open against the round 1 commitment must abort round 3")
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	require.Contains(t, cheatErr.PartyIDs, 2, "the party whose psi did not open must be named")
	require.True(t, setups[1].Blacklist[2], "a psi that does not open is cheating, and must be recorded as such")
}

func TestSignRound3RejectsMalformedPsiLength(t *testing.T) {
	t.Parallel()

	// psi is one half of a commitment over R_j || psi. If the widths are not
	// pinned, bytes can be moved across the boundary and the same commitment opens
	// to a different pair — so a wrong length must be refused outright rather than
	// left to SetByteSlice, which pads and truncates without complaint.
	cases := map[string]func(m *Round2Msg){
		"empty":     func(m *Round2Msg) { m.Psi = nil },
		"truncated": func(m *Round2Msg) { m.Psi = m.Psi[:31] },
		"padded":    func(m *Round2Msg) { m.Psi = append([]byte{0x00}, m.Psi...) },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			setups, signers, r2States, r2Msgs := signThroughRound2(t, "round3-psi-length-"+name)
			inbound := inboundFor(signers, 1, r2Msgs)
			inbound[2] = copyRound2Msg(inbound[2])
			mutate(inbound[2])

			_, err := SignRound3(setups[1], r2States[1], []byte("psi length check"), inbound)
			require.Error(t, err, "psi of the wrong length must abort round 3")
			var cheatErr *CheatingPartyError
			require.ErrorAs(t, err, &cheatErr)
			require.Contains(t, cheatErr.PartyIDs, 2)
		})
	}
}

func TestRound2StateStaysSpentAcrossSerialization(t *testing.T) {
	t.Parallel()

	// A node that snapshots its round 2 state must not be able to replay round 3
	// by restoring the snapshot: the same nonce with a second eff_phi is the same
	// break whether the second run happens in this process or after a restart.
	setups, signers, r2States, r2Msgs := signThroughRound2(t, "round3-spent-across-json")
	msg := []byte("a restored state is still spent")
	inbound := inboundFor(signers, 1, r2Msgs)

	_, err := SignRound3(setups[1], r2States[1], msg, inbound)
	require.NoError(t, err)

	blob, err := r2States[1].MarshalJSON()
	require.NoError(t, err)
	var restored Round2State
	require.NoError(t, restored.UnmarshalJSON(blob))

	_, err = SignRound3(setups[1], &restored, msg, inbound)
	require.Error(t, err, "a restored Round2State must still be spent")
	var inputErr *InvalidInputError
	require.ErrorAs(t, err, &inputErr)
}
