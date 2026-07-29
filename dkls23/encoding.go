package dkls23

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
)

// --- Encoding helpers ---

// scalarToHex serializes a ModNScalar to 64-char hex (32 bytes big-endian).
// Wire-format compatible with the previous bigToHex implementation.
func scalarToHex(s *btcec.ModNScalar) string {
	b := s.Bytes()
	return hex.EncodeToString(b[:])
}

// hexToScalar parses a 64-char hex string into a ModNScalar.
// Wire-format compatible with the previous hexToBig implementation.
func hexToScalar(s string) (btcec.ModNScalar, error) {
	var out btcec.ModNScalar
	if s == "" {
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("hexToScalar: %w", err)
	}
	out.SetByteSlice(b)
	return out, nil
}

// scalarMapToHex serializes map[int]ModNScalar to map[string]string for JSON.
func scalarMapToHex(m map[int]btcec.ModNScalar) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = scalarToHex(&v)
	}
	return out
}

// hexToScalarMap deserializes map[string]string to map[int]ModNScalar from JSON.
func hexToScalarMap(m map[string]string) (map[int]btcec.ModNScalar, error) {
	out := make(map[int]btcec.ModNScalar, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		val, err := hexToScalar(v)
		if err != nil {
			return nil, err
		}
		out[id] = val
	}
	return out, nil
}

func bytesToHex(b []byte) string { return hex.EncodeToString(b) }

func hexToBytes(s string) ([]byte, error) { return hex.DecodeString(s) }

func hexToFixed32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func hexToFixed16(s string) ([16]byte, error) {
	var out [16]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 16 {
		return out, fmt.Errorf("expected 16 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// intMapKeys converts map[int]V to map[string]V for JSON.
func intMapKeys[V any](m map[int]V) map[string]V {
	if m == nil {
		return nil
	}
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = v
	}
	return out
}

// stringMapKeys converts map[string]V to map[int]V from JSON.
func stringMapKeys[V any](m map[string]V) (map[int]V, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[int]V, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("invalid party ID %q: %w", k, err)
		}
		out[id] = v
	}
	return out, nil
}

// map[int][32]byte ↔ map[string]string
func intMap32ToJSON(m map[int][32]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return out
}

func jsonToIntMap32(m map[string]string) (map[int][32]byte, error) {
	out := make(map[int][32]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hexToFixed32(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// map[int][16]byte ↔ map[string]string
func intMap16ToJSON(m map[int][16]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return out
}

func jsonToIntMap16(m map[string]string) (map[int][16]byte, error) {
	out := make(map[int][16]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hexToFixed16(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// map[int][]byte ↔ map[string]string (hex encoded values)
func intMapBytesToJSON(m map[int][]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v)
	}
	return out
}

func jsonToIntMapBytes(m map[string]string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// --- VOLE array encoding ---
// The VOLE arrays are large (up to 53KB) so we flatten to binary + base64.

func encodeVOLESlice(data [][Ell + Rho][32]byte) string {
	n := len(data)
	buf := make([]byte, n*(Ell+Rho)*32)
	for j := range data {
		for i := 0; i < Ell+Rho; i++ {
			copy(buf[(j*(Ell+Rho)+i)*32:], data[j][i][:])
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeVOLESlice(s string) ([][Ell + Rho][32]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	entrySize := (Ell + Rho) * 32
	if len(buf)%entrySize != 0 {
		return nil, fmt.Errorf("VOLE slice data size %d not divisible by %d", len(buf), entrySize)
	}
	n := len(buf) / entrySize
	out := make([][Ell + Rho][32]byte, n)
	for j := 0; j < n; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(out[j][i][:], buf[(j*(Ell+Rho)+i)*32:])
		}
	}
	return out, nil
}

func encodeVOLEFixed(data [Xi][Ell + Rho][32]byte) string {
	buf := make([]byte, Xi*(Ell+Rho)*32)
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(buf[(j*(Ell+Rho)+i)*32:], data[j][i][:])
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeVOLEFixed(s string) ([Xi][Ell + Rho][32]byte, error) {
	var out [Xi][Ell + Rho][32]byte
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	expected := Xi * (Ell + Rho) * 32
	if len(buf) != expected {
		return out, fmt.Errorf("VOLE fixed data size %d, expected %d", len(buf), expected)
	}
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(out[j][i][:], buf[(j*(Ell+Rho)+i)*32:])
		}
	}
	return out, nil
}

func encodeRhoFixed(data [Rho][32]byte) string {
	buf := make([]byte, Rho*32)
	for k := 0; k < Rho; k++ {
		copy(buf[k*32:], data[k][:])
	}
	return hex.EncodeToString(buf)
}

func decodeRhoFixed(s string) ([Rho][32]byte, error) {
	var out [Rho][32]byte
	buf, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(buf) != Rho*32 {
		return out, fmt.Errorf("rho data size %d, expected %d", len(buf), Rho*32)
	}
	for k := 0; k < Rho; k++ {
		copy(out[k][:], buf[k*32:])
	}
	return out, nil
}

func encodeBoolArray(data [Xi]bool) string {
	buf := make([]byte, (Xi+7)/8)
	for j := 0; j < Xi; j++ {
		if data[j] {
			buf[j/8] |= 1 << (uint(j) % 8)
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeBoolArray(s string) ([Xi]bool, error) {
	var out [Xi]bool
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(buf) != (Xi+7)/8 {
		return out, fmt.Errorf("bool array size %d, expected %d", len(buf), (Xi+7)/8)
	}
	for j := 0; j < Xi; j++ {
		out[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return out, nil
}

// [][]byte ↔ []string (hex)
func encodeBytesSlice(data [][]byte) []string {
	out := make([]string, len(data))
	for i, b := range data {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func decodeBytesSlice(data []string) ([][]byte, error) {
	out := make([][]byte, len(data))
	for i, s := range data {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// =====================================================================
// DKGRound1Output
// =====================================================================

type dkgRound1OutputJSON struct {
	FeldmanCommitments  []string          `json:"feldman_commitments"`
	PairwiseCommitments map[string]string `json:"pairwise_commitments"`
	PairwiseSalts       map[string]string `json:"pairwise_salts"`
}

func (o *DKGRound1Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(dkgRound1OutputJSON{
		FeldmanCommitments:  encodeBytesSlice(o.FeldmanCommitments),
		PairwiseCommitments: intMap32ToJSON(o.PairwiseCommitments),
		PairwiseSalts:       intMap32ToJSON(o.PairwiseSalts),
	})
}

func (o *DKGRound1Output) UnmarshalJSON(data []byte) error {
	var j dkgRound1OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	o.FeldmanCommitments, err = decodeBytesSlice(j.FeldmanCommitments)
	if err != nil {
		return err
	}
	o.PairwiseCommitments, err = jsonToIntMap32(j.PairwiseCommitments)
	if err != nil {
		return err
	}
	o.PairwiseSalts, err = jsonToIntMap32(j.PairwiseSalts)
	return err
}

// =====================================================================
// DKGRound2Output
// =====================================================================

type dkgRound2OutputJSON struct {
	SecretShares map[string]string `json:"secret_shares"`
}

func (o *DKGRound2Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(dkgRound2OutputJSON{
		SecretShares: intMapBytesToJSON(o.SecretShares),
	})
}

func (o *DKGRound2Output) UnmarshalJSON(data []byte) error {
	var j dkgRound2OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	o.SecretShares, err = jsonToIntMapBytes(j.SecretShares)
	return err
}

// =====================================================================
// VOLEBobState
// =====================================================================

type voleBobStateJSON struct {
	Beta  string `json:"beta"`
	Chi   string `json:"chi"`
	Gamma string `json:"gamma"`
}

func (s *VOLEBobState) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleBobStateJSON{
		Beta:  encodeBoolArray(s.Beta),
		Chi:   scalarToHex(&s.Chi),
		Gamma: encodeVOLESlice(s.Gamma),
	})
}

func (s *VOLEBobState) UnmarshalJSON(data []byte) error {
	var j voleBobStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	s.Beta, err = decodeBoolArray(j.Beta)
	if err != nil {
		return err
	}
	s.Chi, err = hexToScalar(j.Chi)
	if err != nil {
		return err
	}
	s.Gamma, err = decodeVOLESlice(j.Gamma)
	return err
}

// =====================================================================
// VOLEAliceState
// =====================================================================

type voleAliceStateJSON struct {
	Alpha0 string `json:"alpha0"`
	Alpha1 string `json:"alpha1"`
	CU     string `json:"c_u"`
	CV     string `json:"c_v"`
}

func (s *VOLEAliceState) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleAliceStateJSON{
		Alpha0: encodeVOLESlice(s.Alpha0),
		Alpha1: encodeVOLESlice(s.Alpha1),
		CU:     scalarToHex(&s.C_u),
		CV:     scalarToHex(&s.C_v),
	})
}

func (s *VOLEAliceState) UnmarshalJSON(data []byte) error {
	var j voleAliceStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	s.Alpha0, err = decodeVOLESlice(j.Alpha0)
	if err != nil {
		return err
	}
	s.Alpha1, err = decodeVOLESlice(j.Alpha1)
	if err != nil {
		return err
	}
	s.C_u, err = hexToScalar(j.CU)
	if err != nil {
		return err
	}
	s.C_v, err = hexToScalar(j.CV)
	return err
}

// =====================================================================
// VOLEMultiplyMsg
// =====================================================================

type voleMultiplyMsgJSON struct {
	SID    string `json:"sid"`
	ATilde string `json:"a_tilde"`
	Eta    string `json:"eta"`
	Mu     string `json:"mu"`
}

func (m *VOLEMultiplyMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleMultiplyMsgJSON{
		SID:    m.SID,
		ATilde: encodeVOLEFixed(m.ATilde),
		Eta:    encodeRhoFixed(m.Eta),
		Mu:     hex.EncodeToString(m.Mu[:]),
	})
}

func (m *VOLEMultiplyMsg) UnmarshalJSON(data []byte) error {
	var j voleMultiplyMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	m.SID = j.SID
	var err error
	m.ATilde, err = decodeVOLEFixed(j.ATilde)
	if err != nil {
		return err
	}
	m.Eta, err = decodeRhoFixed(j.Eta)
	if err != nil {
		return err
	}
	m.Mu, err = hexToFixed32(j.Mu)
	return err
}

// =====================================================================
// Round1Msg
// =====================================================================

// Round1Msg needs custom encoding for the same reason OTExtCorrectionsMsg does:
// [][Xi/8]byte is a slice of fixed-size arrays and does not serialize usefully by
// default.
type round1MsgJSON struct {
	Commitment     string   `json:"commitment"`
	OTECorrections []string `json:"ote_corrections"`
}

func (m *Round1Msg) MarshalJSON() ([]byte, error) {
	corrs := make([]string, len(m.OTECorrections))
	for i, c := range m.OTECorrections {
		corrs[i] = hex.EncodeToString(c[:])
	}
	return json.Marshal(round1MsgJSON{
		Commitment:     hex.EncodeToString(m.Commitment[:]),
		OTECorrections: corrs,
	})
}

func (m *Round1Msg) UnmarshalJSON(data []byte) error {
	var j round1MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	if m.Commitment, err = hexToFixed32(j.Commitment); err != nil {
		return err
	}
	m.OTECorrections = make([][Xi / 8]byte, len(j.OTECorrections))
	for i, s := range j.OTECorrections {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("Round1Msg.OTECorrections[%d]: %w", i, err)
		}
		if len(b) != Xi/8 {
			return fmt.Errorf("Round1Msg.OTECorrections[%d]: got %d bytes, want %d", i, len(b), Xi/8)
		}
		copy(m.OTECorrections[i][:], b)
	}
	return nil
}

// =====================================================================
// Round1State
// =====================================================================

type round1StateJSON struct {
	SigID            string                   `json:"sig_id"`
	Signers          []int                    `json:"signers"`
	RI               string                   `json:"r_i"`
	PhiI             string                   `json:"phi_i"`
	RIPoint          string                   `json:"r_i_point"`
	Com              string                   `json:"com"`
	Salt             string                   `json:"salt"`
	ZetaI            string                   `json:"zeta_i"`
	VoleBobForRound2 map[string]*VOLEBobState `json:"vole_bob_for_round2"`
}

func (s *Round1State) MarshalJSON() ([]byte, error) {
	return json.Marshal(round1StateJSON{
		SigID:            s.SigID,
		Signers:          s.Signers,
		RI:               scalarToHex(&s.R_i),
		PhiI:             scalarToHex(&s.Phi_i),
		RIPoint:          hex.EncodeToString(s.R_iPoint),
		Com:              hex.EncodeToString(s.Com[:]),
		Salt:             hex.EncodeToString(s.Salt[:]),
		ZetaI:            scalarToHex(&s.ZetaI),
		VoleBobForRound2: intMapKeys(s.VoleBobForRound2),
	})
}

func (s *Round1State) UnmarshalJSON(data []byte) error {
	var j round1StateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	s.SigID = j.SigID
	s.Signers = j.Signers
	var err error
	s.R_i, err = hexToScalar(j.RI)
	if err != nil {
		return err
	}
	s.Phi_i, err = hexToScalar(j.PhiI)
	if err != nil {
		return err
	}
	s.R_iPoint, err = hex.DecodeString(j.RIPoint)
	if err != nil {
		return err
	}
	s.Com, err = hexToFixed32(j.Com)
	if err != nil {
		return err
	}
	s.Salt, err = hexToFixed32(j.Salt)
	if err != nil {
		return err
	}
	s.ZetaI, err = hexToScalar(j.ZetaI)
	if err != nil {
		return err
	}
	s.VoleBobForRound2, err = stringMapKeys(j.VoleBobForRound2)
	return err
}

// =====================================================================
// Round2State
// =====================================================================

type round2StateJSON struct {
	Round1State   *Round1State      `json:"round1_state"`
	SKI           string            `json:"sk_i"`
	CU            map[string]string `json:"c_u"`
	CV            map[string]string `json:"c_v"`
	Round1Commits map[string]string `json:"round1_commits"`
}

func (s *Round2State) MarshalJSON() ([]byte, error) {
	return json.Marshal(round2StateJSON{
		Round1State:   s.Round1State,
		SKI:           scalarToHex(&s.SK_i),
		CU:            scalarMapToHex(s.C_u),
		CV:            scalarMapToHex(s.C_v),
		Round1Commits: intMap32ToJSON(s.Round1Commits),
	})
}

func (s *Round2State) UnmarshalJSON(data []byte) error {
	var j round2StateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	s.Round1State = j.Round1State
	var err error
	s.SK_i, err = hexToScalar(j.SKI)
	if err != nil {
		return err
	}
	s.C_u, err = hexToScalarMap(j.CU)
	if err != nil {
		return err
	}
	s.C_v, err = hexToScalarMap(j.CV)
	if err != nil {
		return err
	}
	s.Round1Commits, err = jsonToIntMap32(j.Round1Commits)
	return err
}

// =====================================================================
// Round2Msg
// =====================================================================

type round2MsgJSON struct {
	Decommitment string           `json:"decommitment"`
	Salt         string           `json:"salt"`
	VoleMsg      *VOLEMultiplyMsg `json:"vole_msg"`
	GammaU       string           `json:"gamma_u"`
	GammaV       string           `json:"gamma_v"`
	Psi          string           `json:"psi"`
	PKi          string           `json:"pki"`
}

func (m *Round2Msg) MarshalJSON() ([]byte, error) {
	return json.Marshal(round2MsgJSON{
		Decommitment: hex.EncodeToString(m.Decommitment),
		Salt:         hex.EncodeToString(m.Salt[:]),
		VoleMsg:      m.VoleMsg,
		GammaU:       hex.EncodeToString(m.GammaU),
		GammaV:       hex.EncodeToString(m.GammaV),
		Psi:          hex.EncodeToString(m.Psi),
		PKi:          hex.EncodeToString(m.PKi),
	})
}

func (m *Round2Msg) UnmarshalJSON(data []byte) error {
	var j round2MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	m.Decommitment, err = hex.DecodeString(j.Decommitment)
	if err != nil {
		return err
	}
	m.Salt, err = hexToFixed32(j.Salt)
	if err != nil {
		return err
	}
	m.VoleMsg = j.VoleMsg
	m.GammaU, err = hex.DecodeString(j.GammaU)
	if err != nil {
		return err
	}
	m.GammaV, err = hex.DecodeString(j.GammaV)
	if err != nil {
		return err
	}
	m.Psi, err = hex.DecodeString(j.Psi)
	if err != nil {
		return err
	}
	m.PKi, err = hex.DecodeString(j.PKi)
	return err
}

// =====================================================================
// Round3Msg — []byte fields serialize natively as base64, but we use
// hex for consistency with the rest of the protocol messages.
// =====================================================================

type round3MsgJSON struct {
	WI string `json:"w_i"`
	UI string `json:"u_i"`
}

func (m *Round3Msg) MarshalJSON() ([]byte, error) {
	return json.Marshal(round3MsgJSON{
		WI: hex.EncodeToString(m.W_i),
		UI: hex.EncodeToString(m.U_i),
	})
}

func (m *Round3Msg) UnmarshalJSON(data []byte) error {
	var j round3MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	m.W_i, err = hex.DecodeString(j.WI)
	if err != nil {
		return err
	}
	m.U_i, err = hex.DecodeString(j.UI)
	return err
}

// =====================================================================
// RefreshRound1Output
// =====================================================================

type refreshRound1OutputJSON struct {
	FeldmanCommitments  []string          `json:"feldman_commitments"`
	PairwiseCommitments map[string]string `json:"pairwise_commitments"`
	PairwiseSalts       map[string]string `json:"pairwise_salts"`
	SeedCommitment      string            `json:"seed_commitment"`
	SeedSalt            string            `json:"seed_salt"`
}

func (o *RefreshRound1Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(refreshRound1OutputJSON{
		FeldmanCommitments:  encodeBytesSlice(o.FeldmanCommitments),
		PairwiseCommitments: intMap32ToJSON(o.PairwiseCommitments),
		PairwiseSalts:       intMap32ToJSON(o.PairwiseSalts),
		SeedCommitment:      hex.EncodeToString(o.SeedCommitment[:]),
		SeedSalt:            hex.EncodeToString(o.SeedSalt[:]),
	})
}

func (o *RefreshRound1Output) UnmarshalJSON(data []byte) error {
	var j refreshRound1OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	o.FeldmanCommitments, err = decodeBytesSlice(j.FeldmanCommitments)
	if err != nil {
		return err
	}
	o.PairwiseCommitments, err = jsonToIntMap32(j.PairwiseCommitments)
	if err != nil {
		return err
	}
	o.PairwiseSalts, err = jsonToIntMap32(j.PairwiseSalts)
	if err != nil {
		return err
	}
	o.SeedCommitment, err = hexToFixed32(j.SeedCommitment)
	if err != nil {
		return err
	}
	o.SeedSalt, err = hexToFixed32(j.SeedSalt)
	return err
}

// =====================================================================
// RefreshRound2Output
// =====================================================================

type refreshRound2OutputJSON struct {
	SecretShares map[string]string `json:"secret_shares"`
	Seed         string            `json:"seed"`
}

func (o *RefreshRound2Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(refreshRound2OutputJSON{
		SecretShares: intMapBytesToJSON(o.SecretShares),
		Seed:         hex.EncodeToString(o.Seed[:]),
	})
}

func (o *RefreshRound2Output) UnmarshalJSON(data []byte) error {
	var j refreshRound2OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	o.SecretShares, err = jsonToIntMapBytes(j.SecretShares)
	if err != nil {
		return err
	}
	o.Seed, err = hexToFixed16(j.Seed)
	return err
}

// =====================================================================
// SignerSetup — the sync.RWMutex is excluded from serialization
// =====================================================================

type signerSetupJSON struct {
	MyID        int                        `json:"my_id"`
	AllIDs      []int                      `json:"all_ids"`
	Share       string                     `json:"share"`
	PubKey      string                     `json:"pub_key"`
	Threshold   int                        `json:"threshold"`
	BaseOT      map[string]*BaseOTMaterial `json:"base_ot"`
	FZeroSeeds  map[string]string          `json:"fzero_seeds"`
	Blacklist   map[string]bool            `json:"blacklist"`
	Epoch       int                        `json:"epoch"`
	SignCounter uint64                     `json:"sign_counter"`

	// Legacy fields, decode-only. A setup written before per-session VOLE stored the
	// long-lived correlations here and did not retain the base OT they were derived
	// from, so such a blob cannot be upgraded in place — it must be re-paired. These
	// exist only so UnmarshalJSON can say that clearly instead of silently producing
	// a setup with no base OT.
	LegacyVoleAlice json.RawMessage `json:"vole_alice,omitempty"`
	LegacyVoleBob   json.RawMessage `json:"vole_bob,omitempty"`
}

// baseOTMaterialJSON hex-encodes the seed vectors, matching how every other secret in
// this file is serialized.
type baseOTMaterialJSON struct {
	BobSeeds0  []string `json:"bob_seeds0"`
	BobSeeds1  []string `json:"bob_seeds1"`
	AliceSeeds []string `json:"alice_seeds"`
	Sigma      []bool   `json:"sigma"`
}

func hexSeeds(seeds [][]byte) []string {
	out := make([]string, len(seeds))
	for i, s := range seeds {
		out[i] = hex.EncodeToString(s)
	}
	return out
}

func unhexSeeds(in []string, field string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("BaseOTMaterial.%s[%d]: %w", field, i, err)
		}
		out[i] = b
	}
	return out, nil
}

func (m *BaseOTMaterial) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseOTMaterialJSON{
		BobSeeds0:  hexSeeds(m.BobSeeds0),
		BobSeeds1:  hexSeeds(m.BobSeeds1),
		AliceSeeds: hexSeeds(m.AliceSeeds),
		Sigma:      m.Sigma,
	})
}

func (m *BaseOTMaterial) UnmarshalJSON(data []byte) error {
	var j baseOTMaterialJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	if m.BobSeeds0, err = unhexSeeds(j.BobSeeds0, "BobSeeds0"); err != nil {
		return err
	}
	if m.BobSeeds1, err = unhexSeeds(j.BobSeeds1, "BobSeeds1"); err != nil {
		return err
	}
	if m.AliceSeeds, err = unhexSeeds(j.AliceSeeds, "AliceSeeds"); err != nil {
		return err
	}
	m.Sigma = j.Sigma
	// Shape is validated on the way in, not at first use: a setup that decodes but
	// cannot sign is a much worse failure mode than one that refuses to decode.
	if len(m.BobSeeds0) != LambdaC || len(m.BobSeeds1) != LambdaC ||
		len(m.AliceSeeds) != LambdaC || len(m.Sigma) != LambdaC {
		return &CorruptStateError{
			Phase: "SignerSetup.UnmarshalJSON",
			Detail: fmt.Sprintf("base OT material has lengths %d/%d/%d/%d, want %d each",
				len(m.BobSeeds0), len(m.BobSeeds1), len(m.AliceSeeds), len(m.Sigma), LambdaC),
		}
	}
	return nil
}

func (s *SignerSetup) MarshalJSON() ([]byte, error) {
	bl := make(map[string]bool, len(s.Blacklist))
	for k, v := range s.Blacklist {
		bl[strconv.Itoa(k)] = v
	}
	return json.Marshal(signerSetupJSON{
		MyID:        s.MyID,
		AllIDs:      s.AllIDs,
		Share:       scalarToHex(&s.Share),
		PubKey:      hex.EncodeToString(s.PubKey),
		Threshold:   s.Threshold,
		BaseOT:      intMapKeys(s.BaseOT),
		FZeroSeeds:  intMap16ToJSON(s.FZeroSeeds),
		Blacklist:   bl,
		Epoch:       s.Epoch,
		SignCounter: atomic.LoadUint64(&s.SignCounter),
	})
}

func (s *SignerSetup) UnmarshalJSON(data []byte) error {
	var j signerSetupJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	s.MyID = j.MyID
	s.AllIDs = j.AllIDs
	s.Threshold = j.Threshold
	s.Epoch = j.Epoch
	atomic.StoreUint64(&s.SignCounter, j.SignCounter)

	var err error
	s.Share, err = hexToScalar(j.Share)
	if err != nil {
		return err
	}
	s.PubKey, err = hex.DecodeString(j.PubKey)
	if err != nil {
		return err
	}
	if len(j.BaseOT) == 0 && (len(j.LegacyVoleAlice) > 0 || len(j.LegacyVoleBob) > 0) {
		return &CorruptStateError{
			Phase: "SignerSetup.UnmarshalJSON",
			Detail: "setup was written before per-session VOLE and has no base OT material; " +
				"it stores a long-lived VOLE correlation, which is a key-recovery break. " +
				"Re-run pairing setup for this wallet (pairing is key-independent, so the " +
				"share, public key and address are all preserved)",
		}
	}
	s.BaseOT, err = stringMapKeys(j.BaseOT)
	if err != nil {
		return err
	}
	s.FZeroSeeds, err = jsonToIntMap16(j.FZeroSeeds)
	if err != nil {
		return err
	}
	s.Blacklist = make(map[int]bool, len(j.Blacklist))
	for k, v := range j.Blacklist {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		s.Blacklist[id] = v
	}
	return nil
}
