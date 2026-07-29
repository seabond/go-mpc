package dkls23

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// testEncryptor implements SetupEncryptor using AES-256-GCM.
type testEncryptor struct {
	key []byte // 32 bytes
}

func newTestEncryptor() *testEncryptor {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &testEncryptor{key: key}
}

func (e *testEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *testEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

func TestMarshalUnmarshalSetup(t *testing.T) {
	setups := fullSetup(t)
	for id, s := range setups {
		data, err := MarshalSetup(s)
		require.NoError(t, err, "party %d marshal", id)
		require.NotEmpty(t, data)

		got, err := UnmarshalSetup(data)
		require.NoError(t, err, "party %d unmarshal", id)
		require.Equal(t, s.MyID, got.MyID)
		require.True(t, s.Share.Equals(&got.Share), "party %d share", id)
		require.Equal(t, s.PubKey, got.PubKey)
		require.Equal(t, s.Threshold, got.Threshold)
		require.Equal(t, s.Epoch, got.Epoch)
		require.Equal(t, len(s.BaseOT), len(got.BaseOT))
		for peer, want := range s.BaseOT {
			gotMat := got.BaseOT[peer]
			require.NotNil(t, gotMat, "party %d BaseOT[%d]", id, peer)
			require.Equal(t, want.BobSeeds0, gotMat.BobSeeds0)
			require.Equal(t, want.AliceSeeds, gotMat.AliceSeeds)
			require.Equal(t, want.Sigma, gotMat.Sigma)
		}
		require.Equal(t, len(s.FZeroSeeds), len(got.FZeroSeeds))
	}
}

func TestMarshalEncryptedRoundTrip(t *testing.T) {
	setups := fullSetup(t)
	enc := newTestEncryptor()

	for id, s := range setups {
		ct, err := MarshalEncrypted(s, enc)
		require.NoError(t, err, "party %d encrypt", id)
		require.NotEmpty(t, ct)

		got, err := UnmarshalEncrypted(ct, enc)
		require.NoError(t, err, "party %d decrypt", id)
		require.Equal(t, s.MyID, got.MyID)
		require.True(t, s.Share.Equals(&got.Share))
		require.Equal(t, s.PubKey, got.PubKey)
	}
}

func TestUnmarshalEncryptedWrongKey(t *testing.T) {
	setups := fullSetup(t)
	enc1 := newTestEncryptor()
	enc2 := newTestEncryptor()

	ct, err := MarshalEncrypted(setups[1], enc1)
	require.NoError(t, err)

	_, err = UnmarshalEncrypted(ct, enc2)
	require.Error(t, err, "decrypting with wrong key should fail")
}

func TestUnmarshalSetupBadJSON(t *testing.T) {
	_, err := UnmarshalSetup([]byte("not json"))
	require.Error(t, err)
}

func TestMarshalEncryptedEncryptError(t *testing.T) {
	setups := fullSetup(t)
	_, err := MarshalEncrypted(setups[1], &failingEncryptor{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "encrypt")
}

func TestUnmarshalEncryptedDecryptError(t *testing.T) {
	_, err := UnmarshalEncrypted([]byte("data"), &failingEncryptor{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "decrypt")
}

func TestMarshalEncryptedFunctional(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	enc := newTestEncryptor()

	// Encrypt, decrypt, then sign with the restored setup
	restored := make(map[int]*SignerSetup)
	for id, s := range setups {
		ct, err := MarshalEncrypted(s, enc)
		require.NoError(t, err)
		r, err := UnmarshalEncrypted(ct, enc)
		require.NoError(t, err)
		restored[id] = r
	}

	// Sign with restored setups
	msg := []byte("encrypted persistence test")
	sigID := "enc-persist-sig"
	signers := []int{1, 2, 3}

	r1s := map[int]*Round1State{}
	r1m := map[int]map[int]*Round1Msg{}
	for _, id := range signers {
		st, msgs, err := SignRound1(restored[id], sigID, signers)
		require.NoError(t, err)
		r1s[id] = st
		r1m[id] = msgs
	}
	r2s := map[int]*Round2State{}
	r2m := map[int]map[int]*Round2Msg{}
	for _, id := range signers {
		in := map[int]*Round1Msg{}
		for _, j := range signers {
			if j != id {
				in[j] = r1m[j][id]
			}
		}
		st, msgs, err := SignRound2(restored[id], r1s[id], in)
		require.NoError(t, err)
		r2s[id] = st
		r2m[id] = msgs
	}
	r3f := map[int]map[int]*Round3Msg{}
	for _, id := range signers {
		in := map[int]*Round2Msg{}
		for _, j := range signers {
			if j != id {
				in[j] = r2m[j][id]
			}
		}
		frags, err := SignRound3(restored[id], r2s[id], msg, in)
		require.NoError(t, err)
		r3f[id] = frags
	}
	rx := computeRxFromStates(signers, r2s)
	myFrag := r3f[1][1]
	allFrags := map[int]*Round3Msg{}
	for _, j := range signers {
		if j != 1 {
			allFrags[j] = r3f[j][1]
		}
	}
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)
	r, s, err := SignCombine(restored[1], &rx, &myW, &myU, allFrags, msg)
	require.NoError(t, err)
	require.NotEmpty(t, r)
	require.NotEmpty(t, s)
	t.Logf("Sign after encrypted persistence succeeded: r=%x", r[:4])
}
