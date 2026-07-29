package dkls23

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOTExtension(t *testing.T) {
	t.Parallel()
	// Step 1: Base OT setup (Bob as sender, Alice as receiver).
	// Bob generates base OT key pairs.
	privKeys, bobPubKeys, err := BaseSenderRound1(LambdaC)
	require.NoError(t, err)

	// Alice generates random sigma (her OTE role: base OT receiver choices).
	sigmaBytes := make([]byte, (LambdaC+7)/8)
	_, err = rand.Read(sigmaBytes)
	require.NoError(t, err)
	sigma := make([]bool, LambdaC)
	for k := 0; k < LambdaC; k++ {
		sigma[k] = (sigmaBytes[k/8]>>(uint(k)%8))&1 == 1
	}

	// Alice computes base OT receiver messages.
	responses, aliceSeeds, err := BaseReceiverRound1(bobPubKeys, sigma)
	require.NoError(t, err)

	// Bob finalizes base OT to get seed pairs.
	bobSeeds0, bobSeeds1, err := BaseSenderFinalize(privKeys, bobPubKeys, responses)
	require.NoError(t, err)

	// Step 2: Bob's OTE input: random beta ∈ {0,1}^Xi.
	betaBytes := make([]byte, (Xi+7)/8)
	_, err = rand.Read(betaBytes)
	require.NoError(t, err)
	var beta [Xi]bool
	for j := 0; j < Xi; j++ {
		beta[j] = (betaBytes[j/8]>>(uint(j)%8))&1 == 1
	}

	// Step 3: Bob computes corrections and sends to Alice.
	corrections, correctionsProof, err := OTExtReceiverCorrections(testSID, bobSeeds0, bobSeeds1, beta)
	require.NoError(t, err)

	// Step 4: Alice expands sender OTE output.
	alpha0, alpha1, err := OTExtSenderExpand(testSID, aliceSeeds, sigma, corrections, correctionsProof)
	require.NoError(t, err)

	// Step 5: Bob expands receiver OTE output.
	gamma, err := OTExtReceiverExpand(testSID, bobSeeds0, beta, corrections)
	require.NoError(t, err)

	// Verify OTE correctness: gamma[j][i] == alpha{beta[j]}[j][i] for all j, i.
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			if beta[j] {
				require.Equal(t, alpha1[j][i], gamma[j][i],
					"OTE mismatch at j=%d i=%d (beta=true)", j, i)
			} else {
				require.Equal(t, alpha0[j][i], gamma[j][i],
					"OTE mismatch at j=%d i=%d (beta=false)", j, i)
			}
		}
	}
}
