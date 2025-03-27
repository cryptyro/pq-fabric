/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	xdsa "crypto/eddilithium3"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyXDSA(t *testing.T) {
	t.Parallel()

	// Generate a key
	_, lowLevelKey, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signXDSA(lowLevelKey, msg, nil)
	require.NoError(t, err)

	castedKey, _ := lowLevelKey.Public().(*xdsa.PublicKey)
	valid, err := verifyXDSA(castedKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestXdsaSignerSign(t *testing.T) {
	t.Parallel()

	signer := &xdsaSigner{}
	verifierPrivateKey := &xdsaPrivateKeyVerifier{}
	verifierPublicKey := &xdsaPublicKeyKeyVerifier{}

	// Generate a key
	_, lowLevelKey, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k := &xdsaPrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	require.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	require.NoError(t, err)
	require.NotNil(t, sigma)

	// Verify
	castedKey, _ := lowLevelKey.Public().(*xdsa.PublicKey)
	valid, err := verifyXDSA(castedKey, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestXdsaPrivateKey(t *testing.T) {
	t.Parallel()

	pub, lowLevelKey, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)
	k := &xdsaPrivateKey{lowLevelKey}

	require.False(t, k.Symmetric())
	require.True(t, k.Private())

	_, err = k.Bytes()
	require.NoError(t, err)

	k.privKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	raw, _ := (pub).MarshalBinary()
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
	xdsaPK, ok := pk.(*xdsaPublicKey)
	require.True(t, ok)
	castedKey, _ := lowLevelKey.Public().(*xdsa.PublicKey)
	require.Equal(t, castedKey, xdsaPK.pubKey)
}

func TestXdsaPublicKey(t *testing.T) {
	t.Parallel()

	pub, lowLevelKey, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)
	castedKey, _ := lowLevelKey.Public().(*xdsa.PublicKey)
	k := &xdsaPublicKey{castedKey}

	require.False(t, k.Symmetric())
	require.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	require.Nil(t, ski)

	k.pubKey = castedKey
	ski = k.SKI()
	raw, _ := pub.MarshalBinary()
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	require.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	require.NoError(t, err)
	require.Equal(t, k, pk)

	bytes, err := k.Bytes()
	require.NoError(t, err)
	bytes2, err := k.pubKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")
}
