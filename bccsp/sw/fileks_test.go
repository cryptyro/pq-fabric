/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ed25519"
	xdsa "crypto/eddilithium3"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		t.Fatalf("Failed initiliazing KeyStore [%s]", err)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ecdsaPrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ecdsaPublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ed25519PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&ed25519PublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&xdsaPrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&xdsaPublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&aesPrivateKey{nil, false})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&aesPrivateKey{nil, true})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestBigKeyFile(t *testing.T) {
	ksPath := t.TempDir()

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	require.NoError(t, err)

	// Generate a key for keystore to find
	_, privKey, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cspKey := &xdsaPrivateKey{privKey}
	ski := cspKey.SKI()
	rawKey, err := privateKeyToPEM(privKey, nil)
	require.NoError(t, err)

	// Large padding array, of some values PEM parser will NOOP
	bigBuff := make([]byte, 1<<17)
	for i := range bigBuff {
		bigBuff[i] = '\n'
	}
	copy(bigBuff, rawKey)

	// >64k, so that total file size will be too big
	os.WriteFile(filepath.Join(ksPath, "bigfile.pem"), bigBuff, 0o666)

	_, err = ks.GetKey(ski)
	require.Error(t, err)
	expected := fmt.Sprintf("key with SKI %x not found in %s", ski, ksPath)
	require.EqualError(t, err, expected)

	// 1k, so that the key would be found
	os.WriteFile(filepath.Join(ksPath, "smallerfile.pem"), bigBuff[0:1<<13], 0o666)

	_, err = ks.GetKey(ski)
	require.NoError(t, err)
}

func TestReInitKeyStore(t *testing.T) {
	ksPath := t.TempDir()

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	require.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedKeyStore)
	require.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	require.EqualError(t, err, "keystore is already initialized")
}

func TestDirExists(t *testing.T) {
	r, err := dirExists("")
	require.False(t, r)
	require.NoError(t, err)

	r, err = dirExists(os.TempDir())
	require.NoError(t, err)
	require.Equal(t, true, r)

	r, err = dirExists(filepath.Join(os.TempDir(), "7rhf90239vhev90"))
	require.NoError(t, err)
	require.Equal(t, false, r)
}

func TestDirEmpty(t *testing.T) {
	_, err := dirEmpty("")
	require.Error(t, err)

	path := filepath.Join(os.TempDir(), "7rhf90239vhev90")
	defer os.Remove(path)
	os.Mkdir(path, os.ModePerm)

	r, err := dirEmpty(path)
	require.NoError(t, err)
	require.Equal(t, true, r)

	r, err = dirEmpty(os.TempDir())
	require.NoError(t, err)
	require.Equal(t, false, r)
}

func TestStoreAndGetEd25519Keys(t *testing.T) {
	ksPath, err := os.MkdirTemp("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	require.NoError(t, err)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ed25519FabricPriv := &ed25519PrivateKey{privKey: &priv}
	ed25519FabricPub := &ed25519PublicKey{pubKey: &pub}

	err = ks.StoreKey(ed25519FabricPriv)
	require.NoError(t, err)
	_, err = ks.GetKey(ed25519FabricPriv.SKI())
	require.NoError(t, err)

	err = ks.StoreKey(ed25519FabricPub)
	require.NoError(t, err)
	_, err = ks.GetKey(ed25519FabricPub.SKI())
	require.NoError(t, err)
}

func TestStoreAndGetXDSAKeys(t *testing.T) {
	ksPath, err := os.MkdirTemp("", "bccspks")
	require.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	require.NoError(t, err)

	pub, priv, err := xdsa.GenerateKey(rand.Reader)
	require.NoError(t, err)

	xdsaFabricPriv := &xdsaPrivateKey{privKey: priv}
	xdsaFabricPub := &xdsaPublicKey{pubKey: pub}

	err = ks.StoreKey(xdsaFabricPriv)
	require.NoError(t, err)
	_, err = ks.GetKey(xdsaFabricPriv.SKI())
	require.NoError(t, err)

	err = ks.StoreKey(xdsaFabricPub)
	require.NoError(t, err)
	_, err = ks.GetKey(xdsaFabricPub.SKI())
	require.NoError(t, err)
}
