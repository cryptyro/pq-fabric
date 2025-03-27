/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	xdsa "crypto/eddilithium3"
	"crypto/rand"

	"github.com/hyperledger/fabric/bccsp"
)

func signXDSA(k *xdsa.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sign(rand.Reader, msg, opts)
}

func verifyXDSA(k *xdsa.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return xdsa.Verify(k, msg, signature), nil
}

type xdsaSigner struct{}

func (s *xdsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	key := k.(*xdsaPrivateKey)
	return signXDSA(key.privKey, msg, opts)
}

type xdsaPrivateKeyVerifier struct{}

func (v *xdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	castedKey, _ := (k.(*xdsaPrivateKey).privKey.Public()).(*xdsa.PublicKey)
	return verifyXDSA(castedKey, signature, msg, opts)
}

type xdsaPublicKeyKeyVerifier struct{}

func (v *xdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyXDSA(k.(*xdsaPublicKey).pubKey, signature, msg, opts)
}
