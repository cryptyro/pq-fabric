/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	xdsa "crypto/eddilithium3"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
)

type xdsaPrivateKey struct {
	privKey *xdsa.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *xdsaPrivateKey) Bytes() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(k.privKey) //(k.privKey).MarshalBinary()
}

// SKI returns the subject key identifier of this key.
func (k *xdsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	pub := k.privKey.Public().(*xdsa.PublicKey)
	raw, err := pub.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal the private key")
		return nil
	}

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *xdsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *xdsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *xdsaPrivateKey) PublicKey() (bccsp.Key, error) {
	castedKey, ok := k.privKey.Public().(*xdsa.PublicKey)
	if !ok {
		return nil, errors.New("Error casting xdsa public key")
	}
	return &xdsaPublicKey{castedKey}, nil
}

type xdsaPublicKey struct {
	pubKey *xdsa.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *xdsaPublicKey) Bytes() (raw []byte, err error) {
	return x509.MarshalPKIXPublicKey(k.pubKey) //(k.pubKey).MarshalBinary()
}

// SKI returns the subject key identifier of this key.
func (k *xdsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw, err := (k.pubKey).MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal the public key")
		return nil
	}
	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *xdsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *xdsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *xdsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
