/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	xdsa "crypto/eddilithium3"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}
	return nil, false
}

func privateKeyToDER(privateKey crypto.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	switch key := privateKey.(type) {
	// Fabric supports ECDSA and ED25519 adn XDSA at the moment.
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	case *ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(*privateKey.(*ed25519.PrivateKey))
	case *xdsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(privateKey.(*xdsa.PrivateKey))
	default:
		return nil, fmt.Errorf("found unknown private key type (%T) in marshaling", key)
	}
}

func privateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return privateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("invalid key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa private key. It must be different from nil")
		}

		// get the oid for the curve
		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
		// omit NamedCurveOID for compatibility as it's optional
		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
		}

		var pkcs8Key pkcs8Info
		pkcs8Key.Version = 0
		pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil
	case *ed25519.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid ed25519 private key. It must be different from nil")
		}

		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(*k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ED key to asn1: [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil

	case *xdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid xdsa private key. It must be different from nil")
		}

		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ED key to asn1: [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil

	case *rsa.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid rsa private key. It must be different from nil")
		}
		raw := x509.MarshalPKCS1PrivateKey(k)

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: raw,
			},
		), nil

	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PrivateKey, *ed25519.PrivateKey, *xdsa.PrivateKey or *rsa.PrivateKey")
	}
}

func privateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa private key. It must be different from nil")
		}
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	case *ed25519.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid ed25519 private key. It must be different from nil")
		}
		raw, err := x509.MarshalPKCS8PrivateKey(*k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	case *xdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid xdsa private key. It must be different from nil")
		}
		raw, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PrivateKey, *xdsa.PrivateKey or *ed25519.PrivateKey")
	}
}

func derToPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return
		case ed25519.PrivateKey:
			return
		case *xdsa.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey, xdsa.PrivateKey or an ed25519.PrivateKey")
}

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func pemToAES(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different fom nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

func aesToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

func aesToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return aesToPEM(raw), nil
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"AES PRIVATE KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

func publicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return publicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa public key. It must be different from nil")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil
	case *ed25519.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ed25519 public key. It must be different from nil")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(*k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	case *xdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid xdsa public key. It must be different from nil")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid rsa public key. It must be different from nil")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PublicKey, *xdsa.PublicKey,  *ed25519.PublicKey or *rsa.PublicKey")
	}
}

func publicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa public key. It must be different from nil")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	case *ed25519.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ed25519 public key. It must be different from nil")
		}
		raw, err := x509.MarshalPKIXPublicKey(*k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	case *xdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid xdsa public key. It must be different from nil")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PublicKey, *xdsa.PublicKey or *ed25519.PublicKey")
	}
}

func pemToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding. Block must be different from nil [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different from nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToPublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER. It must be different from nil")
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}
