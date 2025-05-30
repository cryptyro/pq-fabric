/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	xdsa "crypto/eddilithium3"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOidFromNamedCurve(t *testing.T) {
	var (
		oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
		oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
		oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
		oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	)

	type result struct {
		oid asn1.ObjectIdentifier
		ok  bool
	}

	tests := []struct {
		name     string
		curve    elliptic.Curve
		expected result
	}{
		{
			name:  "P224",
			curve: elliptic.P224(),
			expected: result{
				oid: oidNamedCurveP224,
				ok:  true,
			},
		},
		{
			name:  "P256",
			curve: elliptic.P256(),
			expected: result{
				oid: oidNamedCurveP256,
				ok:  true,
			},
		},
		{
			name:  "P384",
			curve: elliptic.P384(),
			expected: result{
				oid: oidNamedCurveP384,
				ok:  true,
			},
		},
		{
			name:  "P521",
			curve: elliptic.P521(),
			expected: result{
				oid: oidNamedCurveP521,
				ok:  true,
			},
		},
		{
			name:  "T-1000",
			curve: &elliptic.CurveParams{Name: "T-1000"},
			expected: result{
				oid: nil,
				ok:  false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oid, ok := oidFromNamedCurve(test.curve)
			require.Equal(t, oid, test.expected.oid)
			require.Equal(t, ok, test.expected.ok)
		})
	}
}

func TestECDSAKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Private Key DER format
	der, err := privateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	keyFromDER, err := derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromDer := keyFromDER.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromDer.D) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromDer.X) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromDer.Y) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid Y coordinate.")
	}

	// Private Key PEM format
	rawPEM, err := privateKeyToPEM(key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	keyFromPEM, err := pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromPEM := keyFromPEM.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromPEM.D) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Private Key <-> PEM
	_, err = privateKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = privateKeyToPEM((*ecdsa.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	_, err = pemToPrivateKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPrivateKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail invalid PEM")
	}

	_, err = derToPrivateKey(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	_, err = derToPrivateKey([]byte{0, 1, 3, 4})
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on invalid DER")
	}

	_, err = privateKeyToDER(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	// Private Key Encrypted PEM format
	encPEM, err := privateKeyToPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	require.Error(t, err)
	encKeyFromPEM, err := pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromEncPEM := encKeyFromPEM.(*ecdsa.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromEncPEM.D) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	// Public Key PEM format
	rawPEM, err = publicKeyToPEM(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	keyFromPEM, err = pemToPublicKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}
	ecdsaPkFromPEM := keyFromPEM.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Public Key <-> PEM
	_, err = publicKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = pemToPublicKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	// Public Key Encrypted PEM format
	encPEM, err = publicKeyToPEM(&key.PublicKey, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPublicKey(encPEM, nil)
	require.Error(t, err)
	pkFromEncPEM, err := pemToPublicKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaPkFromEncPEM := pkFromEncPEM.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on wrong password")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil password")
	}

	_, err = pemToPublicKey(nil, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	_, err = pemToPublicKey(nil, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM and wrong password")
	}

	// Public Key DER format
	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	keyFromDER, err = derToPublicKey(der)
	require.NoError(t, err)
	ecdsaPkFromPEM = keyFromDER.(*ecdsa.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}
}

func TestED25519Keys(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating ED25519 key [%s]", err)
	}

	// Private Key DER format
	der, err := privateKeyToDER(&key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	_, err = derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	rawPEM, err := privateKeyToPEM(&key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	_, err = pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	_, err = privateKeyToPEM((ed25519.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	encPEM, err := privateKeyToPEM(&key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	require.Error(t, err)
	_, err = pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	// Public Key PEM format
	rawPEM, err = publicKeyToPEM(&pub, nil)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	_, err = pemToPublicKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}

	// Public Key Encrypted PEM format
	encPEM, err = publicKeyToPEM(&pub, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPublicKey(encPEM, nil)
	require.Error(t, err)
	_, err = pemToPublicKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on wrong password")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil password")
	}

	// Public Key DER format
	der, err = x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	_, err = derToPublicKey(der)
	require.NoError(t, err)
}

func TestXDSAKeys(t *testing.T) {
	pub, key, err := xdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating xdsa key [%s]", err)
	}

	// Private Key DER format
	der, err := privateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	_, err = derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	rawPEM, err := privateKeyToPEM(key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	_, err = pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	_, err = privateKeyToPEM((*xdsa.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	encPEM, err := privateKeyToPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	require.Error(t, err)
	_, err = pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	// Public Key PEM format
	rawPEM, err = publicKeyToPEM(pub, nil)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	_, err = pemToPublicKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}

	// Public Key Encrypted PEM format
	encPEM, err = publicKeyToPEM(pub, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPublicKey(encPEM, nil)
	require.Error(t, err)
	_, err = pemToPublicKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on wrong password")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil password")
	}

	// Public Key DER format
	der, err = x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	_, err = derToPublicKey(der)
	require.NoError(t, err)
}

func TestAESKey(t *testing.T) {
	k := []byte{0, 1, 2, 3, 4, 5}
	pem := aesToPEM(k)

	k2, err := pemToAES(pem, nil)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	pem, err = aesToEncryptedPEM(k, k)
	require.NoError(t, err)

	k2, err = pemToAES(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)

	_, err = pemToAES(pem, nil)
	require.Error(t, err)

	_, err = aesToEncryptedPEM(k, nil)
	require.NoError(t, err)

	k2, err = pemToAES(pem, k)
	require.NoError(t, err)
	require.Equal(t, k, k2)
}

func TestDERToPublicKey(t *testing.T) {
	_, err := derToPublicKey(nil)
	require.Error(t, err)
}

func TestNil(t *testing.T) {
	_, err := privateKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = privateKeyToEncryptedPEM((*ecdsa.PrivateKey)(nil), nil)
	require.Error(t, err)
	_, err = privateKeyToEncryptedPEM((ed25519.PrivateKey)(nil), nil)
	require.Error(t, err)

	_, err = privateKeyToEncryptedPEM("Hello World", nil)
	require.Error(t, err)

	_, err = pemToAES(nil, nil)
	require.Error(t, err)

	_, err = aesToEncryptedPEM(nil, nil)
	require.Error(t, err)

	_, err = publicKeyToPEM(nil, nil)
	require.Error(t, err)
	_, err = publicKeyToPEM((*ecdsa.PublicKey)(nil), nil)
	require.Error(t, err)
	_, err = publicKeyToPEM((ed25519.PublicKey)(nil), nil)
	require.Error(t, err)
	_, err = publicKeyToPEM(nil, []byte("hello world"))
	require.Error(t, err)

	_, err = publicKeyToPEM("hello world", nil)
	require.Error(t, err)
	_, err = publicKeyToPEM("hello world", []byte("hello world"))
	require.Error(t, err)

	_, err = publicKeyToEncryptedPEM(nil, nil)
	require.Error(t, err)
	_, err = publicKeyToEncryptedPEM((*ecdsa.PublicKey)(nil), nil)
	require.Error(t, err)
	_, err = publicKeyToEncryptedPEM("hello world", nil)
	require.Error(t, err)
	_, err = publicKeyToEncryptedPEM("hello world", []byte("Hello world"))
	require.Error(t, err)
}
