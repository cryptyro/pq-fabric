/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

const (
	// ECDSA Elliptic Curve Digital Signature Algorithm (key gen, import, sign, verify),
	// at default security level.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	ECDSA = "ECDSA"

	// ECDSAP256 Elliptic Curve Digital Signature Algorithm over P-256 curve
	ECDSAP256 = "ECDSAP256"

	// ECDSAP384 Elliptic Curve Digital Signature Algorithm over P-384 curve
	ECDSAP384 = "ECDSAP384"

	// ECDSAReRand ECDSA key re-randomization
	ECDSAReRand = "ECDSA_RERAND"

	// ED25519 Algorithm
	ED25519 = "ED25519"

	//Hybrid Signature Algorithm
	XDSA = "XDSA"

	// RSA at the default security level.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	RSA = "RSA"
	// RSA at 1024 bit security level.
	RSA1024 = "RSA1024"
	// RSA at 2048 bit security level.
	RSA2048 = "RSA2048"
	// RSA at 3072 bit security level.
	RSA3072 = "RSA3072"
	// RSA at 4096 bit security level.
	RSA4096 = "RSA4096"

	// AES Advanced Encryption Standard at the default security level.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	AES = "AES"
	// AES128 Advanced Encryption Standard at 128 bit security level
	AES128 = "AES128"
	// AES192 Advanced Encryption Standard at 192 bit security level
	AES192 = "AES192"
	// AES256 Advanced Encryption Standard at 256 bit security level
	AES256 = "AES256"

	// HMAC keyed-hash message authentication code
	HMAC = "HMAC"
	// HMACTruncated256 HMAC truncated at 256 bits.
	HMACTruncated256 = "HMAC_TRUNCATED_256"

	// SHA Secure Hash Algorithm using default family.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	SHA = "SHA"

	// SHA2 is an identifier for SHA2 hash family
	SHA2 = "SHA2"
	// SHA3 is an identifier for SHA3 hash family
	SHA3 = "SHA3"

	// SHA256
	SHA256 = "SHA256"
	// SHA384
	SHA384 = "SHA384"
	// SHA3_256
	SHA3_256 = "SHA3_256"
	// SHA3_384
	SHA3_384 = "SHA3_384"

	// X509Certificate Label for X509 certificate related operation
	X509Certificate = "X509Certificate"
)

// ECDSAKeyGenOpts contains options for ECDSA key generation.
type ECDSAKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type ED25519KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *ED25519KeyGenOpts) Algorithm() string {
	return ED25519
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ED25519KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type XDSAKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *XDSAKeyGenOpts) Algorithm() string {
	return XDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *XDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAPKIXPublicKeyImportOpts contains options for ECDSA public key importation in PKIX format
type ECDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAPrivateKeyImportOpts contains options for ECDSA secret key importation in DER format
// or PKCS#8 format.
type ECDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAGoPublicKeyImportOpts contains options for ECDSA key importation from ecdsa.PublicKey
type ECDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAGoPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ED25519PrivateKeyImportOpts contains options for ED25519 key importation from ed25519.PublicKey
type ED25519PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ED25519PrivateKeyImportOpts) Algorithm() string {
	return ED25519
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ED25519PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ED25519GoPublicKeyImportOpts contains options for ED25519 key importation from ed25519.PublicKey
type ED25519GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ED25519GoPublicKeyImportOpts) Algorithm() string {
	return ED25519
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ED25519GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// XDSAPrivateKeyImportOpts contains options for XDSA key importation from XDSA.PublicKey
type XDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *XDSAPrivateKeyImportOpts) Algorithm() string {
	return XDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *XDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// XDSAGoPublicKeyImportOpts contains options for XDSA key importation from XDSA.PublicKey
type XDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *XDSAGoPublicKeyImportOpts) Algorithm() string {
	return XDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *XDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAReRandKeyOpts contains options for ECDSA key re-randomization.
type ECDSAReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *ECDSAReRandKeyOpts) Algorithm() string {
	return ECDSAReRand
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *ECDSAReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

// AESKeyGenOpts contains options for AES key generation at default security level
type AESKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *AESKeyGenOpts) Algorithm() string {
	return AES
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *AESKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// HMACTruncated256AESDeriveKeyOpts contains options for HMAC truncated
// at 256 bits key derivation.
type HMACTruncated256AESDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACTruncated256AESDeriveKeyOpts) Algorithm() string {
	return HMACTruncated256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256AESDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256AESDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

// HMACDeriveKeyOpts contains options for HMAC key derivation.
type HMACDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACDeriveKeyOpts) Algorithm() string {
	return HMAC
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

// AES256ImportKeyOpts contains options for importing AES 256 keys.
type AES256ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *AES256ImportKeyOpts) Algorithm() string {
	return AES
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *AES256ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// HMACImportKeyOpts contains options for importing HMAC keys.
type HMACImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *HMACImportKeyOpts) Algorithm() string {
	return HMAC
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *HMACImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// SHAOpts contains options for computing SHA.
type SHAOpts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHAOpts) Algorithm() string {
	return SHA
}

// RSAKeyGenOpts contains options for RSA key generation.
type RSAKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *RSAKeyGenOpts) Algorithm() string {
	return RSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *RSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// RSAGoPublicKeyImportOpts contains options for RSA key importation from rsa.PublicKey
type RSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *RSAGoPublicKeyImportOpts) Algorithm() string {
	return RSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *RSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// X509PublicKeyImportOpts contains options for importing public keys from an x509 certificate
type X509PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *X509PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
