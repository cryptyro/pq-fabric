//go:build ignore
// +build ignore

/*
Ommit the above two lines and use "go generate" to generate the test certificates
*/

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate -command gencerts go run ./generate.go
//go:generate gencerts -orgs 2 -child-orgs 2 -servers 2 -clients 2

package main

import (
	xdsa "crypto/eddilithium3"
	//"crypto/ecdsa"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// command line flags
var (
	numOrgs        = flag.Int("orgs", 2, "number of unique organizations")
	numChildOrgs   = flag.Int("child-orgs", 2, "number of intermediaries per organization")
	numClientCerts = flag.Int("clients", 1, "number of client certificates per organization")
	numServerCerts = flag.Int("servers", 1, "number of server certificates per organization")
)

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// default template for X509 certificates
func x509Template() (x509.Certificate, error) {
	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return x509.Certificate{}, err
	}

	now := time.Now()
	// basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour), //~ten years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	return x509, nil
}

// generate an EC private key (P256 curve)
func genKeyXDSA(name string) (*xdsa.PrivateKey, error) {
	_, priv, err := xdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// write key out to file
	keyBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	keyFile, err := os.OpenFile(name+"-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// generate a signed X509 certficate using XDSA
func genCertificateXDSA(
	name string,
	template, parent *x509.Certificate,
	pub *xdsa.PublicKey, priv *xdsa.PrivateKey,
) (*x509.Certificate, error) {
	// create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	// write cert out to file
	certFile, err := os.Create(name + "-cert.pem")
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	// pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}

// generate an EC certificate appropriate for use by a TLS server
func genServerCertificateXDSA(name string, signKey *xdsa.PrivateKey, signCert *x509.Certificate) error {
	fmt.Println(name)

	key, err := genKeyXDSA(name)
	if err != nil {
		return err
	}
	template, err := x509Template()
	if err != nil {
		return err
	}

	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}

	// set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = "localhost"

	template.Subject = subject
	template.DNSNames = []string{"localhost"}
	template.IPAddresses = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	_, err = genCertificateXDSA(name, &template, signCert, key.Public().(*xdsa.PublicKey), signKey)
	if err != nil {
		return err
	}

	return nil
}

// generate an EC certificate appropriate for use by a TLS server
func genClientCertificateXDSA(name string, signKey *xdsa.PrivateKey, signCert *x509.Certificate) error {
	fmt.Println(name)

	key, err := genKeyXDSA(name)
	if err != nil {
		return err
	}
	template, err := x509Template()
	if err != nil {
		return err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name
	template.Subject = subject

	_, err = genCertificateXDSA(name, &template, signCert, key.Public().(*xdsa.PublicKey), signKey)
	if err != nil {
		return err
	}

	return nil
}

// generate an EC certificate signing(CA) key pair and output as
// PEM-encoded files
func genCertificateAuthorityXDSA(name string) (*xdsa.PrivateKey, *x509.Certificate, error) {
	key, err := genKeyXDSA(name)
	if err != nil {
		return nil, nil, err
	}
	template, err := x509Template()
	if err != nil {
		return nil, nil, err
	}

	// this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	// set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	x509Cert, err := genCertificateXDSA(name, &template, &template, key.Public().(*xdsa.PublicKey), key)
	if err != nil {
		return nil, nil, err
	}
	return key, x509Cert, nil
}

// generate an EC certificate appropriate for use by a TLS server
func genIntermediateCertificateAuthorityXDSA(
	name string,
	signKey *xdsa.PrivateKey,
	signCert *x509.Certificate,
) (*xdsa.PrivateKey, *x509.Certificate, error) {
	fmt.Println(name)

	key, err := genKeyXDSA(name)
	if err != nil {
		return nil, nil, err
	}
	template, err := x509Template()
	if err != nil {
		return nil, nil, err
	}

	// this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	// set the organization for the subject
	subject := subjectTemplate()
	subject.Organization = []string{name}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = []byte{1, 2, 3, 4}

	x509Cert, err := genCertificateXDSA(name, &template, signCert, key.Public().(*xdsa.PublicKey), signKey)
	if err != nil {
		return nil, nil, err
	}

	return key, x509Cert, nil
}

const baseOrgName = "Org"

func main() {
	flag.Parse()
	fmt.Printf("Generating %d organizations each with %d server(s) and %d client(s)\n", *numOrgs, *numServerCerts, *numClientCerts)

	// generate orgs / CAs
	for i := 1; i <= *numOrgs; i++ {
		signKey, signCert, err := genCertificateAuthorityXDSA(fmt.Sprintf(baseOrgName+"%d", i))
		if err != nil {
			fmt.Printf("error generating CA %s%d : %s\n", baseOrgName, i, err.Error())
		}
		// generate server certificates for the org
		for j := 1; j <= *numServerCerts; j++ {
			name := fmt.Sprintf(baseOrgName+"%d-server%d", i, j)
			if err := genServerCertificateXDSA(name, signKey, signCert); err != nil {
				fmt.Printf("error generating server certificate for %s: %s\n", name, err.Error())
			}
		}
		// generate client certificates for the org
		for k := 1; k <= *numClientCerts; k++ {
			name := fmt.Sprintf(baseOrgName+"%d-client%d", i, k)
			if err := genClientCertificateXDSA(name, signKey, signCert); err != nil {
				fmt.Printf("error generating client certificate for %s: %s\n", name, err.Error())
			}
		}
		// generate child orgs (intermediary authorities)
		for m := 1; m <= *numChildOrgs; m++ {
			name := fmt.Sprintf(baseOrgName+"%d-child%d", i, m)
			childSignKey, childSignCert, err := genIntermediateCertificateAuthorityXDSA(name, signKey, signCert)
			if err != nil {
				fmt.Printf("error generating CA %s: %s\n", name, err.Error())
			}
			// generate server certificates for the child org
			for n := 1; n <= *numServerCerts; n++ {
				name := fmt.Sprintf(baseOrgName+"%d-child%d-server%d", i, m, n)
				if err := genServerCertificateXDSA(name, childSignKey, childSignCert); err != nil {
					fmt.Printf("error generating server certificate for %s: %s\n", name, err.Error())
				}
			}
			// generate client certificates for the child org
			for p := 1; p <= *numClientCerts; p++ {
				name := fmt.Sprintf(baseOrgName+"%d-child%d-client%d", i, m, p)
				if err := genClientCertificateXDSA(name, childSignKey, childSignCert); err != nil {
					fmt.Printf("error generating server certificate for %s: %s\n", name, err.Error())
				}
			}
		}
	}
}
