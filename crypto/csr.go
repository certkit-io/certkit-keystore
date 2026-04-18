package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

func GenerateCSR(sans []string, keyAlgorithm string) (csrPEM string, keyPEM string, err error) {
	var privKey crypto.Signer

	switch keyAlgorithm {
	case "EC256":
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RSA2048":
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA4096":
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return "", "", fmt.Errorf("unsupported key algorithm: %s", keyAlgorithm)
	}
	if err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}

	var cn string
	if len(sans) > 0 {
		cn = sans[0]
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return "", "", fmt.Errorf("create certificate request: %w", err)
	}

	csrBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return string(csrBlock), string(keyBlock), nil
}
