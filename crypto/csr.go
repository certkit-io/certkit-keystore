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

type KeyAlgorithm string

const (
	KeyAlgorithmEC256   KeyAlgorithm = "EC256"
	KeyAlgorithmEC384   KeyAlgorithm = "EC384"
	KeyAlgorithmRSA2048 KeyAlgorithm = "RSA2048"
	KeyAlgorithmRSA4096 KeyAlgorithm = "RSA4096"
)

// GeneratePrivateKey creates a private key with the given algorithm.
func GeneratePrivateKey(keyAlgorithm KeyAlgorithm) (crypto.Signer, error) {
	var privKey crypto.Signer
	var err error

	switch keyAlgorithm {
	case KeyAlgorithmEC256:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyAlgorithmEC384:
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyAlgorithmRSA2048:
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyAlgorithmRSA4096:
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", keyAlgorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return privKey, nil
}

// KeyAlgorithmOf names the algorithm of a public key, or "" if it isn't one
// the keystore generates.
func KeyAlgorithmOf(pub crypto.PublicKey) KeyAlgorithm {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return KeyAlgorithmEC256
		case elliptic.P384():
			return KeyAlgorithmEC384
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return KeyAlgorithmRSA2048
		case 4096:
			return KeyAlgorithmRSA4096
		}
	}
	return ""
}

// EncodePrivateKeyPEM encodes a private key as a PKCS#8 PEM.
func EncodePrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ParsePrivateKeyPEM parses a plaintext private key PEM (PKCS#8, PKCS#1 or
// SEC 1) into a signer.
func ParsePrivateKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}

	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}

func GenerateCSR(sans []string, keyAlgorithm KeyAlgorithm) (csrPEM string, keyPEM string, err error) {
	privKey, err := GeneratePrivateKey(keyAlgorithm)
	if err != nil {
		return "", "", err
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

	keyBlock, err := EncodePrivateKeyPEM(privKey)
	if err != nil {
		return "", "", err
	}

	return string(csrBlock), string(keyBlock), nil
}
