package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/certkit-io/certkit-keystore/storage"
	"software.sslmate.com/src/go-pkcs12"
)

type FetchCertificateRequest struct {
	ConfigurationSqid string `json:"config_id"`
	CertificateSqid   string `json:"certificate_id"`
}

type FetchCertificateResponse struct {
	CertificatePem  string `json:"certificatePem"`
	KeyPem          string `json:"keyPem"`
	CertificateSha1 string `json:"certificateSha1"`
}

func handleFetchCertificate(w http.ResponseWriter, r *http.Request) {
	agentSqid := r.PathValue("agentSqid")
	log.Printf("fetch-certificate request from agent %s", agentSqid)

	// TODO: Forward agent signature to CertKit for validation

	var req FetchCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Agent %s requesting cert %s (config %s)", agentSqid, req.CertificateSqid, req.ConfigurationSqid)

	certFiles, err := storage.ReadLatestCert(req.CertificateSqid)
	if err != nil {
		log.Printf("Failed to read cert %s: %v", req.CertificateSqid, err)
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	// Combine cert + chain (matching .NET FullCertificateAndChainPem)
	fullPEM := certFiles.CertPEM
	if certFiles.ChainPEM != "" {
		fullPEM += certFiles.ChainPEM
	}

	resp := FetchCertificateResponse{
		CertificatePem:  fullPEM,
		KeyPem:          certFiles.KeyPEM,
		CertificateSha1: certFiles.SHA1,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleFetchPfx(w http.ResponseWriter, r *http.Request) {
	agentSqid := r.PathValue("agentSqid")
	log.Printf("fetch-pfx request from agent %s", agentSqid)

	// TODO: Forward agent signature to CertKit for validation

	var req FetchCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Agent %s requesting PFX for cert %s (config %s)", agentSqid, req.CertificateSqid, req.ConfigurationSqid)

	certFiles, err := storage.ReadLatestCert(req.CertificateSqid)
	if err != nil {
		log.Printf("Failed to read cert %s: %v", req.CertificateSqid, err)
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	password := generatePassword(16)
	pfxData, err := encodePFX(certFiles, password)
	if err != nil {
		log.Printf("Failed to encode PFX for %s: %v", req.CertificateSqid, err)
		http.Error(w, "failed to generate PFX", http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Certkit-Pfx-Password", password)
	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Write(pfxData)
}

func encodePFX(certFiles *storage.CertFiles, password string) ([]byte, error) {
	certBlock, _ := pem.Decode([]byte(certFiles.CertPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	leafCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(certFiles.KeyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in private key")
	}
	privKey, err := parsePrivateKeyDER(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	var chainCerts []*x509.Certificate
	chainData := []byte(certFiles.ChainPEM)
	for {
		block, rest := pem.Decode(chainData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse chain certificate: %w", err)
			}
			chainCerts = append(chainCerts, cert)
		}
		chainData = rest
	}

	return pkcs12.Modern2023.Encode(privKey, leafCert, chainCerts, password)
}

func parsePrivateKeyDER(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func generatePassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}
