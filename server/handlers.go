package server

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	"github.com/certkit-io/certkit-keystore/storage"
	"software.sslmate.com/src/go-pkcs12"
)

type fetchCertificateRequest struct {
	ConfigurationSqid string `json:"config_id"`
	CertificateSqid   string `json:"certificate_id"`
}

type fetchCertificateResponse struct {
	CertificatePem  string `json:"certificate_pem"`
	KeyPem          string `json:"key_pem"`
	CertificateSha1 string `json:"certificate_sha1"`
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	cfg := &config.CurrentConfig
	fmt.Fprintf(w, "CertKit Keystore\n\n")
	fmt.Fprintf(w, "Base URL:       %s\n", cfg.Keystore.BaseUrl())
	fmt.Fprintf(w, "Application ID: %s\n", cfg.Keystore.ApplicationId)
	fmt.Fprintf(w, "Keystore ID:    %s\n", cfg.Keystore.Id)
	fmt.Fprintf(w, "Storage Dir:    %s\n\n", cfg.Keystore.StorageDir)
	fmt.Fprintf(w, "Management URL: %s\n", fmt.Sprintf("%s/app/%s/keystore", cfg.CertkitBaseUrl, cfg.Keystore.ApplicationId))
}

func handleFetchCertificate(w http.ResponseWriter, r *http.Request) {
	agentSqid := r.PathValue("agentSqid")
	log.Printf("fetch-certificate request from agent %s", agentSqid)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := api.ValidateAgentRequest(agentSqid, buildAgentRequest(r, bodyBytes)); err != nil {
		log.Printf("Agent %s validation failed: %v", agentSqid, err)
		http.Error(w, "agent authorization failed", http.StatusUnauthorized)
		return
	}

	var req fetchCertificateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
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
		fullPEM += "\n" + certFiles.ChainPEM
	}

	resp := fetchCertificateResponse{
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

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := api.ValidateAgentRequest(agentSqid, buildAgentRequest(r, bodyBytes)); err != nil {
		log.Printf("Agent %s validation failed: %v", agentSqid, err)
		http.Error(w, "agent authorization failed", http.StatusUnauthorized)
		return
	}

	var req fetchCertificateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
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

	return pkcs12.LegacyDES.Encode(privKey, leafCert, chainCerts, password)
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

func buildAgentRequest(r *http.Request, bodyBytes []byte) api.AgentRequest {
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = values[0]
	}
	return api.AgentRequest{
		Host:    r.Host,
		Path:    r.URL.RequestURI(),
		Headers: headers,
		Body:    string(bodyBytes),
	}
}
