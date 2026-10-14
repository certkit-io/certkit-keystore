package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// EncryptedKeyPEMType is the PEM block type of a private key encrypted at
// rest. The block's bytes are nonce || ciphertext || tag (AES-256-GCM over the
// original PEM), and its Kid header identifies the encryption key.
const EncryptedKeyPEMType = "CERTKIT ENCRYPTED PRIVATE KEY"

// EncryptionKeySize is the length of the at-rest encryption key (AES-256).
const EncryptionKeySize = 32

const kidHeader = "Kid"

// ErrKeyMismatch means a private key was encrypted with a different
// encryption key than the one supplied.
var ErrKeyMismatch = errors.New("private key was encrypted with a different encryption key")

// plaintextKeyPEMTypes are the unencrypted private key formats the keystore
// writes or receives from CertKit.
var plaintextKeyPEMTypes = map[string]bool{
	"PRIVATE KEY":     true,
	"EC PRIVATE KEY":  true,
	"RSA PRIVATE KEY": true,
}

// KeyID returns a short identifier for an encryption key: the first 4 bytes
// of its SHA-256, in hex.
func KeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// EncryptedKeyID reports whether data is an encrypted private key PEM and, if
// so, the Kid it was encrypted with.
func EncryptedKeyID(data []byte) (kid string, encrypted bool) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != EncryptedKeyPEMType {
		return "", false
	}
	return block.Headers[kidHeader], true
}

// EncryptPrivateKeyPEM encrypts a plaintext private key PEM with key.
func EncryptPrivateKeyPEM(key []byte, plaintextPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(plaintextPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	if !plaintextKeyPEMTypes[block.Type] {
		return nil, fmt.Errorf("not a plaintext private key (PEM type %q)", block.Type)
	}

	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	kid := KeyID(key)
	sealed := aead.Seal(nonce, nonce, plaintextPEM, []byte(kid))

	return pem.EncodeToMemory(&pem.Block{
		Type:    EncryptedKeyPEMType,
		Headers: map[string]string{kidHeader: kid},
		Bytes:   sealed,
	}), nil
}

// DecryptPrivateKeyPEM returns the plaintext PEM for an encrypted private key.
// Plaintext private keys (written before encryption at rest) are returned
// unchanged. Returns ErrKeyMismatch if data was encrypted with another key.
func DecryptPrivateKeyPEM(key []byte, data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	if plaintextKeyPEMTypes[block.Type] {
		return data, nil
	}
	if block.Type != EncryptedKeyPEMType {
		return nil, fmt.Errorf("unexpected PEM type %q for private key", block.Type)
	}

	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	kid := block.Headers[kidHeader]
	if kid != KeyID(key) {
		return nil, fmt.Errorf("%w (file kid %q, current kid %q)", ErrKeyMismatch, kid, KeyID(key))
	}

	nonceSize := aead.NonceSize()
	if len(block.Bytes) < nonceSize+aead.Overhead() {
		return nil, errors.New("encrypted private key is truncated")
	}

	plain, err := aead.Open(nil, block.Bytes[:nonceSize], block.Bytes[nonceSize:], []byte(kid))
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != EncryptionKeySize {
		return nil, fmt.Errorf("invalid encryption key length: got %d, want %d", len(key), EncryptionKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
