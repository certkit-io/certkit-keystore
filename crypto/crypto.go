package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func CreateNewKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	return &KeyPair{
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv),
	}, nil
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(data), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(data), nil
}

func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(data), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(data), nil
}

func (kp *KeyPair) DecodePrivateKey() (ed25519.PrivateKey, error) {
	if kp == nil {
		return nil, errors.New("keypair is nil")
	}
	return DecodePrivateKey(kp.PrivateKey)
}

func (kp *KeyPair) DecodePublicKey() (ed25519.PublicKey, error) {
	if kp == nil {
		return nil, errors.New("keypair is nil")
	}
	return DecodePublicKey(kp.PublicKey)
}
