package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func testEncryptionKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, EncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testEncryptionKey(t)

	for _, alg := range []KeyAlgorithm{KeyAlgorithmEC256, KeyAlgorithmRSA2048} {
		t.Run(string(alg), func(t *testing.T) {
			_, keyPEM, err := GenerateCSR([]string{"example.com"}, alg)
			if err != nil {
				t.Fatal(err)
			}

			encrypted, err := EncryptPrivateKeyPEM(key, []byte(keyPEM))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if bytes.Contains(encrypted, []byte("BEGIN PRIVATE KEY")) {
				t.Fatal("encrypted output contains the plaintext PEM header")
			}

			kid, isEncrypted := EncryptedKeyID(encrypted)
			if !isEncrypted || kid != KeyID(key) {
				t.Fatalf("EncryptedKeyID = (%q, %v), want (%q, true)", kid, isEncrypted, KeyID(key))
			}

			decrypted, err := DecryptPrivateKeyPEM(key, encrypted)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(decrypted) != keyPEM {
				t.Fatal("decrypted PEM does not match the original")
			}
		})
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	_, keyPEM, _ := GenerateCSR([]string{"example.com"}, KeyAlgorithmEC256)
	encrypted, err := EncryptPrivateKeyPEM(testEncryptionKey(t), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptPrivateKeyPEM(testEncryptionKey(t), encrypted)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v, want ErrKeyMismatch", err)
	}
}

func TestDecryptTampered(t *testing.T) {
	key := testEncryptionKey(t)
	_, keyPEM, _ := GenerateCSR([]string{"example.com"}, KeyAlgorithmEC256)
	encrypted, err := EncryptPrivateKeyPEM(key, []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encrypted)

	tamper := func(mutate func(b *pem.Block)) []byte {
		b := &pem.Block{Type: block.Type, Headers: map[string]string{}, Bytes: bytes.Clone(block.Bytes)}
		for k, v := range block.Headers {
			b.Headers[k] = v
		}
		mutate(b)
		return pem.EncodeToMemory(b)
	}

	cases := map[string][]byte{
		"ciphertext": tamper(func(b *pem.Block) { b.Bytes[20] ^= 0xff }),
		"tag":        tamper(func(b *pem.Block) { b.Bytes[len(b.Bytes)-1] ^= 0xff }),
		"nonce":      tamper(func(b *pem.Block) { b.Bytes[0] ^= 0xff }),
		"kid":        tamper(func(b *pem.Block) { b.Headers[kidHeader] = "00000000" }),
		"truncated":  tamper(func(b *pem.Block) { b.Bytes = b.Bytes[:10] }),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecryptPrivateKeyPEM(key, data); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDecryptPlaintextPassthrough(t *testing.T) {
	for _, typ := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: []byte("not really a key")})
		// No key is needed to read a plaintext file.
		got, err := DecryptPrivateKeyPEM(nil, data)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: plaintext was not returned unchanged", typ)
		}
	}
}

func TestUnknownPEMType(t *testing.T) {
	key := testEncryptionKey(t)
	data := pem.EncodeToMemory(&pem.Block{Type: "REDACTED PRIVATE KEY", Bytes: []byte("KEY NOT FOUND")})

	if _, err := DecryptPrivateKeyPEM(key, data); err == nil {
		t.Fatal("decrypt: expected an error for an unknown PEM type")
	}
	if _, err := EncryptPrivateKeyPEM(key, data); err == nil {
		t.Fatal("encrypt: expected an error for an unknown PEM type")
	}
	if _, err := DecryptPrivateKeyPEM(key, []byte("garbage")); err == nil {
		t.Fatal("decrypt: expected an error for non-PEM data")
	}
}

func TestEncryptRejectsAlreadyEncrypted(t *testing.T) {
	key := testEncryptionKey(t)
	_, keyPEM, _ := GenerateCSR([]string{"example.com"}, KeyAlgorithmEC256)
	encrypted, err := EncryptPrivateKeyPEM(key, []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptPrivateKeyPEM(key, encrypted); err == nil || !strings.Contains(err.Error(), EncryptedKeyPEMType) {
		t.Fatalf("err = %v, want refusal to double-encrypt", err)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	_, keyPEM, _ := GenerateCSR([]string{"example.com"}, KeyAlgorithmEC256)
	if _, err := EncryptPrivateKeyPEM(make([]byte, 16), []byte(keyPEM)); err == nil {
		t.Fatal("expected an error for a 16-byte key")
	}
}
