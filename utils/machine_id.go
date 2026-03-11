//go:build !windows

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const identityNamespace = "certkit-keystore"

func GetStableMachineID() (string, error) {
	if id, err := loadPersistentID(); err == nil {
		return id, nil
	}

	if id, err := readAndHash("/etc/machine-id"); err == nil {
		return id, nil
	}

	if id, err := containerID(); err == nil {
		return id, nil
	}

	return generateAndPersistID()
}

func loadPersistentID() (string, error) {
	path := persistentIDPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("empty persisted id")
	}
	return id, nil
}

func generateAndPersistID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	id := hashWithNamespace(hex.EncodeToString(b))

	path := persistentIDPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		return "", err
	}

	return id, nil
}

func readAndHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("empty id source")
	}
	return hashWithNamespace(s), nil
}

func containerID() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/docker/") ||
			strings.Contains(line, "/kubepods/") ||
			strings.Contains(line, "/containerd/") {

			parts := strings.Split(line, "/")
			id := parts[len(parts)-1]
			if len(id) >= 12 {
				return hashWithNamespace(id), nil
			}
		}
	}
	return "", errors.New("no container id found")
}

func hashWithNamespace(value string) string {
	sum := sha256.Sum256([]byte(value + ":" + identityNamespace))
	return hex.EncodeToString(sum[:])
}

func persistentIDPath() string {
	if p := os.Getenv("KEYSTORE_ID_PATH"); p != "" {
		return p
	}

	if os.Geteuid() == 0 {
		return "/var/lib/certkit/keystore-id"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".certkit", "keystore-id")
}
