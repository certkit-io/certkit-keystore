package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// warnedBothLocations holds the certificates already reported as stored in
// both the legacy and the collection location, so each is logged once.
var warnedBothLocations sync.Map

// AdoptLegacyCert moves a certificate stored before v2, directly under the
// storage directory, into its collection's directory. Only CertKit knows
// which collection a certificate belongs to, so this runs for every
// certificate a poll returns. Returns true if the certificate was moved.
func AdoptLegacyCert(collectionId string, customCertId string) (bool, error) {
	if !IsSafeId(collectionId) || !IsSafeId(customCertId) || !isLegacyCertDirName(customCertId) {
		return false, nil
	}

	legacy := legacyCertRootDir(customCertId)
	if info, err := os.Stat(legacy); err != nil || !info.IsDir() {
		return false, nil
	}

	target := certRootDir(collectionId, customCertId)
	if _, err := os.Stat(target); err == nil {
		if _, warned := warnedBothLocations.LoadOrStore(customCertId, true); !warned {
			log.Printf("Certificate %s is stored in both %s and %s; using %s and leaving %s alone",
				customCertId, legacy, target, target, legacy)
		}
		return false, nil
	}

	if err := ensureDir(filepath.Dir(target)); err != nil {
		return false, fmt.Errorf("create collection directory: %w", err)
	}
	if err := os.Rename(legacy, target); err != nil {
		return false, fmt.Errorf("move %s to %s: %w", legacy, target, err)
	}

	log.Printf("Moved certificate %s into collection %s: %s", customCertId, collectionId, target)
	return true, nil
}
