//go:build windows

package selfupdate

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData  = modwintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = modwintrust.NewProc("WTHelperGetProvCertFromChain")
)

// cryptProviderCert mirrors the leading fields of wintrust.h CRYPT_PROVIDER_CERT.
type cryptProviderCert struct {
	size uint32
	cert *windows.CertContext
}

// verifyUpdateSignature requires the downloaded update to carry a valid
// Authenticode signature from the same publisher as the running binary. The
// SHA256 only proves the download matches what the server announced; the
// signature proves it came out of the CertKit release pipeline, so a
// compromised update server alone cannot push a binary onto the machine.
func verifyUpdateSignature(path string) error {
	current, err := resolveExecutablePath()
	if err != nil {
		return err
	}
	want, err := authenticodeSigner(current)
	if err != nil {
		return fmt.Errorf("running binary is not validly signed, so there is no publisher to verify updates against: %w", err)
	}
	got, err := authenticodeSigner(path)
	if err != nil {
		return fmt.Errorf("update is not validly signed: %w", err)
	}
	return checkSamePublisher(want, got)
}

// checkSamePublisher compares subjects only: the issuing intermediate CA
// rotates between releases.
func checkSamePublisher(want, got *x509.Certificate) error {
	if got.Subject.String() != want.Subject.String() {
		return fmt.Errorf("update is signed by %q, expected %q", got.Subject, want.Subject)
	}
	return nil
}

// authenticodeSigner verifies the file's embedded Authenticode signature
// (chain to a trusted root, file hash, timestamp) and returns the signer's
// certificate.
func authenticodeSigner(path string) (*x509.Certificate, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	data := &windows.WinTrustData{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE,
		// Revocation lookups need CRL/OCSP access that many servers lack;
		// requiring them would block updates there entirely.
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()
	if verifyErr != nil {
		return nil, verifyErr
	}

	// Read the leaf certificate of the signer WinVerifyTrust just validated,
	// rather than searching the signature's certificate bag, which can carry
	// arbitrary unauthenticated certificates.
	provData, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(data.StateData))
	if provData == 0 {
		return nil, fmt.Errorf("read verified signature state")
	}
	signer, _, _ := procWTHelperGetProvSignerFromChain.Call(provData, 0, 0, 0)
	if signer == 0 {
		return nil, fmt.Errorf("read signer")
	}
	provCertPtr, _, _ := procWTHelperGetProvCertFromChain.Call(signer, 0)
	if provCertPtr == 0 {
		return nil, fmt.Errorf("read signer certificate")
	}
	provCert := *(**cryptProviderCert)(unsafe.Pointer(&provCertPtr))
	if provCert.cert == nil || provCert.cert.EncodedCert == nil {
		return nil, fmt.Errorf("signer certificate is empty")
	}
	// The certificate memory belongs to the verification state, which the
	// deferred close frees, and x509.ParseCertificate retains its input.
	der := bytes.Clone(unsafe.Slice(provCert.cert.EncodedCert, provCert.cert.Length))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signer certificate: %w", err)
	}
	return cert, nil
}
