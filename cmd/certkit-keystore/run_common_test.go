package main

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func stubEncryptionKeyFetch(t *testing.T, fetch func() ([]byte, error), delay time.Duration) {
	t.Helper()
	prevFetch, prevDelays := fetchEncryptionKey, encryptionKeyRetryDelays
	t.Cleanup(func() {
		fetchEncryptionKey = prevFetch
		encryptionKeyRetryDelays = prevDelays
	})
	fetchEncryptionKey = fetch
	encryptionKeyRetryDelays = []time.Duration{delay}
}

func TestWaitForEncryptionKeyRetries(t *testing.T) {
	want := bytes.Repeat([]byte{7}, 32)
	attempts := 0
	stubEncryptionKeyFetch(t, func() ([]byte, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("certkit unreachable")
		}
		return want, nil
	}, time.Millisecond)

	key, ok := waitForEncryptionKey(make(chan struct{}))
	if !ok || !bytes.Equal(key, want) {
		t.Fatalf("waitForEncryptionKey = %v, %v; want the key", key, ok)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestWaitForEncryptionKeyStops(t *testing.T) {
	stubEncryptionKeyFetch(t, func() ([]byte, error) {
		return nil, errors.New("certkit unreachable")
	}, time.Hour)

	stopCh := make(chan struct{})
	done := make(chan bool)
	go func() {
		_, ok := waitForEncryptionKey(stopCh)
		done <- ok
	}()

	close(stopCh)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("waitForEncryptionKey reported success after stop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitForEncryptionKey did not return after stop")
	}
}
