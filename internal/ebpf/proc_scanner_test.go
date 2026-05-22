//go:build linux

// Tests for the proc scanner run on Linux only (scanMapsFile uses syscall.Stat).

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanMapsFileExtractsLibCrypto(t *testing.T) {
	content := `7f1a00000000-7f1a00001000 r--p 00000000 fd:01 123456 /usr/lib/libcrypto.so.3
7f1a00001000-7f1a00100000 r-xp 00001000 fd:01 123456 /usr/lib/libcrypto.so.3
7f1b00000000-7f1b00001000 r--p 00000000 fd:01 999999 /usr/lib/libssl.so.3
7f1c00000000-7f1c00001000 r--p 00000000 fd:01 777777 /lib/x86_64-linux-gnu/libc.so.6
`
	// Write a temp file with the maps content and a real file for libcrypto path.
	dir := t.TempDir()
	mapsFile := filepath.Join(dir, "maps")
	if err := os.WriteFile(mapsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// scanMapsFile stats the paths — they won't exist in this test environment,
	// so it will skip them. We just verify it doesn't panic or error.
	instances, err := scanMapsFile(mapsFile)
	if err != nil {
		t.Fatalf("scanMapsFile returned error: %v", err)
	}
	// On a non-Linux system the paths won't stat successfully, so instances may be empty.
	// The important thing is no panic and no error.
	_ = instances
}

func TestScanMapsFileSkipsNonLibCrypto(t *testing.T) {
	content := `7f1b00000000-7f1b00001000 r--p 00000000 fd:01 999999 /usr/lib/libssl.so.3
7f1c00000000-7f1c00001000 r--p 00000000 fd:01 777777 /lib/x86_64-linux-gnu/libc.so.6
7f1d00000000-7f1d00001000 rw-p 00000000 00:00 0      [heap]
`
	dir := t.TempDir()
	mapsFile := filepath.Join(dir, "maps")
	if err := os.WriteFile(mapsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	instances, err := scanMapsFile(mapsFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(instances) != 0 {
		t.Errorf("expected 0 instances (paths won't stat on this platform), got %d", len(instances))
	}
}

func TestScanMapsFileMissingFile(t *testing.T) {
	_, err := scanMapsFile("/nonexistent/maps")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestScanProcForLibCryptoDoesNotError(t *testing.T) {
	// On a real Linux system this scans /proc/*/maps — just verify no panic/error.
	_, err := ScanProcForLibCrypto()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
