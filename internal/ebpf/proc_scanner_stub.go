//go:build !linux

package ebpf

// LibCryptoInstance is a unique libcrypto shared library found on the host.
type LibCryptoInstance struct {
	Path  string
	Inode uint64
}

// ScanProcForLibCrypto is a no-op stub on non-Linux platforms.
func ScanProcForLibCrypto() ([]LibCryptoInstance, error) {
	return nil, nil
}
