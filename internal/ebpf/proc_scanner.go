//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LibCryptoInstance is a unique libcrypto shared library found on the host,
// identified by its inode so we attach at most one uprobe per binary image.
type LibCryptoInstance struct {
	Path  string
	Inode uint64
}

// ScanProcForLibCrypto walks /proc/*/maps and returns all unique libcrypto
// shared library instances by inode. The caller should attach a d2i_X509
// uprobe to each instance not already tracked.
func ScanProcForLibCrypto() ([]LibCryptoInstance, error) {
	entries, err := filepath.Glob("/proc/*/maps")
	if err != nil {
		return nil, fmt.Errorf("glob /proc/*/maps: %w", err)
	}

	seen := make(map[uint64]bool)
	var result []LibCryptoInstance

	for _, maps := range entries {
		instances, err := scanMapsFile(maps)
		if err != nil {
			// Process may have exited between glob and open — skip silently.
			continue
		}
		for _, inst := range instances {
			if !seen[inst.Inode] {
				seen[inst.Inode] = true
				result = append(result, inst)
			}
		}
	}
	return result, nil
}

func scanMapsFile(path string) ([]LibCryptoInstance, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []LibCryptoInstance
	seenInFile := make(map[uint64]bool)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		// Maps lines: addr perms offset dev inode pathname
		// We want lines where pathname contains "libcrypto".
		if !strings.Contains(line, "libcrypto") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		libPath := fields[5]
		if strings.HasPrefix(libPath, "[") || libPath == "" {
			continue
		}

		var stat syscall.Stat_t
		if err := syscall.Stat(libPath, &stat); err != nil {
			continue
		}
		if seenInFile[stat.Ino] {
			continue
		}
		seenInFile[stat.Ino] = true
		result = append(result, LibCryptoInstance{Path: libPath, Inode: stat.Ino})
	}
	return result, scanner.Err()
}
