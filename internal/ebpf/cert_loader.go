// CertLoader manages the lifecycle of the cert_hook eBPF uprobe program.
// Hooks d2i_X509 in libcrypto to capture DER-encoded X.509 certificates
// during TLS handshakes. Userspace parses the DER to extract SPIFFE IDs.
//
// ADR-004, ADR-006 Option 4: uprobe on d2i_X509 at parse time — no OpenSSL
// struct offset knowledge required.

//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// CertEvent is a DER-encoded X.509 certificate captured from d2i_X509.
// Layout matches struct cert_event in cert_hook.c.
type CertEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	DERLen      uint32 // bytes valid in DER (capped at maxDERBytes)
	OrigLen     uint32 // original len argument to d2i_X509
	DER         []byte // DER bytes, length DERLen
}

const certEventHeaderSize = 16 // timestamp(8) + pid(4) + tid(4) + der_len(4) + orig_len(4) = 24
const maxDERBytes = 2048       // must match MAX_DER_BYTES in cert_hook.c

// ParseCertEvent parses a raw ring buffer sample into a CertEvent.
func ParseCertEvent(data []byte) (*CertEvent, error) {
	const hdr = 24 // 8+4+4+4+4
	if len(data) < hdr+maxDERBytes {
		return nil, fmt.Errorf("cert event too short: %d bytes", len(data))
	}
	ev := &CertEvent{
		TimestampNS: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		TID:         binary.LittleEndian.Uint32(data[12:16]),
		DERLen:      binary.LittleEndian.Uint32(data[16:20]),
		OrigLen:     binary.LittleEndian.Uint32(data[20:24]),
	}
	if ev.DERLen > maxDERBytes {
		ev.DERLen = maxDERBytes
	}
	ev.DER = make([]byte, ev.DERLen)
	copy(ev.DER, data[24:24+ev.DERLen])
	return ev, nil
}

// CertLoader manages the lifecycle of the cert_hook eBPF uprobe program.
// It can attach to multiple libcrypto instances (one per unique inode) so that
// SPIFFE extraction works for containerized workloads with their own libcrypto.
type CertLoader struct {
	objs          certHookObjects
	reader        *ringbuf.Reader
	logger        *slog.Logger
	libCryptoPath string
	// attachedInodes tracks inode → [uprobe, uretprobe] to avoid duplicate attachments.
	attachedInodes map[uint64][]link.Link
}

// NewCertLoader creates a CertLoader targeting the given libcrypto shared library.
// libCryptoPath must be an absolute path (e.g. /host/usr/lib/libcrypto.so.3).
func NewCertLoader(libCryptoPath string, logger *slog.Logger) *CertLoader {
	return &CertLoader{
		libCryptoPath:  libCryptoPath,
		logger:         logger,
		attachedInodes: make(map[uint64][]link.Link),
	}
}

// Load loads the cert_hook eBPF program, attaches uprobes to the primary
// libcrypto path, and opens the ring buffer reader.
func (l *CertLoader) Load(ctx context.Context) error {
	if err := loadCertHookObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading cert_hook eBPF objects: %w", err)
	}

	if err := l.AttachToExecutable(l.libCryptoPath); err != nil {
		l.objs.Close()
		return err
	}

	rd, err := ringbuf.NewReader(l.objs.CertEvents)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("opening cert_events ring buffer: %w", err)
	}
	l.reader = rd

	// Close the reader when ctx is cancelled so any blocked Read() returns.
	// Started once here — NOT inside Read() to avoid goroutine-per-read leak.
	go func() {
		<-ctx.Done()
		l.reader.Close()
	}()

	l.logger.Info("cert hook eBPF program loaded",
		"libcrypto", l.libCryptoPath,
		"uprobes", []string{"d2i_X509"},
	)
	return nil
}

// AttachToExecutable attaches d2i_X509 uprobes to the given libcrypto path,
// skipping if the inode is already tracked. Safe to call concurrently after Load.
func (l *CertLoader) AttachToExecutable(path string) error {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	inode := stat.Ino

	if _, already := l.attachedInodes[inode]; already {
		return nil
	}

	if err := ensureExecutable(path); err != nil {
		return fmt.Errorf("chmod +x %s: %w", path, err)
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", path, err)
	}

	up, err := ex.Uprobe("d2i_X509", l.objs.UprobeD2iX509, nil)
	if err != nil {
		return fmt.Errorf("attaching uprobe/d2i_X509 to %s: %w", path, err)
	}

	urp, err := ex.Uretprobe("d2i_X509", l.objs.UretprobeD2iX509, nil)
	if err != nil {
		up.Close()
		return fmt.Errorf("attaching uretprobe/d2i_X509 to %s: %w", path, err)
	}

	l.attachedInodes[inode] = []link.Link{up, urp}
	l.logger.Info("d2i_X509 uprobe attached", "path", path, "inode", inode)
	return nil
}

// AttachedCount returns the number of libcrypto instances currently hooked.
func (l *CertLoader) AttachedCount() int {
	return len(l.attachedInodes)
}

// Read blocks until a raw cert event is available, or the context is cancelled.
func (l *CertLoader) Read(ctx context.Context) ([]byte, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("reading cert_events ring buffer: %w", err)
	}
	return record.RawSample, nil
}

// Close detaches all uprobes, closes the ring buffer, and unloads the program.
func (l *CertLoader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	l.closeLinks()
	return l.objs.Close()
}

func (l *CertLoader) closeLinks() {
	for inode, links := range l.attachedInodes {
		for _, ln := range links {
			ln.Close()
		}
		delete(l.attachedInodes, inode)
	}
}
