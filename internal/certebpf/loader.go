// Package certebpf loads the cert_hook eBPF uprobe and streams captured
// X.509 DER bytes to the caller.
//
// ADR-006 Option 4 prototype: hook d2i_X509 (public OpenSSL API) to capture
// peer certificate DER during TLS handshake, without reading internal structs.
//
// Linux only — see loader_stub.go for non-Linux platforms.

//go:build linux

package certebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// MaxDERBytes matches MAX_DER_BYTES in cert_hook.c.
const MaxDERBytes = 2048

// CertEventSize is the fixed wire size of a cert event from the ring buffer.
// 8 (timestamp) + 4 (pid) + 4 (tid) + 4 (der_len) + 4 (orig_len) + 2048 (der) = 2072 bytes.
const CertEventSize = 8 + 4 + 4 + 4 + 4 + MaxDERBytes

// CertEvent is a captured DER event from a successful d2i_X509 call.
type CertEvent struct {
	Timestamp time.Duration // kernel monotonic time
	PID       uint32
	TID       uint32
	DERLen    uint32 // bytes valid in DER (capped at MaxDERBytes)
	OrigLen   uint32 // original len argument to d2i_X509
	DER       []byte // DER-encoded X.509 certificate bytes
}

// ParseCertEvent decodes raw bytes from the eBPF ring buffer into a CertEvent.
func ParseCertEvent(data []byte) (*CertEvent, error) {
	if len(data) < CertEventSize {
		return nil, fmt.Errorf("cert event too short: got %d bytes, want %d", len(data), CertEventSize)
	}

	derLen := binary.LittleEndian.Uint32(data[16:20])
	if derLen > MaxDERBytes {
		derLen = MaxDERBytes
	}

	ev := &CertEvent{
		Timestamp: time.Duration(binary.LittleEndian.Uint64(data[0:8])) * time.Nanosecond,
		PID:       binary.LittleEndian.Uint32(data[8:12]),
		TID:       binary.LittleEndian.Uint32(data[12:16]),
		DERLen:    derLen,
		OrigLen:   binary.LittleEndian.Uint32(data[20:24]),
		DER:       make([]byte, derLen),
	}
	copy(ev.DER, data[24:24+derLen])

	return ev, nil
}

// Loader manages the cert_hook uprobe lifecycle.
type Loader struct {
	objs   certHookObjects
	links  []link.Link
	reader *ringbuf.Reader
	logger *slog.Logger
}

// NewLoader creates a Loader. Call Load() to attach the uprobe.
func NewLoader(logger *slog.Logger) *Loader {
	return &Loader{logger: logger}
}

// Load loads the cert_hook eBPF objects and attaches uprobes to the given
// libssl shared library path. Pass an optional pid to target a specific
// process; pass 0 to hook all processes using that library.
//
// libsslPath is the absolute path to libssl.so visible from the current
// mount namespace (e.g. /usr/lib/x86_64-linux-gnu/libssl.so.3, or
// /proc/<pid>/root/usr/lib/... for a container process).
func (l *Loader) Load(libsslPath string, pid int) error {
	if err := loadCertHookObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading cert_hook eBPF objects: %w", err)
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("opening %s: %w", libsslPath, err)
	}

	opts := &link.UprobeOptions{}
	if pid > 0 {
		opts.PID = pid
	}

	upEntry, err := ex.Uprobe("d2i_X509", l.objs.UprobeD2iX509, opts)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("attaching uprobe d2i_X509: %w", err)
	}
	l.links = append(l.links, upEntry)

	upRet, err := ex.Uretprobe("d2i_X509", l.objs.UretprobeD2iX509, opts)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching uretprobe d2i_X509: %w", err)
	}
	l.links = append(l.links, upRet)

	rd, err := ringbuf.NewReader(l.objs.CertEvents)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("opening cert_events ring buffer: %w", err)
	}
	l.reader = rd

	l.logger.Info("cert_hook uprobe attached",
		"library", libsslPath,
		"pid_filter", pid,
		"symbol", "d2i_X509",
	)
	return nil
}

// Read blocks until a cert event is available or ctx is cancelled.
// Returns the raw ring buffer bytes; use ParseCertEvent to decode.
func (l *Loader) Read(ctx context.Context) ([]byte, error) {
	go func() {
		<-ctx.Done()
		l.reader.Close()
	}()

	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("reading cert_events ring buffer: %w", err)
	}
	return record.RawSample, nil
}

// Close detaches uprobes, closes the ring buffer reader, and unloads objects.
func (l *Loader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	l.closeLinks()
	return l.objs.Close()
}

func (l *Loader) closeLinks() {
	for _, ln := range l.links {
		ln.Close()
	}
	l.links = nil
}
