// TLS loader manages the lifecycle of the tls_hook eBPF uprobe program.
// It attaches uprobes to SSL_write and SSL_read in libssl.so and reads
// captured plaintext from the tls_events ring buffer.
//
// Crawl scope: SSL_write captures outbound plaintext used for OTLP, JWT,
// and MCP extraction. SSL_read captures inbound responses.

//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TLSLoader manages the lifecycle of the TLS uprobe eBPF program.
type TLSLoader struct {
	objs      tlsHookObjects
	links     []link.Link
	reader    *ringbuf.Reader
	logger    *slog.Logger
	libSSLPath string
}

// NewTLSLoader creates a TLSLoader that will hook the given libssl shared library.
// libSSLPath must be an absolute path to libssl.so (e.g. /usr/lib/x86_64-linux-gnu/libssl.so.3).
func NewTLSLoader(libSSLPath string, logger *slog.Logger) *TLSLoader {
	return &TLSLoader{
		libSSLPath: libSSLPath,
		logger:     logger,
	}
}

// Load loads the TLS hook eBPF program into the kernel and attaches uprobes to
// SSL_write and SSL_read in the target libssl.
func (l *TLSLoader) Load(ctx context.Context) error {
	if os.Getuid() == 0 {
		if err := rlimit.RemoveMemlock(); err != nil {
			l.logger.Warn("RemoveMemlock failed", "error", err)
		}
	}
	if err := loadTlsHookObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading tls_hook eBPF objects: %w", err)
	}

	// cilium/ebpf requires the shared library to have the executable bit set.
	// On Debian/Ubuntu, shared libs lack it — set it defensively.
	if err := ensureExecutable(l.libSSLPath); err != nil {
		l.objs.Close()
		return fmt.Errorf("chmod +x %s: %w", l.libSSLPath, err)
	}

	ex, err := link.OpenExecutable(l.libSSLPath)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("opening executable %s: %w", l.libSSLPath, err)
	}

	// Uprobe on SSL_write entry (saves buf + num)
	upWrite, err := ex.Uprobe("SSL_write", l.objs.UprobeSslWrite, nil)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("attaching uprobe/SSL_write: %w", err)
	}
	l.links = append(l.links, upWrite)

	// Uretprobe on SSL_write return (captures plaintext + emits to ring buffer)
	urpWrite, err := ex.Uretprobe("SSL_write", l.objs.UretprobeSslWrite, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching uretprobe/SSL_write: %w", err)
	}
	l.links = append(l.links, urpWrite)

	// Uprobe on SSL_read entry
	upRead, err := ex.Uprobe("SSL_read", l.objs.UprobeSslRead, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching uprobe/SSL_read: %w", err)
	}
	l.links = append(l.links, upRead)

	// Uretprobe on SSL_read return
	urpRead, err := ex.Uretprobe("SSL_read", l.objs.UretprobeSslRead, nil)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("attaching uretprobe/SSL_read: %w", err)
	}
	l.links = append(l.links, urpRead)

	rd, err := ringbuf.NewReader(l.objs.TlsEvents)
	if err != nil {
		l.closeLinks()
		l.objs.Close()
		return fmt.Errorf("opening tls_events ring buffer reader: %w", err)
	}
	l.reader = rd

	// Close the reader when ctx is cancelled so any blocked Read() returns.
	// Started once here — NOT inside Read() to avoid goroutine-per-read leak.
	go func() {
		<-ctx.Done()
		l.reader.Close()
	}()

	l.logger.Info("TLS hook eBPF program loaded",
		"libssl", l.libSSLPath,
		"uprobes", []string{"SSL_write", "SSL_read"},
	)
	return nil
}

// Read blocks until a raw TLS event is available from the ring buffer,
// or the context is cancelled. Returns the raw bytes of one event.
func (l *TLSLoader) Read(ctx context.Context) ([]byte, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("reading tls_events ring buffer: %w", err)
	}
	return record.RawSample, nil
}

// Close detaches uprobes, closes the ring buffer reader, and unloads
// the eBPF program.
func (l *TLSLoader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	l.closeLinks()
	return l.objs.Close()
}

func (l *TLSLoader) closeLinks() {
	for _, ln := range l.links {
		ln.Close()
	}
	l.links = nil
}

// ensureExecutable sets the executable bit on path if not already set.
// cilium/ebpf requires shared libraries to have the executable bit to open them.
func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode()&0111 != 0 {
		return nil // already executable
	}
	return os.Chmod(path, info.Mode()|0111)
}
