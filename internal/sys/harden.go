package sys

import (
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Harden closes the two ways a secret held in memory reaches the disk without anyone deciding it
// should. Both are real rather than theoretical: this machine writes core dumps to
// /var/lib/systemd/coredump by default, and a dump of a process holding a passphrase is a plain
// file with the passphrase in it, readable by root forever after.
//
//	RLIMIT_CORE = 0   a crash produces no dump at all
//	MADV_DONTDUMP     applied per secret buffer, so even a dump forced elsewhere excludes it
//
// It reports what it managed, because a hardening step that silently fails is worse than one that
// was never attempted — it leaves you believing in a protection you do not have.
func Harden() []string {
	var done []string

	// A zero core limit is honoured by the kernel before any handler runs, so it also defeats
	// systemd-coredump: there is nothing to hand over.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err == nil {
		done = append(done, "core dumps disabled")
	}

	// PR_SET_DUMPABLE 0 additionally stops another process from attaching with ptrace and reading
	// this one's memory — the same thing a debugger does, and the same thing a curious root does.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err == nil {
		done = append(done, "ptrace/dump denied")
	}

	return done
}

// SwapWarning reports active swap, which is the other path from memory to disk. Nothing here can
// prevent a page from being written to an unencrypted swap device; the honest response is to say so
// rather than to imply a guarantee that does not exist.
func SwapWarning() string {
	b, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return ""
	}
	return fmt.Sprintf("swap is active (%d devices) — unless it is encrypted, memory can reach the disk", len(lines)-1)
}

// Secret is a buffer for a value that must not leak: memory outside the Go heap, locked against
// swapping, excluded from core dumps, and overwritten when released.
//
// Not a Go string, and that is the point. A string is immutable, so it cannot be wiped; the garbage
// collector may copy it while compacting, leaving stale copies nowhere anyone can reach to erase.
// An anonymous mapping is the one region whose address and lifetime this program actually controls.
type Secret struct {
	buf    []byte
	n      int
	locked bool
}

// NewSecret allocates a locked buffer of the given capacity.
func NewSecret(size int) (*Secret, error) {
	if size <= 0 {
		size = 256
	}
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	s := &Secret{buf: buf}

	// Mlock keeps the pages resident, so they are never written to swap. The default memlock limit
	// is a few megabytes — ample for one passphrase, and the reason this is a small dedicated buffer
	// rather than an attempt to lock the whole heap, which would simply fail.
	if err := unix.Mlock(buf); err == nil {
		s.locked = true
	}
	// Excluded from any core dump that still happens despite RLIMIT_CORE — a belt beside the brace,
	// and unlike most such pairs this one costs nothing.
	_ = unix.Madvise(buf, unix.MADV_DONTDUMP)
	return s, nil
}

// Locked reports whether the buffer is actually pinned in RAM.
func (s *Secret) Locked() bool { return s != nil && s.locked }

// Append adds bytes, silently ignoring anything past the capacity.
func (s *Secret) Append(b []byte) {
	if s == nil {
		return
	}
	for _, c := range b {
		if s.n >= len(s.buf) {
			return
		}
		s.buf[s.n] = c
		s.n++
	}
}

// Backspace removes the last byte, respecting UTF-8 continuation bytes so deleting one Cyrillic
// character removes the whole character rather than half of it.
func (s *Secret) Backspace() {
	if s == nil || s.n == 0 {
		return
	}
	s.n--
	for s.n > 0 && s.buf[s.n]&0xC0 == 0x80 {
		s.buf[s.n] = 0
		s.n--
	}
	s.buf[s.n] = 0
}

// Len is the number of runes held, for rendering the mask.
func (s *Secret) Len() int {
	if s == nil {
		return 0
	}
	return len([]rune(string(s.buf[:s.n])))
}

// Empty reports whether anything has been entered.
func (s *Secret) Empty() bool { return s == nil || s.n == 0 }

// Reset wipes the contents without releasing the buffer.
func (s *Secret) Reset() {
	if s == nil {
		return
	}
	for i := range s.buf[:s.n] {
		s.buf[i] = 0
	}
	s.n = 0
}

// Use hands the value to fn as a string for the moment it is needed.
//
// This is the seam where the guarantee necessarily weakens, and it is worth naming rather than
// hiding: converting to a string copies the bytes onto the Go heap, where they cannot be wiped.
// The copy is short-lived and the caller is expected to use it and discard it, but a program that
// must compose a password out of this value cannot avoid the moment when it exists as one.
func (s *Secret) Use(fn func(string)) {
	if s == nil {
		fn("")
		return
	}
	fn(string(s.buf[:s.n]))
}

// WriteTo writes the value straight out of the locked buffer, which is the path Use is not.
//
// Nothing becomes a Go string here, so the collector never gets a copy it can duplicate and nobody
// can erase. Use this whenever the destination is a file descriptor — the pipe into `pass` is the
// reason it exists — and keep Use for the cases where a string is genuinely unavoidable.
func (s *Secret) WriteTo(w io.Writer) (int64, error) {
	if s == nil || s.buf == nil {
		return 0, nil
	}
	n, err := w.Write(s.buf[:s.n])
	return int64(n), err
}

// Set replaces the contents in place, so a generated value can be dropped into a field that is
// already holding a locked buffer instead of allocating a second one beside it.
func (s *Secret) Set(b []byte) {
	if s == nil {
		return
	}
	s.Reset()
	s.Append(b)
}

// Equal reports whether two buffers hold the same bytes.
//
// Constant time, because this compares a password against its confirmation and a timing difference
// would leak its length prefix; and without either side becoming a string, which is the whole point
// of holding them here in the first place.
func (s *Secret) Equal(o *Secret) bool {
	if s == nil || o == nil {
		return s == o
	}
	return subtle.ConstantTimeCompare(s.buf[:s.n], o.buf[:o.n]) == 1
}

// Close wipes the buffer and returns it to the kernel.
func (s *Secret) Close() {
	if s == nil || s.buf == nil {
		return
	}
	for i := range s.buf {
		s.buf[i] = 0
	}
	if s.locked {
		_ = unix.Munlock(s.buf)
	}
	_ = unix.Munmap(s.buf)
	s.buf, s.n, s.locked = nil, 0, false
}
