// Package sys is the only place in keyforge that shells out. Everything the tool does is a layer
// over ssh-keygen / gpg / openssl / mkcert, so the whole process-spawning surface is deliberately
// concentrated here: one place to audit, one place that decides what may touch a terminal.
//
// The distinction that matters for a tool holding keys:
//
//   - Run captures output and never gives the child a terminal. Use it for questions
//     ("what type is this key", "when does this cert expire") — never for anything that
//     could prompt for a secret, because a captured prompt is an invisible hang.
//   - Interactive hands the REAL terminal over to the child. Passphrases go through this and
//     only this: the secret is typed straight into ssh-keygen's own prompt, so it never enters
//     keyforge's memory, never reaches a command line, and never shows up in `ps`.
package sys

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Result is the outcome of a captured command.
type Result struct {
	Stdout string
	Stderr string
	Code   int
}

// OK reports whether the command exited successfully.
func (r Result) OK() bool { return r.Code == 0 }

// Run executes name with args, captures both streams and returns the exit code instead of an
// error for non-zero exits — callers here nearly always want to inspect the output either way
// (ssh-keygen signals "wrong passphrase" through the exit code, not through a distinct error).
// A genuine failure to START the process is still returned as an error.
func Run(name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	// No stdin: a captured command that decides to prompt must fail fast rather than hang
	// forever behind a TUI that has already repainted over its question.
	cmd.Stdin = nil
	err := cmd.Run()
	res := Result{Stdout: strings.TrimRight(out.String(), "\n"), Stderr: strings.TrimRight(errb.String(), "\n")}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Code = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// RunIn is Run with a working directory.
func RunIn(dir, name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.Stdin = &out, &errb, nil
	err := cmd.Run()
	res := Result{Stdout: strings.TrimRight(out.String(), "\n"), Stderr: strings.TrimRight(errb.String(), "\n")}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Code = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// Interactive builds a command wired to the real terminal. The caller is expected to hand it to
// tea.ExecProcess, which suspends the TUI, restores cooked mode and lets the child own the screen.
//
// This is the ONLY way a passphrase is ever entered. ssh-keygen asks, the user answers, the secret
// lives in ssh-keygen's address space and nowhere else — not in an argv the whole machine can read
// through /proc, not in a Go string that outlives the call, not in a shell history.
func Interactive(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	// GPG_TTY is how gpg tells its agent which terminal to put pinentry on. Without it the agent
	// falls back to whatever terminal it inherited when it was STARTED, which is a different one
	// as often as not — pinentry then either fails outright ("Inappropriate ioctl for device") or,
	// worse, draws its dialog on somebody else's screen and leaves mouse tracking switched on there.
	// The passphrase prompt has to appear on the terminal keyforge just handed over, and this is the
	// documented way to say so.
	if t := TTYName(); t != "" {
		cmd.Env = append(cmd.Env, "GPG_TTY="+t)
	}
	return cmd
}

// TTYName is the terminal this process is attached to, or "" when there is none.
//
// Read from the descriptor rather than from $TTY or ttyname(3), because the value that matters is
// the one the child will actually be handed — under tea.ExecProcess that is this process's stdin.
func TTYName() string {
	n, err := os.Readlink("/proc/self/fd/0")
	if err != nil || !strings.HasPrefix(n, "/dev/") {
		return ""
	}
	return n
}

// Have reports whether a tool is on PATH. Views use it to grey out what this machine cannot do
// rather than offering an action that dies at the moment it is chosen.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Which returns the resolved path of a tool, or "" when absent.
func Which(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// Clipboard copies text using whichever helper this session has. Wayland first (wl-copy), then X11
// (xclip), then the OSC 52 escape as a last resort — that one works over SSH and inside tmux, where
// neither helper exists.
func Clipboard(text string) error {
	if Have("wl-copy") {
		cmd := exec.Command("wl-copy")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	if Have("xclip") {
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	// OSC 52, the fallback this function's comment has always promised and never had. It asks
	// the TERMINAL to hold the text, which is the only mechanism that works over SSH and inside
	// tmux, where neither helper exists. Written to /dev/tty rather than stdout: stdout may be
	// a pipe, and a control sequence in a pipe is corruption rather than a copy.
	//
	// The terminal may refuse — kitty wants clipboard_control, and some multiplexers pass it on
	// only when configured — and there is no reply to read, so this reports success on having
	// sent it. That is honest about what it knows: the alternative is claiming failure on every
	// terminal that quietly complies.
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer func() { _ = tty.Close() }()
		payload := base64.StdEncoding.EncodeToString([]byte(text))
		if _, err := fmt.Fprintf(tty, "\x1b]52;c;%s\a", payload); err == nil {
			return nil
		}
	}
	return errors.New("no clipboard helper (wl-copy / xclip) and the terminal would not take it")
}

// ClearClipboard empties whatever Clipboard filled.
//
// The Passwords tab copies through `pass show --clip`, which wipes itself after 45 seconds, and
// the interface says so. The Generator copied through the helper above and left the value there
// for ever — in the clipboard and in every clipboard manager's history — on the one tab whose
// values are brand-new master-passphrase candidates.
func ClearClipboard() {
	if Have("wl-copy") {
		_ = exec.Command("wl-copy", "--clear").Run()
		return
	}
	if Have("xclip") {
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader("")
		_ = cmd.Run()
		return
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer func() { _ = tty.Close() }()
		_, _ = fmt.Fprint(tty, "\x1b]52;c;!\a")
	}
}
