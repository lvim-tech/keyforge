// keyforge — a layer over ssh-keygen, gpg, openssl and pass.
//
// It generates keys and passphrases, and it answers the question those tools never ask on their
// own: which of the secrets on this machine would actually stop someone holding a copy of the files.
//
// Two rules run through the whole program:
//
//	No secret ever reaches a command line. Passphrases are typed into ssh-keygen's own prompt,
//	generated ones go into `pass` through its standard input. Nothing lands in argv, where every
//	local user can read it out of /proc while the command runs.
//
//	Nothing cryptographic is reimplemented. The tools that already exist are the ones doing the
//	work; keyforge only knows which of them to call, with which flags, and in what order.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/audit"
	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/sys"
	"github.com/lvim-tech/keyforge/internal/ui"
)

// version is stamped at build time: go build -ldflags "-X main.version=…"
var version = "dev"

func main() {
	var (
		doAudit = flag.Bool("audit", false, "print the audit as text and exit (for scripts and cron)")
		doGen   = flag.Bool("gen", false, "generate one password and print it")
		words   = flag.Int("words", 5, "number of words for --gen")
		chars   = flag.Int("chars", 0, "if >0, --gen makes a character string of this length instead of a phrase")
		showVer = flag.Bool("version", false, "version")
	)
	flag.Usage = usage
	flag.Parse()

	// Before anything else, and before any secret can exist in this process: no core dumps, no
	// ptrace. On this machine a dump would land in /var/lib/systemd/coredump as a plain file — a
	// passphrase written to disk by a crash nobody asked for.
	hardening := sys.Harden()

	switch {
	case *showVer:
		fmt.Println("keyforge", version)
		fmt.Println("hardening:", strings.Join(hardening, ", "))
		if w := sys.SwapWarning(); w != "" {
			fmt.Println("warning:", w)
		}
	case *doAudit:
		os.Exit(runAudit())
	case *doGen:
		os.Exit(runGen(*words, *chars))
	default:
		p := tea.NewProgram(ui.New(), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "keyforge:", err)
			os.Exit(1)
		}
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `keyforge — keys, passwords and audit

  keyforge                interactive interface
  keyforge --audit        check ~/.ssh and the system, as text
  keyforge --gen          generate a phrase (--words N) or a string (--chars N)

With no arguments it starts the interface.
`)
}

// runAudit prints the sweep as plain text. Exit code carries the verdict so a cron job or a shell
// prompt can react without parsing anything: 0 clean, 1 warnings, 2 something is open right now.
func runAudit() int {
	rep := audit.Run()
	high, warn, info := rep.Counts()

	fmt.Printf("keyforge audit · %d keys · %d known hosts\n\n", rep.Keys, rep.Hosts)
	if len(rep.Findings) == 0 {
		fmt.Println("Nothing to report.")
		return 0
	}
	for _, sev := range []audit.Severity{audit.High, audit.Warn, audit.Info} {
		for _, f := range rep.Findings {
			if f.Severity != sev {
				continue
			}
			fmt.Printf("[%-8s] %-24s %s\n", sev, f.Subject, f.Message)
			if f.Action != "" {
				fmt.Printf("%-11s %-24s → %s\n", "", "", f.Action)
			}
		}
	}
	fmt.Printf("\nhigh: %d   warn: %d   info: %d\n", high, warn, info)
	switch {
	case high > 0:
		return 2
	case warn > 0:
		return 1
	}
	return 0
}

// runGen prints one secret to stdout and its strength to stderr, so the value can be piped while
// the assessment still reaches a human:
//
//	keyforge --gen | pass insert -e ssh/newkey
func runGen(words, chars int) int {
	var (
		value string
		bits  float64
		err   error
	)
	if chars > 0 {
		o := passgen.DefaultOptions()
		o.Length = chars
		value, bits, err = passgen.Password(o)
	} else {
		o := passgen.DefaultPhraseOptions()
		o.Words = words
		value, bits, err = passgen.Phrase(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyforge:", err)
		return 1
	}
	label, detail := passgen.Strength(bits)
	fmt.Println(value)
	fmt.Fprintf(os.Stderr, "%s · %s\n", capitalise(label), detail)
	return 0
}

// capitalise upper-cases the first RUNE. Slicing [:1] would cut a Cyrillic letter in half — its
// first byte alone is not a character, and the terminal renders the remainder as replacement marks.
func capitalise(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[0])) + string(r[1:])
}
