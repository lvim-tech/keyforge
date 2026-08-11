// Package sheet renders a printable password sheet.
//
// A sheet of paper in a drawer is the one backup that survives what none of the digital ones do:
// a rooted machine, a forgotten master passphrase, a disk that will not mount at four in the
// morning. It is also the one backup that leaks if left lying about, so everything here is built
// around getting it printed and gone.
//
// TWO DECISIONS FOLLOW FROM THAT.
//
// The file is written to /dev/shm — a tmpfs, which is RAM. Plaintext secrets therefore never touch
// persistent storage: no journal entry, no block that survives a delete, nothing for a later
// forensic pass to recover. On reboot the file is gone whether or not anyone remembered to remove it.
//
// The document is HTML handed to whichever converter the machine has, rather than a PDF assembled
// here. Writing PDF by hand would mean either restricting labels to Latin (the built-in fonts have
// no Cyrillic) or embedding and subsetting a TrueType font — a few hundred lines of exactly the kind
// of thing this program exists not to reimplement. HTML also stays readable and printable on its own
// when no converter exists at all.
package sheet

import (
	"crypto/rand"
	"fmt"
	"html"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Entry is one line on the sheet.
type Entry struct {
	Label  string // what it opens
	Secret string
	Note   string // optional: host, username, anything worth writing down beside it
}

// pick returns a uniform random integer in [0,n) from the system CSPRNG. The positions of the noise
// must be unguessable too: predictable placement would let anyone holding two sheets subtract them.
func pick(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("invalid range")
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// Options controls the rendering.
type Options struct {
	Title   string
	Entries []Entry
	Folded  bool // draw a fold line, so the sheet can be folded with the secrets inside
}

// Dir is where sheets are written: RAM, not disk. Falls back to the system temp directory only if
// /dev/shm is missing, and the caller is told so it can warn.
func Dir() (path string, inRAM bool) {
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		return "/dev/shm", true
	}
	return os.TempDir(), false
}

// Converters are tried in order. Each takes an HTML path and an output PDF path.
type converter struct {
	name string
	args func(in, out string) []string
}

var converters = []converter{
	{"weasyprint", func(in, out string) []string { return []string{in, out} }},
	{"wkhtmltopdf", func(in, out string) []string { return []string{"--quiet", in, out} }},
	{"google-chrome-stable", func(in, out string) []string {
		return []string{"--headless=new", "--disable-gpu", "--no-pdf-header-footer",
			"--print-to-pdf=" + out, "file://" + in}
	}},
	{"chromium", func(in, out string) []string {
		return []string{"--headless=new", "--disable-gpu", "--no-pdf-header-footer",
			"--print-to-pdf=" + out, "file://" + in}
	}},
	{"libreoffice", func(in, out string) []string {
		return []string{"--headless", "--convert-to", "pdf", "--outdir", filepath.Dir(out), in}
	}},
}

// Converter returns the name of the tool that will be used, or "" when the sheet can only be
// written as HTML. Shown in the interface so the user knows what will happen before it happens.
func Converter() string {
	for _, c := range converters {
		if sys.Have(c.name) {
			return c.name
		}
	}
	return ""
}

// Write renders the sheet and converts it. It returns the path of the file to print — the PDF when
// a converter exists, the HTML otherwise — plus the HTML path, so the caller can remove both.
func Write(o Options) (result, htmlPath string, err error) {
	base, _ := Dir()

	// A PRIVATE DIRECTORY, because the PDF is not ours to create.
	//
	// The HTML below is opened 0600 and is safe from birth. The PDF is written by an external
	// converter — chromium, weasyprint, libreoffice — under ITS umask, which on most machines
	// means 0644, in /dev/shm, which every user on the machine can list. The chmod afterwards
	// closes the window but does not remove it, and the file it closes is a page of passwords.
	// A 0700 directory is the only way to cover a file we do not open ourselves: the converter
	// can create it however it likes and nobody else can reach it.
	stamp := time.Now().Format("20060102-150405")
	dir, err := os.MkdirTemp(base, "keyforge-"+stamp+"-")
	if err != nil {
		return "", "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	htmlPath = filepath.Join(dir, "sheet.html")
	pdfPath := filepath.Join(dir, "sheet.pdf")

	// 0600 from the moment it exists: the window between creating a world-readable file and
	// chmod-ing it is small, and on a machine with other users it is the whole attack.
	f, err := os.OpenFile(htmlPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	if _, err := f.WriteString(render(o)); err != nil {
		_ = f.Close()
		return "", htmlPath, err
	}
	if err := f.Close(); err != nil {
		return "", htmlPath, err
	}

	for _, c := range converters {
		if !sys.Have(c.name) {
			continue
		}
		res, runErr := sys.Run(c.name, c.args(htmlPath, pdfPath)...)
		if runErr == nil && res.OK() {
			// libreoffice ignores the output name and derives it from the input.
			if _, statErr := os.Stat(pdfPath); statErr != nil {
				alt := strings.TrimSuffix(htmlPath, ".html") + ".pdf"
				if _, statErr2 := os.Stat(alt); statErr2 == nil {
					pdfPath = alt
				} else {
					continue
				}
			}
			_ = os.Chmod(pdfPath, 0o600)
			return pdfPath, htmlPath, nil
		}
	}
	return htmlPath, htmlPath, nil
}

// Shred removes a sheet. The name is deliberate about what it does NOT do: on a tmpfs the pages are
// freed and that is genuinely the end of it, but on a journalling filesystem an unlink leaves the
// blocks recoverable. That is precisely why Dir() prefers RAM.
func Shred(paths ...string) {
	// The private directories the files were written into, emptied above and removed after.
	// Left behind they would be a growing list of timestamps in /dev/shm saying when this
	// machine last printed passwords — harmless to open and not harmless to read.
	dirs := map[string]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			if f, err := os.OpenFile(p, os.O_WRONLY, 0o600); err == nil {
				_, _ = f.Write(make([]byte, fi.Size()))
				_ = f.Sync()
				_ = f.Close()
			}
		}
		_ = os.Remove(p)
		if d := filepath.Dir(p); strings.HasPrefix(filepath.Base(d), "keyforge-") {
			dirs[d] = true
		}
	}
	for d := range dirs {
		// Remove, not RemoveAll: an unexpected file in there is a surprise worth leaving for
		// somebody to find rather than deleting on a guess.
		_ = os.Remove(d)
	}
}

func render(o Options) string {
	title := o.Title
	if title == "" {
		title = "Passwords"
	}
	host, _ := os.Hostname()

	var rows strings.Builder
	for i, e := range o.Entries {
		note := ""
		if e.Note != "" {
			note = `<div class="note">` + html.EscapeString(e.Note) + `</div>`
		}
		fmt.Fprintf(&rows, `
    <tr>
      <td class="num">%d</td>
      <td class="label">%s%s</td>
      <td class="secret">%s</td>
    </tr>`, i+1, html.EscapeString(e.Label), note, html.EscapeString(e.Secret))
	}

	fold := ""
	if o.Folded {
		fold = `<div class="fold"></div>`
	}

	// The typography is the point of this document. The secrets are set in a monospace face at a
	// size that can be read across a desk and copied without squinting, because a password sheet
	// that has to be deciphered gets typed wrong, and a password typed wrong at three in the morning
	// is indistinguishable from a password that was never written down.
	return `<!doctype html>
<html lang="bg"><head><meta charset="utf-8"><title>` + html.EscapeString(title) + `</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font-family: "DejaVu Sans", "Noto Sans", system-ui, sans-serif; color: #111; margin: 0; }
  h1 { font-size: 17pt; margin: 0 0 2mm; letter-spacing: .3px; }
  .meta { font-size: 8.5pt; color: #666; margin-bottom: 7mm;
          border-bottom: .4pt solid #bbb; padding-bottom: 2.5mm; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 3.2mm 2mm; vertical-align: top; border-bottom: .4pt dotted #bbb; }
  .num { width: 7mm; color: #999; font-size: 9pt; padding-top: 4.4mm; }
  .label { width: 42mm; font-size: 10.5pt; font-weight: 600; padding-top: 4mm; }
  .note { font-size: 8pt; font-weight: 400; color: #777; margin-top: .8mm; }
  .secret { font-family: "DejaVu Sans Mono", "Noto Sans Mono", monospace;
            font-size: 13.5pt; letter-spacing: .6px; word-break: break-all; line-height: 1.35; }
  .fold { border-top: .4pt dashed #999; margin: 9mm 0; }
  .warn { margin-top: 9mm; font-size: 8.5pt; color: #444;
          border: .4pt solid #999; padding: 3mm 3.5mm; line-height: 1.5; }
  .warn b { color: #000; }
</style></head><body>
  <h1>` + html.EscapeString(title) + `</h1>
  <div class="meta">` + html.EscapeString(host) + ` · ` + time.Now().Format("02.01.2006 15:04") +
		` · ` + fmt.Sprint(len(o.Entries)) + ` entries · keyforge</div>
  <table>` + rows.String() + `
  </table>` + fold + `
  <div class="warn">
    <b>This sheet IS the password.</b> Keep it where you would keep a house key —
    not in a desk drawer, not photographed, not scanned.<br>
    Shred it when it goes. If one of these lines leaks, change it — do not hide it.
  </div>
</body></html>`
}
