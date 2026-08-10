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

// Decoy scatters reserved characters through a secret so the printed sheet is not the secret.
//
// It relies on the generator never emitting these characters: every occurrence on paper is
// therefore noise, and the reader who knows the rule removes them by eye with no ambiguity and no
// tooling. The characters are meant to be ORDINARY — a letter, a digit — so the printed value looks
// like an ordinary password. A marker glyph would announce that something was inserted; a "q"
// announces nothing, and an attacker who does not know the scheme does not learn that it exists.
//
// What this is worth, stated plainly so it is not mistaken for more: it defeats someone who finds
// the paper, and it does not defeat someone who knows the rule. Keep the characters out of every
// config file, every note and every conversation — the secrecy of the rule IS the protection.
//
// Positions avoid the first and last two characters. Noise at an edge is the first thing an eye
// notices, and on a word phrase it would deform the opening syllable, which is what makes the whole
// line hard to read back.
func Decoy(secret, reserved string, count int) string {
	r := []rune(reserved)
	if len(r) == 0 || count <= 0 {
		return secret
	}
	out := []rune(secret)
	for i := 0; i < count; i++ {
		if len(out) < 6 {
			break
		}
		span := len(out) - 4 // positions 2 … len-2
		pos, err := pick(span)
		if err != nil {
			return string(out)
		}
		pos += 2
		ci, err := pick(len(r))
		if err != nil {
			return string(out)
		}
		out = append(out[:pos], append([]rune{r[ci]}, out[pos:]...)...)
	}
	return string(out)
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
	dir, _ := Dir()
	stamp := time.Now().Format("20060102-150405")
	htmlPath = filepath.Join(dir, "keyforge-"+stamp+".html")
	pdfPath := filepath.Join(dir, "keyforge-"+stamp+".pdf")

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
