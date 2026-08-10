package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sheet"
)

type printMode int

const (
	pmList printMode = iota
	pmEntry
	pmMask
	pmSave
)

// row is one line destined for the sheet. Both forms are kept together from the moment they are
// made: deriving the printed value and the real one separately is how a sheet ends up not matching
// the account it was printed for.
type row struct {
	label   string
	note    string
	paper   string
	real    string
	bits    float64
	include bool
	phrase  bool
}

type printView struct {
	rows []row
	sel  int
	mode printMode
	mask sheet.Mask

	// what was written last, so it can be shredded from here
	lastFile string
	lastHTML string

	// rev shows the real values instead of the printed ones. Shared with every other tab that holds
	// a secret, so the toggle, the timer and the wording are the same wherever a value can appear.
	rev reveal

	// entry form
	fLabel, fNote input
	fPhrase       bool
	fLen          int
	fField        int

	// mask form: structure in plain fields, values in a locked, masked one
	mStrip, mCount, mMarkers input
	mValues                  *secretInput
	mField                   int

	// pass export
	fPrefix input

	cfg      config.Config
	cfgErr   string
	cfgSaved bool // the structure on screen matches what is on disk
}

func newPrintView() *printView {
	cfg, err := config.Load()
	v := &printView{
		fLabel:   newInput("label", "what it opens — Neterra root, GitHub…"),
		fNote:    newInput("note", "user, host, whatever helps (optional)"),
		mStrip:   newInput("strip characters", "e.g. q7 — the generator will never produce them"),
		mCount:   newInput("insert count", "2"),
		mMarkers: newInput("markers", "e.g. z — the characters the remembered part hides behind"),
		mValues:  newSecretInput("values", "marker=what you remember — never shown, never stored"),
		fPrefix:  newInput("folder in pass", "sheet/2026-08"),
		fPhrase:  true,
		cfg:      cfg,
	}
	if err != nil {
		v.cfgErr = err.Error()
	}
	v.fLen = cfg.PasswordLength

	// The remembered STRUCTURE goes straight into the form, so the only thing left to type is the
	// part that is actually a secret. Nothing here restores a value: there is none to restore.
	v.mStrip.set(cfg.Sheet.Strip)
	if cfg.Sheet.StripCount > 0 {
		v.mCount.set(strconv.Itoa(cfg.Sheet.StripCount))
	}
	var markers strings.Builder
	for _, r := range cfg.Sheet.MarkerRunes() {
		markers.WriteRune(r)
	}
	v.mMarkers.set(markers.String())
	v.cfgSaved = true
	return v
}

// origin describes where the structure on screen came from, so the user is never left guessing why
// a rule is already filled in — or believing a change is saved when it is not.
func (v *printView) origin() string {
	switch {
	case !v.cfgSaved:
		return "unsaved — [w] writes it"
	case config.BuiltIn():
		return "built in at compile time"
	default:
		return "from " + config.Path()
	}
}

func (v *printView) Title() string { return "Print" }

func (v *printView) capturesInput() bool { return v.mode != pmList }

func (v *printView) Init() tea.Cmd { return nil }

func (v *printView) Update(msg tea.Msg) (view, tea.Cmd) {
	// The hide timer is broadcast rather than typed, so it is taken before the cast below discards
	// everything that is not a key press.
	if v.rev.expired(msg) {
		return v, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}
	switch v.mode {
	case pmEntry:
		return v.updateEntry(key)
	case pmMask:
		return v.updateMask(key)
	case pmSave:
		return v.updateSave(key)
	}
	return v.updateList(key)
}

func (v *printView) updateList(key tea.KeyMsg) (view, tea.Cmd) {
	switch key.String() {
	case "j", "down":
		if v.sel < len(v.rows)-1 {
			v.sel++
		}
	case "k", "up":
		if v.sel > 0 {
			v.sel--
		}
	case "n":
		v.mode, v.fField = pmEntry, 0
		v.fLabel.set("")
		v.fNote.set("")
	case " ":
		if v.sel < len(v.rows) {
			v.rows[v.sel].include = !v.rows[v.sel].include
		}
	case "g":
		if v.sel < len(v.rows) {
			r := &v.rows[v.sel]
			paper, real, bits, err := v.generate(r.phrase, v.fLen)
			if err != nil {
				return v, failure("%v", err)
			}
			r.paper, r.real, r.bits = paper, real, bits
			return v, status("regenerated")
		}
	case "d":
		if v.sel < len(v.rows) {
			v.rows = append(v.rows[:v.sel], v.rows[v.sel+1:]...)
			if v.sel >= len(v.rows) {
				v.sel = maxi(0, len(v.rows)-1)
			}
		}
	case "m":
		v.mode, v.mField = pmMask, 0
	case "v":
		return v, v.rev.toggle()
	case "x":
		return v.export()
	case "s":
		if !passstore.Available() {
			return v, failure("pass is not initialised")
		}
		if v.countIncluded() == 0 {
			return v, failure("nothing is ticked")
		}
		v.mode = pmSave
		v.fPrefix.set("")
	case "w":
		v.cfg.Sheet.Strip = strings.TrimSpace(v.mStrip.String())
		if n, err := strconv.Atoi(strings.TrimSpace(v.mCount.String())); err == nil {
			v.cfg.Sheet.StripCount = n
		}
		v.cfg.Sheet.SetMarkers(strings.TrimSpace(v.mMarkers.String()))
		v.cfg.PasswordLength = v.fLen
		if err := config.Save(v.cfg); err != nil {
			return v, failure("write: %v", err)
		}
		v.cfgSaved = true
		return v, status("the structure was written to %s — the value was NOT", config.Path())

	case "S":
		if v.lastFile == "" {
			return v, failure("no exported file")
		}
		sheet.Shred(v.lastFile, v.lastHTML)
		v.lastFile, v.lastHTML = "", ""
		return v, status("the file was wiped from memory")
	}
	return v, nil
}

// generate produces one row's pair, with the length reduced by the mask's overhead so the printed
// value lands on the round number the user asked for.
func (v *printView) generate(phrase bool, length int) (paper, real string, bits float64, err error) {
	var base string
	if phrase {
		o := passgen.DefaultPhraseOptions()
		o.Reserved = v.mask.Reserved()
		base, bits, err = passgen.Phrase(o)
	} else {
		o := passgen.DefaultOptions()
		o.Reserved = v.mask.Reserved()
		o.Length = length - v.mask.Overhead()
		if o.Length < 8 {
			o.Length = 8
		}
		base, bits, err = passgen.Password(o)
	}
	if err != nil {
		return "", "", 0, err
	}
	paper, real = sheet.Compose(base, v.mask)
	return paper, real, bits, nil
}

func (v *printView) updateEntry(key tea.KeyMsg) (view, tea.Cmd) {
	switch key.String() {
	case "esc":
		v.mode = pmList
		return v, nil
	case "tab", "down":
		v.fField = (v.fField + 1) % 3
		return v, nil
	case "shift+tab", "up":
		v.fField = (v.fField + 2) % 3
		return v, nil
	case "enter":
		if v.fLabel.empty() {
			return v, failure("the label is required — a sheet without labels is useless")
		}
		paper, real, bits, err := v.generate(v.fPhrase, v.fLen)
		if err != nil {
			return v, failure("%v", err)
		}
		v.rows = append(v.rows, row{
			label:   strings.TrimSpace(v.fLabel.String()),
			note:    strings.TrimSpace(v.fNote.String()),
			paper:   paper,
			real:    real,
			bits:    bits,
			include: true,
			phrase:  v.fPhrase,
		})
		v.sel = len(v.rows) - 1
		v.mode = pmList
		return v, status("added: %s", v.rows[v.sel].label)
	}
	if v.fField == 2 {
		switch key.String() {
		case "left", "right", "h", "l", " ":
			v.fPhrase = !v.fPhrase
		case "+", "=":
			v.fLen++
		case "-", "_":
			if v.fLen > 10 {
				v.fLen--
			}
		}
		return v, nil
	}
	if v.fField == 0 {
		v.fLabel.update(key)
	} else {
		v.fNote.update(key)
	}
	return v, nil
}

func (v *printView) updateMask(key tea.KeyMsg) (view, tea.Cmd) {
	switch key.String() {
	case "esc":
		v.mode = pmList
		return v, nil
	case "tab", "down":
		v.mField = (v.mField + 1) % 4
		return v, nil
	case "shift+tab", "up":
		v.mField = (v.mField + 3) % 4
		return v, nil
	case "enter":
		var (
			m      sheet.Mask
			perr   error
			values string
		)
		v.mValues.use(func(s string) { values = s })
		m, perr = parseMask(v.mStrip.String(), v.mCount.String(), v.mMarkers.String(), values)
		values = ""
		if perr != nil {
			return v, failure("%v", perr)
		}
		v.mask = m
		v.mode = pmList
		v.cfgSaved = v.structureMatchesConfig()
		// Existing rows were made under the previous rule and would no longer decode by the new
		// one. Regenerating is the only honest option: silently keeping them would produce a sheet
		// where half the lines follow a rule the other half does not.
		for i := range v.rows {
			paper, real, bits, err := v.generate(v.rows[i].phrase, v.fLen)
			if err != nil {
				return v, failure("%v", err)
			}
			v.rows[i].paper, v.rows[i].real, v.rows[i].bits = paper, real, bits
		}
		if len(v.rows) > 0 {
			return v, status("the rule changed — every row was regenerated")
		}
		return v, status("rule: %s", m.Legend())
	}
	switch v.mField {
	case 0:
		v.mStrip.update(key)
	case 1:
		v.mCount.update(key)
	case 2:
		v.mMarkers.update(key)
	default:
		v.mValues.update(key)
	}
	return v, nil
}

// structureMatchesConfig reports whether the form still equals what was loaded, which is what the
// origin line and the [w] hint key off.
func (v *printView) structureMatchesConfig() bool {
	if strings.TrimSpace(v.mStrip.String()) != v.cfg.Sheet.Strip {
		return false
	}
	n, _ := strconv.Atoi(strings.TrimSpace(v.mCount.String()))
	if n != v.cfg.Sheet.StripCount {
		return false
	}
	var markers strings.Builder
	for _, r := range v.cfg.Sheet.MarkerRunes() {
		markers.WriteRune(r)
	}
	return strings.TrimSpace(v.mMarkers.String()) == markers.String()
}

func (v *printView) updateSave(key tea.KeyMsg) (view, tea.Cmd) {
	switch key.String() {
	case "esc":
		v.mode = pmList
		return v, nil
	case "enter":
		prefix := strings.Trim(strings.TrimSpace(v.fPrefix.String()), "/")
		if prefix == "" {
			return v, failure("a folder is required")
		}
		n, failed := 0, ""
		for _, r := range v.rows {
			if !r.include {
				continue
			}
			name := prefix + "/" + passstore.SuggestName("", slug(r.label))
			meta := map[string]string{"generated-by": "keyforge", "entropy": fmt.Sprintf("%.0f bits", r.bits)}
			if r.note != "" {
				meta["note"] = r.note
			}
			// The REAL value goes in, never the printed one. The store is encrypted; a riddle
			// inside it would only mean that one day you cannot open your own password.
			if err := passstore.Insert(name, r.real, meta); err != nil {
				failed = err.Error()
				break
			}
			n++
		}
		v.mode = pmList
		if failed != "" {
			return v, failure("stored %d, then: %s", n, failed)
		}
		return v, status("stored %d in pass under %s/", n, prefix)
	}
	v.fPrefix.update(key)
	return v, nil
}

func (v *printView) export() (view, tea.Cmd) {
	var entries []sheet.Entry
	for _, r := range v.rows {
		if r.include {
			entries = append(entries, sheet.Entry{Label: r.label, Secret: r.paper, Note: r.note})
		}
	}
	if len(entries) == 0 {
		return v, failure("nothing is ticked")
	}
	out, html, err := sheet.Write(sheet.Options{Title: "Passwords", Entries: entries, Folded: true})
	if err != nil {
		return v, failure("%v", err)
	}
	v.lastFile, v.lastHTML = out, html
	return v, status("%s — print it, then press [S] to wipe it", out)
}

func (v *printView) countIncluded() int {
	n := 0
	for _, r := range v.rows {
		if r.include {
			n++
		}
	}
	return n
}

// parseMask reads the rule form. Structure and secret arrive separately: `markers` says WHICH
// characters stand for something, `values` says what they stand for. Only the first half is ever
// eligible to be written anywhere.
func parseMask(strip, count, markers, values string) (sheet.Mask, error) {
	m := sheet.Mask{Strip: strings.TrimSpace(strip)}
	if c := strings.TrimSpace(count); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 {
			return m, fmt.Errorf("the insert count must be a number")
		}
		m.StripN = n
	}
	if m.Strip == "" {
		m.StripN = 0
	}
	declared := map[rune]bool{}
	for _, r := range strings.TrimSpace(markers) {
		if r == ' ' || r == ',' {
			continue
		}
		if strings.ContainsRune(m.Strip, r) {
			return m, fmt.Errorf("%q is both a strip character and a marker — pick one", string(r))
		}
		declared[r] = true
	}

	parsed, err := config.ParseValues(values)
	if err != nil {
		return m, err
	}
	for marker, val := range parsed {
		if !declared[marker] {
			return m, fmt.Errorf("%q has a value but was not declared as a marker", string(marker))
		}
		if m.Expand == nil {
			m.Expand = map[rune]string{}
		}
		m.Expand[marker] = val
	}
	for r := range declared {
		if m.Expand[r] == "" {
			return m, fmt.Errorf("marker %q has no value", string(r))
		}
	}
	return m, nil
}

// slug turns a label into something safe for a pass entry path.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '_', r == '.':
			b.WriteRune('-')
		case r == '-':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "entry"
	}
	return out
}

func (v *printView) Render(w, h int) string {
	switch v.mode {
	case pmEntry:
		return v.renderEntry(w)
	case pmMask:
		return v.renderMask(w)
	case pmSave:
		return v.renderSave(w)
	}
	return v.renderList(w, h)
}

func (v *printView) renderList(w, h int) string {
	var b strings.Builder

	// A loaded structure without values is not "no rule" — it is a rule waiting for the one part
	// that was never written down. Saying "the sheet holds the passwords themselves" there would be true of the
	// current state and badly misleading about the intent.
	rule := v.mask.Legend()
	if v.mask.Empty() && (strings.TrimSpace(v.mStrip.String()) != "" || strings.TrimSpace(v.mMarkers.String()) != "") {
		rule = "the structure is loaded — press [m] and type the value"
	}
	conv := sheet.Converter()
	if conv == "" {
		conv = stWarn.Render("no converter — HTML will come out instead")
	} else {
		conv = stFg.Render(conv)
	}
	dir, inRAM := sheet.Dir()
	where := stGood.Render(dir + " (in memory)")
	if !inRAM {
		where = stWarn.Render(dir + " (on disk!)")
	}
	b.WriteString("  " + stDim.Render("rule:    ") + stAccent.Render(rule) + stDim.Render("   ("+v.origin()+")") + "\n")
	b.WriteString("  " + stDim.Render("writes:  ") + where + stDim.Render("   via: ") + conv + "\n\n")

	if len(v.rows) == 0 {
		b.WriteString(stDim.Render("  Empty sheet. [n] adds an entry, [m] sets the rule.\n\n"))
		b.WriteString(indent(stNote.Render("Paper is the only backup that survives a compromised machine\nand a forgotten master password."), 2))
		return b.String()
	}

	b.WriteString(stDim.Render(fmt.Sprintf("     %-24s %-34s %s", "label", "on the sheet", "the password")) + "\n")
	for i, r := range v.rows {
		mark := "  "
		st := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			st = stRowSel
		}
		box := stDim.Render("")
		if r.include {
			box = stGood.Render("")
		}
		real := mask(r.real)
		if v.rev.on {
			real = r.real
		}
		bg := st.GetBackground()
		b.WriteString(mark + box + " " +
			cell(r.label, 24, st) + " " +
			cell(r.paper, 34, stFg.Background(bg)) + " " +
			cell(real, maxi(w-70, 8), stAccent.Background(bg)) + "\n")
	}

	if v.sel < len(v.rows) {
		r := v.rows[v.sel]
		label, detail := passgen.Strength(r.bits)
		b.WriteString("\n  " + stDim.Render(label+" · "+detail))
		if !v.mask.Empty() {
			b.WriteString(stDim.Render(" + the remembered part"))
		}
		if r.note != "" {
			b.WriteString("\n  " + stDim.Render("note: ") + stFg.Render(r.note))
		}
		b.WriteString("\n")
	}
	if v.lastFile != "" {
		b.WriteString("\n  " + stNote.Render("last file: "+v.lastFile) + stDim.Render("  — [S] wipes it"))
	}
	return b.String()
}

func (v *printView) renderEntry(w int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render("  New entry for the sheet") + "\n\n")
	b.WriteString("  " + v.fLabel.render(v.fField == 0) + "\n")
	b.WriteString("  " + v.fNote.render(v.fField == 1) + "\n")
	kind := "word phrase"
	if !v.fPhrase {
		kind = fmt.Sprintf("random characters, %d", v.fLen)
	}
	lbl := stDim.Render("kind: ")
	if v.fField == 2 {
		lbl = stKey.Render("kind: ")
		kind = stRowSel.Render(" " + kind + " ")
	}
	b.WriteString("  " + lbl + kind + stDim.Render("   (←/→ switches, +/− length)") + "\n\n")
	if !v.mask.Empty() {
		b.WriteString(stDim.Render("  The rule will be applied: ") + stAccent.Render(v.mask.Legend()) + "\n")
		b.WriteString(stDim.Render(fmt.Sprintf("  Generated %d characters shorter, so the sheet shows a round number.", v.mask.Overhead())))
	}
	return stBox.Width(w - 2).Render(b.String())
}

func (v *printView) renderMask(w int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render("  Rule for the sheet") + "\n\n")
	b.WriteString("  " + v.mStrip.render(v.mField == 0) + "\n")
	b.WriteString("  " + v.mCount.render(v.mField == 1) + "\n")
	b.WriteString("  " + v.mMarkers.render(v.mField == 2) + "\n")
	b.WriteString("  " + v.mValues.render(v.mField == 3) + "\n\n")
	b.WriteString(stDim.Render(
		"  Strip characters make the sheet look like an ordinary password —\n"+
			"  they hide that a rule exists at all. Insertion is the stronger one:\n"+
			"  the sheet genuinely does NOT contain the password; a piece is\n"+
			"  missing that lives only in your head.\n\n") +
		stWarn.Render("  None of this is stored anywhere — not in the config, not on the sheet.\n"+
			"  Forget it and every sheet becomes useless."))
	return stBox.Width(w - 2).Render(b.String())
}

func (v *printView) renderSave(w int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render(fmt.Sprintf("  Store %d ticked entries in pass", v.countIncluded())) + "\n\n")
	b.WriteString("  " + v.fPrefix.render(true) + "\n\n")
	b.WriteString(stDim.Render("  The REAL password goes in, not the printed one.\n" +
		"  The store is encrypted — a riddle inside it would only mean that one\n" +
		"  day you cannot open your own password."))
	return stBox.Width(w - 2).Render(b.String())
}

func (v *printView) Footer() string {
	switch v.mode {
	case pmEntry, pmMask, pmSave:
		return joinHints(hint("enter", "confirm"), hint("esc", "cancel"))
	}
	f := []string{
		hint("n", "new"), hint("space", "tick"), hint("g", "regen"),
		hint("m", "rule"), revealHint(v.rev.on), hint("x", "export"), hint("d", "remove"),
	}
	if !v.cfgSaved {
		f = append(f, hint("w", "save structure"))
	}
	if passstore.Available() {
		f = append(f, hint("s", "to pass"))
	}
	if v.lastFile != "" {
		f = append(f, hint("S", "wipe file"))
	}
	return joinHints(f...)
}
