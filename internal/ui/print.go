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
	"github.com/lvim-tech/keyforge/internal/sys"
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
	label    string
	note     string
	paper    string
	real     string
	bits     float64
	include  bool
	phrase   bool
	imported bool
}

type printView struct {
	rows []row
	sel  int
	mode printMode
	mask sheet.Mask

	// imported reports rows that came out of `pass` rather than out of the generator. They
	// are marked because almost everything the sheet says about a row is only true of one it
	// made itself: it knows the entropy of what it generated and nothing about what you chose.
	// A strength verdict on an imported password would be a number invented to fill a column.
	importNote string

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

	cfg config.Config

	// rule is the whole scheme, values included, as it came back from the encrypted entry.
	// mWhere is the name of that entry — chosen by the user, meaning nothing to anyone else.
	rule   sheet.Rule
	rules  *ruleCache
	mWhere input
}

func newPrintView(cfg config.Config, rules *ruleCache) *printView {
	v := &printView{
		fLabel:   newInput("label", "what it opens — Neterra root, GitHub…"),
		fNote:    newInput("note", "user, host, whatever helps (optional)"),
		mStrip:   newMaskedInput("strip characters", "e.g. q7 — the generator will never produce them"),
		mCount:   newInput("insert count", "2"),
		mMarkers: newMaskedInput("markers", "e.g. z — the characters the remembered part hides behind"),
		mValues:  newSecretInput("values", "what you remember (marker=value if there are several)"),
		mWhere:   newInput("keep it in", "leave blank and one will be made up"),
		fPrefix:  newInput("folder in pass", "sheet/2026-08"),
		fPhrase:  true,
		cfg:      cfg,
	}
	v.fLen = cfg.PasswordLength

	// NOTHING is read here. The rule arrives when an action asks for it — [n], [i], [m] or
	// [x] — because reading it at construction is what made opening keyforge raise a
	// passphrase prompt for a sheet nobody had asked to print.
	v.rules = rules
	if cfg.Sheet.RuleFrom != "" {
		v.mWhere.set(cfg.Sheet.RuleFrom)
	}
	return v
}

// loadRule brings the rule in for the action that needs it, and fills the form from it.
//
// Called by every entry point rather than once, so the first of them pays the prompt and the
// rest are free for as long as the cache holds.
func (v *printView) loadRule() error {
	r, err := v.rules.get()
	if err != nil {
		return err
	}
	v.rule = r
	v.mask = r.Mask()
	v.mStrip.set(r.Strip)
	if r.StripN > 0 {
		v.mCount.set(strconv.Itoa(r.StripN))
	} else {
		v.mCount.set("")
	}
	var markers strings.Builder
	for k := range r.Markers {
		markers.WriteRune(k)
	}
	v.mMarkers.set(markers.String())
	return nil
}

// saveRule writes the whole scheme into the entry the user named, and puts only that name
// into the config.
//
// Nothing about this is reported anywhere afterwards. There is no "rule: set" line and no
// audit entry once it exists, because the absence of a mention IS the state: a machine that
// announces a masking scheme has given away the one thing the scheme depends on.
func (v *printView) saveRule() error {
	where := strings.Trim(strings.TrimSpace(v.mWhere.String()), "/")
	if where == "" {
		// Left blank on purpose is the ordinary case, so the ordinary case gets the better
		// answer: a random name rather than one somebody would have thought up, which tends
		// to say what it is.
		g, err := sheet.GenerateName()
		if err != nil {
			return err
		}
		where = g
	}
	if !passstore.Available() {
		return fmt.Errorf("pass is not initialised, so there is nowhere to keep it")
	}
	r := v.rule
	if err := sheet.ValidateRule(r); err != nil {
		return err
	}

	body := r.Encode()
	sec, err := sys.NewSecret(len(body) + 16)
	if err != nil {
		return err
	}
	defer sec.Close()
	sec.Append([]byte(body))

	if passstore.Exists(where) {
		// Overwriting is allowed for the rule's OWN entry and for nothing else. "Keep it in"
		// takes a free-form store path, so a user who types the name of a real login here — a
		// perfectly natural thing to do while thinking about where the rule should live — had
		// that password replaced by the encoded rule, silently and unrecoverably outside a
		// git-backed store. Insert and Replace were split apart in passstore precisely so no
		// call could fail to find what you meant and quietly do the other thing; this call
		// site was the one place that undid it.
		if where != v.cfg.Sheet.RuleFrom {
			if err := rulePresent(where); err != nil {
				return err
			}
		}
		err = passstore.Replace(where, sec, nil)
	} else {
		err = passstore.InsertSecret(where, sec, nil)
	}
	if err != nil {
		return err
	}

	// Only this one field, through Update: writing the whole of this view's startup copy would
	// put its stale lock/agent sections over anything Settings saved earlier in the session.
	updated, err := config.Update(func(c *config.Config) { c.Sheet.RuleFrom = where })
	if err != nil {
		return err
	}
	v.cfg = updated
	// The cache is told, or nothing in this process knows the rule exists until a restart.
	// The Generator asks the cache — not this view — for the characters it must not produce,
	// so without this the very next password made after the setup would be generated free of
	// a rule that had just been written, and would not survive being put on a sheet.
	v.rules.adopt(where, body)
	v.mWhere.set(where)
	return nil
}

// rulePresent reports whether an existing entry actually holds a rule, and refuses by name when it
// does not. Reading it costs a decryption — the same one saving the rule would have needed anyway —
// and it is the only way to tell a rule entry apart from a password: both are one line of text.
func rulePresent(name string) error {
	sec, err := passstore.Reveal(name)
	if err != nil {
		return fmt.Errorf("%q already exists and could not be read, so it will not be written over: %v", name, err)
	}
	defer sec.Close()
	ok := false
	sec.Use(func(body string) { _, ok = sheet.DecodeRuleStrict(body) })
	if !ok {
		return fmt.Errorf("%q already exists and does not hold a rule — pick another name", name)
	}
	return nil
}

func (v *printView) Title() string { return "Print" }

func (v *printView) capturesInput() bool { return v.mode != pmList }

func (v *printView) Init() tea.Cmd { return nil }

func (v *printView) Update(msg tea.Msg) (view, tea.Cmd) {
	if _, ok := msg.(openRuleMsg); ok {
		if err := v.loadRule(); err != nil {
			return v, failure("%v", err)
		}
		v.mode, v.mField = pmMask, 0
		return v, nil
	}
	if _, ok := msg.(forgetMsg); ok {
		// This view held MORE in the clear than any other and was the only one not listening.
		// Every row carries the real password; v.rule and v.mask carry the marker values —
		// the one thing in this design that is never written down. Behind a curtain that has
		// just told gpg-agent to forget, keyforge went on holding all of it.
		//
		// The sheet goes with it. Losing an unfinished sheet to a lock is a real cost and it
		// is the smaller one: the alternative is a lock that covers the screen while the
		// passwords sit behind it, which is the thing this program exists to not do. Rows
		// imported from `pass` come back with [i]; generated ones were never stored anyway.
		v.rev.hide()
		v.rows, v.sel = nil, 0
		v.rule, v.mask = sheet.Rule{}, sheet.Mask{}
		v.mStrip.set("")
		v.mCount.set("")
		v.mMarkers.set("")
		v.mValues.reset()
		v.importNote = ""
		v.mode = pmList
		return v, nil
	}
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
		if err := v.loadRule(); err != nil {
			return v, failure("%v", err)
		}
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
			wasImported := r.imported
			r.paper, r.real, r.bits = paper, real, bits
			// It is no longer what `pass` holds, so it must stop claiming to be. A row that
			// still read "from pass" after being regenerated would put a password on the
			// sheet that the account has never had — the sheet and the store disagreeing,
			// silently, which is the failure a paper backup exists to rule out.
			r.imported = false
			if wasImported {
				return v, status("regenerated — this is a NEW password; [s] puts it in pass")
			}
			return v, status("regenerated")
		}
	case "d":
		if v.sel < len(v.rows) {
			v.rows = append(v.rows[:v.sel], v.rows[v.sel+1:]...)
			if v.sel >= len(v.rows) {
				v.sel = max(0, len(v.rows)-1)
			}
		}
	case "i":
		if err := v.loadRule(); err != nil {
			return v, failure("%v", err)
		}
		return v.importFromStore()
	case "m":
		// Only while there is no rule. Once one exists this key does nothing and is not
		// offered: changing a rule silently invalidates every sheet already printed under
		// the old one, and a key that says "rule" on a machine that has one announces the
		// scheme to anyone reading over a shoulder. The setup form is still reachable — the
		// Generator sends openRuleMsg when it finds no rule — which is the one moment it is
		// meant to be reachable.
		if v.rules.configured() {
			return v, nil
		}
		if err := v.loadRule(); err != nil {
			return v, failure("%v", err)
		}
		v.mode, v.mField = pmMask, 0
	case "v":
		return v, v.rev.toggle()
	case "x":
		if err := v.loadRule(); err != nil {
			return v, failure("%v", err)
		}
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
	// [w] is gone. It survived from when the rule was typed into the config, and after the
	// form began storing on [enter] the only state it could ever reach was this: no rule yet,
	// so nothing has been entered, so v.rule is EMPTY — and it wrote that empty rule into
	// `pass`, set sheet.rule_from to point at it, and by doing so made rules.configured()
	// true. That gated [m] and silenced the generator's offer, permanently, with no way back
	// from inside the program. A key whose every reachable outcome is harm is not a key.

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
		// From the config, like the Generator: phrase_words and separator were being ignored
		// here too, so a sheet made in Print did not match a password made two tabs away.
		o := passgen.DefaultPhraseOptions()
		if v.cfg.PhraseWords > 0 {
			o.Words = v.cfg.PhraseWords
		}
		if v.cfg.Separator != "" {
			o.Separator = v.cfg.Separator
		}
		o.Reserved = v.mask.Reserved()
		base, bits, err = passgen.Phrase(o)
	} else {
		o := passgen.DefaultOptions()
		if v.cfg.Ambiguous != "" {
			o.Ambiguous = v.cfg.Ambiguous
		}
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
		v.mField = (v.mField + 1) % 5
		return v, nil
	case "shift+tab", "up":
		v.mField = (v.mField + 4) % 5
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
		v.rule = sheet.Rule{Strip: m.Strip, StripN: m.StripN, Markers: m.Expand}
		v.mode = pmList

		// Stored here, on the same key that confirms it. It used to take a second press of
		// [w] afterwards — while the form itself said "[w] keeps all of it", on a screen
		// where w is simply typed into a field. A rule that looked saved and was not is the
		// worst of the three states this form can be in, and the two-step existed for no
		// reason: defining the rule and keeping it are the same intention.
		if err := v.saveRule(); err != nil {
			return v, failure("%v", err)
		}
		// Existing rows were made under the previous rule and would no longer decode by the new
		// one. Regenerating is the only honest option: silently keeping them would produce a sheet
		// where half the lines follow a rule the other half does not.
		regenerated := 0
		for i := range v.rows {
			paper, real, bits, err := v.generate(v.rows[i].phrase, v.fLen)
			if err != nil {
				return v, failure("%v", err)
			}
			v.rows[i].paper, v.rows[i].real, v.rows[i].bits = paper, real, bits
			// Same reason as [g]: this is no longer the password `pass` holds, so the row must
			// stop saying it came from there. A sheet that claims "from pass" for a password
			// the store has never had is the sheet/store divergence this file exists to avoid.
			if v.rows[i].imported {
				v.rows[i].imported = false
				regenerated++
			}
		}
		if regenerated > 0 {
			return v, status("stored as %s — %d imported %s now NEW; [s] puts them in pass",
				v.mWhere.String(), regenerated, plural(regenerated, "password is", "passwords are"))
		}
		if len(v.rows) > 0 {
			return v, status("stored as %s — every row was regenerated", v.mWhere.String())
		}
		return v, status("stored as %s", v.mWhere.String())
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

// importFromStore fills the sheet from `pass`.
//
// This is the paper backup of a store that already exists, as opposed to the sheet made
// while the passwords are being chosen. Every entry has to be decrypted to be printed —
// there is no reading a password without opening it — so this asks the agent once and is
// the one action in this tab that can fail because a passphrase was not given.
func (v *printView) importFromStore() (view, tea.Cmd) {
	if !passstore.Available() {
		return v, failure("pass is not initialised")
	}
	entries, err := passstore.Entries()
	if err != nil {
		return v, failure("%v", err)
	}
	if len(entries) == 0 {
		return v, failure("the store is empty")
	}

	// Rows already on the sheet, so a second [i] adds what is new instead of a second copy
	// of everything. Importing twice used to double the sheet, and two identical lines with
	// different noise on them look like two different passwords for the same account.
	have := map[string]bool{}
	for _, r := range v.rows {
		have[r.label] = true
	}

	added, dropped, again := 0, false, 0
	// Grouped by REASON, so the sentence is said once and the entries are a list under it.
	// Four refusals used to mean the same clause four times, wrapped across eight lines, with
	// the store paths buried inside it.
	refused := map[string][]string{}
	var reasons []string
	for _, e := range entries {
		if have[e.Name] {
			again++
			continue
		}
		// The entry holding the rule is not a password and must never reach a sheet: it is
		// the legend, and printing it beside the lines it decodes would undo the entire
		// point of masking them. Skipped without a word, like everything else about it.
		if e.Name == v.cfg.Sheet.RuleFrom {
			continue
		}
		sec, err := passstore.Reveal(e.Name)
		if err != nil {
			return v, failure("%s: %v", e.Leaf, err)
		}
		var real string
		sec.Use(func(s string) { real = s })
		sec.Close()
		if real == "" {
			continue
		}
		paper, md, cerr := sheet.ComposeExisting(real, v.mask)
		if cerr != nil {
			// Refused rather than printed wrong. A row that cannot be read back is worse
			// than a row that is missing: the missing one is noticed at once.
			// e.Name, not e.Leaf: a store shaped websites/<site>/<login> has a dozen
			// entries all called "user", and "left out — user" names none of them.
			why := cerr.Error()
			if _, seen := refused[why]; !seen {
				reasons = append(reasons, why)
			}
			refused[why] = append(refused[why], e.Name)
			continue
		}
		dropped = dropped || md
		v.rows = append(v.rows, row{
			label:    e.Name,
			paper:    paper,
			real:     real,
			include:  true,
			imported: true,
		})
		added++
	}
	// BOTH facts, not the last one. These were two assignments to the same field, so the
	// marker note silently replaced the list of refusals — which is how a sheet can come out
	// with two of a dozen passwords on it and nothing on screen saying where the rest went.
	var notes []string
	if dropped {
		notes = append(notes, "a marker had nothing to stand for in some of these — only the noise was used there")
	}
	for _, why := range reasons {
		notes = append(notes, "left out — "+why+":")
		for _, name := range refused[why] {
			notes = append(notes, listMark+" "+name)
		}
	}
	v.importNote = strings.Join(notes, "\n  ")
	// "Already there" outranks "refused": on a second [i] every acceptable entry is a repeat,
	// so counting only the refusals would report total failure on a sheet that is complete.
	if added == 0 && again > 0 {
		return v, status("already on the sheet — nothing new in pass")
	}
	if added == 0 && len(reasons) > 0 {
		// The status line is one line by construction, so it counts rather than lists; the
		// names are already under the sheet.
		n := 0
		for _, names := range refused {
			n += len(names)
		}
		return v, failure("nothing could be put on the sheet — %d %s left out, see below",
			n, plural(n, "entry", "entries"))
	}
	if again > 0 {
		return v, status("imported %d; %d were already on the sheet", added, again)
	}
	return v, status("imported %d from pass", added)
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

	// With a single marker, the bare value is accepted. Demanding "z=Qx9" there is asking the
	// user to restate what the field above already says, and the only thing that redundancy
	// produced was a refusal to save something perfectly well specified. The pair form stays
	// for the case it exists to serve: more than one marker.
	values = strings.TrimSpace(values)
	if len(declared) == 1 && values != "" && !strings.Contains(values, "=") {
		for r := range declared {
			values = string(r) + "=" + values
		}
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

// columns divides the width between the label and the sheet line, leaving the rest for the
// password. The label gets up to half the screen because it is the only column a reader uses to
// tell one row from another; the sheet line is bounded by what a password can be.
func (v *printView) columns(w int) (labelW, paperW int) {
	labelW = max(mini(w/3, 52), 18)
	paperW = max(mini(w-labelW-30, 40), 16)
	return labelW, paperW
}

func (v *printView) renderList(w, h int) string {
	var b strings.Builder

	// NOTHING is said about the rule here — not what it is, not whether there is one.
	//
	// This line used to print its legend: "remove q, 7". Anyone glancing at the screen
	// learned how to read the paper, which is the single thing the paper depends on not being
	// known. And a bare "rule: set" is barely better: it tells an observer that a scheme
	// exists, and from there the sheet stops looking like an ordinary password.
	//
	// So the state is invisible in both directions. The absence of a mention is the state.
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
	b.WriteString("  " + stDim.Render("writes:  ") + where + stDim.Render("   via: ") + conv + "\n\n")

	if len(v.rows) == 0 {
		// The same disappearance as the footer: [m] is mentioned only while it is there to
		// be used. Afterwards the empty sheet is just an empty sheet.
		if v.rules.configured() {
			b.WriteString(stDim.Render("  Empty sheet. [n] adds an entry.") + "\n\n")
		} else {
			b.WriteString(stDim.Render("  Empty sheet. [n] adds an entry, [m] sets the rule.") + "\n\n")
		}
		b.WriteString(indent(stNote.Render("Paper is the only backup that survives a compromised machine\nand a forgotten master password."), 2))
		return b.String()
	}

	// The columns grow with the terminal instead of being three fixed numbers. A store shaped
	// websites/<site>/<login> puts the identifying half at the END of the label, and 24 columns
	// cut it off exactly there — every row read "websites/abv.bg/artdesi…", which is the same
	// row twice as far as the reader is concerned.
	labelW, paperW := v.columns(w)
	b.WriteString(stDim.Render(fmt.Sprintf("     %-*s %-*s %s", labelW, "label", paperW, "on the sheet", "the password")) + "\n")
	start, end := window(len(v.rows), v.sel, max(h-10, 1))
	if start > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", start)) + "\n")
	}
	for i, r := range v.rows[start:end] {
		i += start
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
			cell(tail(r.label, labelW), labelW, st) + " " +
			cell(r.paper, paperW, stFg.Background(bg)) + " " +
			cell(real, max(w-labelW-paperW-8, 8), stAccent.Background(bg)) + "\n")
	}

	if end < len(v.rows) {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d below", len(v.rows)-end)) + "\n")
	}

	// The import note belongs to the LAST IMPORT, not to the row under the cursor, and it used
	// to be drawn only while an imported row happened to be selected. So the one line saying
	// where ten of twelve passwords went disappeared as soon as the cursor moved off them.
	if v.importNote != "" {
		// Folded to the terminal, and the list items hang under their own bullet. A wrapped
		// second line starting at the left margin reads as another item, which on a list of
		// store paths is a store path that does not exist.
		for _, line := range strings.Split(v.importNote, "\n") {
			line = strings.TrimSpace(line)
			if name, ok := strings.CutPrefix(line, listMark+" "); ok {
				wrapped := wrapText(name, max(w-10, 24))
				parts := strings.Split(wrapped, "\n")
				b.WriteString("\n    " + stDim.Render(listMark) + " " + stFg.Render(parts[0]))
				for _, cont := range parts[1:] {
					b.WriteString("\n      " + stFg.Render(cont))
				}
				continue
			}
			b.WriteString("\n" + indent(stWarn.Render(wrapText(line, max(w-4, 30))), 2))
		}
		b.WriteString("\n")
	}

	// The full label of the row under the cursor, because the column above is cut to fit and
	// two logins at the same site differ only in the part that gets cut.
	if v.sel < len(v.rows) {
		if full := v.rows[v.sel].label; full != "" {
			b.WriteString("\n" + indent(stDim.Render(wrapText(full, max(w-4, 30))), 2) + "\n")
		}
	}

	if v.sel < len(v.rows) && v.rows[v.sel].imported {
		b.WriteString("\n  " + stDim.Render("from pass — its strength is not something this sheet knows"))
		b.WriteString("\n")
	} else if v.sel < len(v.rows) {
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
	b.WriteString("  " + v.mValues.render(v.mField == 3) + "\n")
	b.WriteString("  " + v.mWhere.render(v.mField == 4) + "\n\n")
	// Wrapped to the box rather than to hard line breaks written by hand. Fixed-width text
	// inside a box whose width comes from the terminal is text that breaks the box the moment
	// the terminal is narrower than the author's was — the lines fold at the wrong place and
	// the frame ends up drawn through them.
	inner := max(w-8, 32)
	para := func(style func(...string) string, text string) {
		b.WriteString(indent(style(wrapText(text, inner)), 2) + "\n\n")
	}
	para(func(s ...string) string { return stDim.Render(s[0]) },
		"Strip characters make the sheet look like an ordinary password — they hide that a "+
			"rule exists at all. A marker is the stronger one: the sheet genuinely does NOT "+
			"contain the password; a piece is missing that lives only in your head.")
	para(func(s ...string) string { return stDim.Render(s[0]) },
		"It is kept in the pass entry named above, encrypted, so it does not have to be typed "+
			"again. The config keeps only that name.")
	para(func(s ...string) string { return stWarn.Render(s[0]) },
		"Remember what stands behind the marker anyway. The entry opens with your GPG key, and "+
			"the sheet exists for the day that key does not open. It is a convenience, not the "+
			"record.")
	b.WriteString(indent(stDim.Render(wrapText(
		"[enter] keeps it. Changing a rule does not change sheets already printed. They stay readable only by the "+
			"rule they were made under, and nothing here remembers which that was.", inner)), 2))
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
		hint("j/k", "move"),
		hint("n", "new"), hint("i", "from pass"), hint("space", "tick"), hint("g", "regen"),
	}
	// Offered only while there is no rule, and gone entirely once there is one — the same
	// disappearance the audit line makes. A footer that keeps saying "rule" is the program
	// telling every reader of the screen that a masking scheme is in use here.
	//
	// [w] used to be listed beside it and is NOT any more, because the key itself is gone: the
	// form stores on [enter] now. A footer naming a key that does nothing is worse than one
	// that names nothing — it sends the reader to press it and then to wonder what they broke.
	if !v.rules.configured() {
		f = append(f, hint("m", "rule"))
	}
	f = append(f, revealHint(v.rev.on), hint("x", "export"), hint("d", "remove"))
	if passstore.Available() {
		f = append(f, hint("s", "to pass"))
	}
	if v.lastFile != "" {
		f = append(f, hint("S", "wipe file"))
	}
	return joinHints(f...)
}
