// Package ui is the terminal interface. The palette below is Everforest, the same one the rest of
// the lvim-tech set paints with, so keyforge does not look like a stranger next to the editor.
//
// Colours carry meaning here and only meaning: red is "this is open right now", yellow is "this
// will bite you later", green is "verified good", grey is context. Nothing is coloured for
// decoration — on a screen that reports security state, a colour that means nothing is a colour
// that teaches you to ignore colours.
package ui

import (
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/theme"
)

// The palette in force. Ten roles, filled from whatever theme resolved — see internal/theme for
// where one comes from. They are variables rather than constants because the values move; what
// each of them MEANS does not, and nothing below reassigns a role to a second meaning.
var (
	cBg     lipgloss.Color
	cBgAlt  lipgloss.Color
	cFg     lipgloss.Color
	cDim    lipgloss.Color
	cRed    lipgloss.Color
	cYellow lipgloss.Color
	cGreen  lipgloss.Color
	cBlue   lipgloss.Color
	cPurple lipgloss.Color
	cOrange lipgloss.Color
)

// The styles, built FROM the palette rather than beside it.
//
// A lipgloss.Style holds the colour it was given, so these cannot be package-level initialisers
// any more: a theme that arrives after the program has started has to be able to rebuild them.
// They are rebuilt whole rather than patched, which is what keeps a repaint from leaving one
// screen in the old colours.
var (
	stTitle    lipgloss.Style
	stTab      lipgloss.Style
	stTabOn    lipgloss.Style
	stTabTight lipgloss.Style // the same tab with the padding taken away, for narrow terminals

	stKey    lipgloss.Style
	stDim    lipgloss.Style
	stFg     lipgloss.Style
	stGood   lipgloss.Style
	stWarn   lipgloss.Style
	stBad    lipgloss.Style
	stAccent lipgloss.Style
	stNote   lipgloss.Style

	stRow    lipgloss.Style
	stRowSel lipgloss.Style

	stBox lipgloss.Style

	stFooter lipgloss.Style
	stErr    lipgloss.Style
	stOK     lipgloss.Style
)

// loaded is the theme currently painted, kept so the Settings tab can say which one it is and
// where it came from. A theme that half-applied in silence would be worse than none.
var loaded = theme.Result{Palette: theme.Builtin(), Name: "everforest (built-in)", Source: "built-in"}

// The built-in palette is in force before anything is read from disk, so a package that draws
// during a test — or an early failure that prints before the config is loaded — is never painting
// with the zero value, which lipgloss renders as the terminal's default and nothing else.
func init() { UseTheme(loaded) }

// ApplyTheme resolves the configured theme and paints with it, returning what it found.
func ApplyTheme(c config.Config) theme.Result {
	r := theme.Load(c.Theme)
	UseTheme(r)
	return r
}

// CurrentTheme is what is on screen right now.
func CurrentTheme() theme.Result { return loaded }

// UseTheme repaints the whole interface from a palette.
//
// Every style is rebuilt here and nowhere else. The alternative — each screen reading the palette
// as it draws — is how one tab ends up a theme behind the others, and the colours in this program
// are not decoration: a red that is not the same red everywhere is a red that has stopped meaning
// "this is open right now".
func UseTheme(r theme.Result) {
	loaded = r
	p := r.Palette
	cBg, cBgAlt = lipgloss.Color(p.BG), lipgloss.Color(p.BGAlt)
	cFg, cDim = lipgloss.Color(p.FG), lipgloss.Color(p.Dim)
	cRed, cYellow, cGreen = lipgloss.Color(p.Red), lipgloss.Color(p.Yellow), lipgloss.Color(p.Green)
	cBlue, cPurple, cOrange = lipgloss.Color(p.Blue), lipgloss.Color(p.Purple), lipgloss.Color(p.Orange)

	stTitle = lipgloss.NewStyle().Bold(true).Foreground(cBg).Background(cBlue).Padding(0, 1)
	stTab = lipgloss.NewStyle().Foreground(cDim).Padding(0, 2)
	stTabOn = lipgloss.NewStyle().Bold(true).Foreground(cBg).Background(cGreen).Padding(0, 2)
	stTabTight = lipgloss.NewStyle().Foreground(cDim)

	stKey = lipgloss.NewStyle().Bold(true).Foreground(cBlue)
	stDim = lipgloss.NewStyle().Foreground(cDim)
	stFg = lipgloss.NewStyle().Foreground(cFg)
	stGood = lipgloss.NewStyle().Foreground(cGreen)
	stWarn = lipgloss.NewStyle().Foreground(cYellow)
	stBad = lipgloss.NewStyle().Bold(true).Foreground(cRed)
	stAccent = lipgloss.NewStyle().Foreground(cPurple)
	stNote = lipgloss.NewStyle().Foreground(cOrange)

	stRow = lipgloss.NewStyle().Foreground(cFg)
	stRowSel = lipgloss.NewStyle().Bold(true).Foreground(cFg).Background(cBgAlt)

	stBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cDim).
		Padding(0, 1)

	stFooter = lipgloss.NewStyle().Foreground(cDim).Padding(0, 1)
	stErr = lipgloss.NewStyle().Bold(true).Foreground(cRed).Padding(0, 1)
	stOK = lipgloss.NewStyle().Bold(true).Foreground(cGreen).Padding(0, 1)
}

// listMark prefixes the items of a list written in prose, so a run of names reads as an
// enumeration rather than as a sentence that happened to wrap.
const listMark = "●"

// pointer is the lvim-tech marker for the active row — the same glyph the editor's pickers use.
const pointer = "➤"

// cell lays out one column: it truncates and pads the PLAIN text first and only then applies the
// style. Doing it the other way round is the standard way a styled table comes out ragged — the
// escape codes that colour a cell are counted by %-12s as if they were letters, so every coloured
// column ends up short by exactly the length of its own colour.
func cell(s string, w int, st lipgloss.Style) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) > w {
		if w == 1 {
			s = "…"
		} else {
			s = string(r[:w-1]) + "…"
		}
		r = []rune(s)
	}
	return st.Render(s + strings.Repeat(" ", w-len(r)))
}

// NEWLINES GO OUTSIDE Render, ALWAYS.
//
// lipgloss treats a styled string as a BLOCK: it splits on "\n" and pads every line to the width
// of the widest one. So Render("text\n\n") does not emit two line breaks — it emits the text and
// then two lines of spaces as wide as the text, the last of which carries no newline at all. The
// next thing written lands on the end of that padding, which is how a note ends up starting from
// the middle of the screen while its own second line starts at the left margin.
//
//	WRONG   b.WriteString(st.Render("Empty sheet.\n\n"))
//	RIGHT   b.WriteString(st.Render("Empty sheet") + "\n\n")
//
// The same rule as `cell` below and for the same reason: style the text, lay out around it.

// clampLines cuts a rendered block to at most n lines.
func clampLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n")
}

// window returns the half-open range of rows to draw so that `sel` stays on screen.
//
// The cursor is kept inside the visible band rather than centred: a list that recentres on every
// keypress moves under the eye, and the row you were reading is somewhere else by the time you
// look back at it.
func window(total, sel, room int) (start, end int) {
	if room <= 0 || total <= 0 {
		return 0, 0
	}
	if total <= room {
		return 0, total
	}
	start = sel - room/2
	if start < 0 {
		start = 0
	}
	if start > total-room {
		start = total - room
	}
	return start, start + room
}

// hanging renders `prefix + text` folded to width, with the continuation aligned under the TEXT
// rather than under the prefix.
//
// A wrapped second line starting back at the marker reads as a second item, which on a list of
// store paths is a path that does not exist. Returned as lines so the caller decides the
// indentation and the styling — the layout is done around the text, never inside a Render.
func hanging(prefix, text string, width int) []string {
	pad := strings.Repeat(" ", len([]rune(prefix)))
	body := wrapText(text, max(width-len([]rune(prefix)), 12))
	var out []string
	for i, l := range strings.Split(body, "\n") {
		if i == 0 {
			out = append(out, prefix+l)
			continue
		}
		out = append(out, pad+l)
	}
	return out
}

// tail keeps the END of a string when it will not fit.
//
// The opposite of trunc, and the right choice for a store path: `websites/abv.bg/` is the part
// every row shares, and the login after it is the part that tells them apart. Cutting from the
// front leaves "…abv.bg/artdesign@abv.bg" — which names the row — instead of
// "websites/abv.bg/artdesi…", which names the site everybody already knows.
func tail(s string, w int) string {
	r := []rune(s)
	if w <= 1 || len(r) <= w {
		return s
	}
	return "…" + string(r[len(r)-(w-1):])
}

// mini is the counterpart of maxi.
func mini(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sortedKeys gives a map a stable render order, so a detail pane does not reshuffle its own rows
// between two draws of the same thing.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hint renders one "[k] label" pair for the footer.
func hint(k, label string) string {
	return stKey.Render("["+k+"]") + " " + stDim.Render(label)
}

// joinHints spaces out a list of footer hints.
func joinHints(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "  "
		}
		out += p
	}
	return out
}

// indent shifts every line of a block right by n spaces. Prefixing a multi-line string with spaces
// only moves its first line — the rest keep starting at column zero, which is how a bordered box
// ends up with its top-left corner in one place and its left edge in another.
func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// plural picks the right noun for a count, so a list never reports "1 entries".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
