// Package theme is where keyforge's colours come from.
//
// THE PALETTE IS TEN ROLES, NOT TEN COLOURS. What the interface asks for is "the colour that means
// this is open right now", not "red" — the meanings are fixed and only the values move. That is
// what makes an external theme safe: a palette can repaint the whole program and cannot change what
// a colour is saying, because nothing here maps a role onto a second meaning.
//
// WHERE A PALETTE COMES FROM. keyforge is one of a set of tools that share lvim-colorscheme's
// palettes, and the plugin already publishes the ACTIVE theme name for exactly this purpose: it
// writes `stdpath("data")/lvim-colorscheme/theme`, one line, "so a host's bootstrap/installer can
// read the theme WITHOUT loading the plugin" — its own words. keyforge reads that mirror and looks
// for a palette of that name among its themes.
//
// NOTHING HERE CAN FAIL. Every step is "use it if it resolves, otherwise try the next one", and the
// last one is the built-in Everforest that used to be hard-coded. A theme file that is missing,
// unreadable, half-written or full of nonsense costs the colour it could not supply and nothing
// else: a security tool that refused to start over a colour would be a bad trade, and one that
// started with no colours at all would be a worse one, because the colours here carry meaning.
package theme

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lvim-tech/keyforge/internal/config"
	"gopkg.in/yaml.v3"
)

// Palette is the ten roles the interface paints with.
//
// bg/bgAlt are the surface and the one step off it that marks a selected row; fg and dim are
// ordinary text and context. The five hues are the ones that carry meaning — red "open right now",
// yellow "will bite you later", green "verified good", blue the interactive accent, purple and
// orange the two secondary accents (folder names, notes).
//
// TitleFG is the one OPTIONAL role: the ink for text drawn ON an accent surface — the chip and
// the active tab. Empty means the theme did not name it, and the interface falls back to bg,
// which is what was always painted there — so every palette written before the role existed
// keeps looking exactly as it did.
type Palette struct {
	BG      string `json:"bg"`
	BGAlt   string `json:"bg_alt"`
	FG      string `json:"fg"`
	Dim     string `json:"dim"`
	Red     string `json:"red"`
	Yellow  string `json:"yellow"`
	Green   string `json:"green"`
	Blue    string `json:"blue"`
	Purple  string `json:"purple"`
	Orange  string `json:"orange"`
	TitleFG string `json:"title_fg"`
}

// Builtin is Everforest, the palette keyforge carried hard-coded before any of this existed. It is
// the floor under every other source: a partial theme is completed from it role by role.
func Builtin() Palette {
	return Palette{
		BG:     "#2f383e",
		BGAlt:  "#374247",
		FG:     "#d3c6aa",
		Dim:    "#859289",
		Red:    "#e67e80",
		Yellow: "#dbbc7f",
		Green:  "#a7c080",
		Blue:   "#7fbbb3",
		Purple: "#d699b6",
		Orange: "#e69875",
	}
}

// Result is a loaded palette and the account of where it came from, which the Settings tab shows.
// A theme that silently half-applied would be indistinguishable from one that did not apply.
type Result struct {
	Palette Palette
	Name    string   // the theme's name, as resolved
	Source  string   // the file it was read from, or "built-in"
	Notes   []string // roles filled from the built-in, a foreground lifted for contrast
}

// file names the palette document format keyforge reads.
//
// name + colors, the same per-app YAML shape lvim-colorscheme already generates for the other
// Bubble Tea tools in this set (extras/keyforge/*.yaml) — so the `extra/misc/keyforge.lua`
// generator beside it has nothing new to invent. A flat object of role → hex is accepted too,
// because that is what somebody writing one by hand produces on the first try. yaml.v3 also parses
// JSON, so a document pointed at by a literal `.json` path is read by the same code.
type file struct {
	Name   string            `yaml:"name" json:"name"`
	Colors map[string]string `yaml:"colors" json:"colors"`
}

// Load resolves a palette, in the order a user would expect to be obeyed.
//
//  1. $KEYFORGE_THEME — a path to a palette file, or a bare theme name. The explicit override,
//     which is also what makes a theme testable without touching anything on disk.
//  2. $LVIM_COLORSCHEME — a theme name, for a shell that already exports which theme it is in.
//  3. Whatever lvim-colorscheme says is active right now, from the mirror it writes for
//     non-Neovim readers. This is the one that makes keyforge FOLLOW the editor: change the
//     colorscheme there and keyforge is repainted the next time it starts.
//  4. `theme` in keyforge's own config.json — a path or a name.
//  5. The built-in.
//
// Each step is skipped when it does not resolve to a palette, so naming a theme in the config is
// not defeated by a Neovim whose palette keyforge has no file for.
func Load(configured string) Result {
	for _, cand := range []struct{ name, from string }{
		{strings.TrimSpace(os.Getenv("KEYFORGE_THEME")), "KEYFORGE_THEME"},
		{strings.TrimSpace(os.Getenv("LVIM_COLORSCHEME")), "LVIM_COLORSCHEME"},
		{activeColorscheme(), "lvim-colorscheme"},
		{strings.TrimSpace(configured), "config.json"},
	} {
		if cand.name == "" {
			continue
		}
		if r, ok := resolve(cand.name); ok {
			r.Source = cand.from + ": " + r.Source
			return r
		}
	}
	return Result{Palette: Builtin(), Name: "everforest (built-in)", Source: "built-in"}
}

// resolve turns a name or a path into a palette.
func resolve(name string) (Result, bool) {
	// A path is anything that looks like one: it is taken literally, so a theme can be kept
	// anywhere and pointed at from an environment variable during a single run. A bare name that
	// already carries a palette-document suffix is a path too — read it where it stands.
	if strings.ContainsRune(name, os.PathSeparator) ||
		strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") ||
		strings.HasSuffix(name, ".json") {
		if r, ok := readFile(name); ok {
			return r, true
		}
		return Result{}, false
	}
	dir := config.ThemeDir()
	// The per-app YAML file, one per theme, under both spellings of the same name. Neovim calls it
	// `lvim-everforest-soft` (the :colorscheme command) and every generated file calls it
	// `LvimEverforest_soft` (the extras/ file name), and which of the two a user has in hand
	// depends only on where they copied it from.
	for _, n := range []string{name, extrasName(name)} {
		if n == "" {
			continue
		}
		if r, ok := readFile(filepath.Join(dir, n+".yaml")); ok {
			return r, true
		}
	}
	return Result{}, false
}

// readFile reads one palette document. The parsing is separate so it can be tested against the
// documents this has to survive — half-written, hand-written, and about something else entirely —
// without a file per case.
func readFile(path string) (Result, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false
	}
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	r, ok := parsePalette(b, base)
	if !ok {
		return Result{}, false
	}
	r.Source = path
	return r, true
}

// parsePalette turns a palette document into a result, or refuses it.
func parsePalette(b []byte, fallbackName string) (Result, bool) {
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return Result{}, false
	}
	if len(f.Colors) == 0 {
		// The hand-written form: role → hex at the top level. Unmarshalled into the same map,
		// so a document that is neither shape simply produces no roles and is refused below.
		flat := map[string]string{}
		if err := yaml.Unmarshal(b, &flat); err != nil {
			return Result{}, false
		}
		delete(flat, "name")
		f.Colors = flat
	}
	p, missing := fill(f.Colors)
	if len(missing) == len(roleNames) {
		// Nothing in it was a colour. That is a file about something else, not a theme, and
		// accepting it would repaint the program with the built-in while claiming otherwise.
		return Result{}, false
	}
	name := f.Name
	if name == "" {
		name = fallbackName
	}
	p, lifted := readable(p)
	return Result{Palette: p, Name: name, Notes: append(filledNote(missing), lifted...)}, true
}

// filledNote says which roles the document did not supply, because a theme that half-applied and
// said nothing is the one failure mode a fallback introduces.
func filledNote(missing []string) []string {
	if len(missing) == 0 {
		return nil
	}
	return []string{"from the built-in: " + strings.Join(missing, ", ")}
}

// roleNames is the document's key for each role, in the order a missing-role note lists them.
var roleNames = []string{"bg", "bg_alt", "fg", "dim", "red", "yellow", "green", "blue", "purple", "orange"}

// fill builds a palette from whatever the document supplied, taking anything missing or malformed
// from the built-in — so a theme that names three colours is three colours changed, not a broken
// screen.
func fill(colors map[string]string) (Palette, []string) {
	b := Builtin()
	p := Palette{}
	var missing []string
	set := []struct {
		role string
		into *string
		from string
	}{
		{"bg", &p.BG, b.BG},
		{"bg_alt", &p.BGAlt, b.BGAlt},
		{"fg", &p.FG, b.FG},
		{"dim", &p.Dim, b.Dim},
		{"red", &p.Red, b.Red},
		{"yellow", &p.Yellow, b.Yellow},
		{"green", &p.Green, b.Green},
		{"blue", &p.Blue, b.Blue},
		{"purple", &p.Purple, b.Purple},
		{"orange", &p.Orange, b.Orange},
	}
	for _, s := range set {
		if hex, ok := normalise(colors[s.role]); ok {
			*s.into = hex
			continue
		}
		*s.into = s.from
		missing = append(missing, s.role)
	}
	// title_fg is optional and stays OUTSIDE the required ten: it is not taken from the
	// built-in and its absence is not reported, because absence is a complete answer — the
	// interface paints the accent surfaces with bg then, as it always has. Only a value the
	// theme actually supplies moves anything.
	if hex, ok := normalise(colors["title_fg"]); ok {
		p.TitleFG = hex
	}
	return p, missing
}

// normalise accepts "#rrggbb" and "rrggbb", in either case, and refuses everything else. A value
// lipgloss cannot parse is the same problem as a missing one, and is treated as one.
func normalise(s string) (string, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	if len(s) != 6 {
		return "", false
	}
	if _, err := strconv.ParseUint(s, 16, 32); err != nil {
		return "", false
	}
	return "#" + strings.ToLower(s), true
}

// readable keeps the text off the background.
//
// THIS IS NOT A NICETY, and the palettes prove it: lvim-colorscheme's `fg` is tuned for syntax
// highlighting, where it is one colour among many on a highlighted line, and several styles carry
// a deliberately muted one — everforest_soft's is #5a6158 on a #292f33 background, which measures
// 1.6:1 and cannot be read as plain text. The plugin's own generator for the other Bubble Tea tool
// in this set puts the same floor under the same colour for the same reason.
//
// The floor is the WCAG 3:1 for large text, which is about where a terminal font stops being
// effortless. Only fg is checked and only fg moves: the hues carry meaning, and the right answer
// for a theme whose red is invisible is a better theme, not a red keyforge invented.
func readable(p Palette) (Palette, []string) {
	if contrast(p.FG, p.BG) >= 3 {
		return p, nil
	}
	old := p.FG
	p.FG = lift(p.FG, p.BG, 3)
	return p, []string{fmt.Sprintf("fg %s reads at %.1f:1 on %s — lifted to %s",
		old, contrast(old, p.BG), p.BG, p.FG)}
}

// lift walks a colour away from a background until it clears the ratio, keeping its hue.
//
// Away means towards white on a dark background and towards black on a light one, in small steps,
// so what comes back is still recognisably the theme's foreground. Replacing it with plain white
// would clear the floor too and would paint every muted theme with the same glaring text.
func lift(fg, bg string, target float64) string {
	away := "#ffffff"
	if contrast("#000000", bg) > contrast("#ffffff", bg) {
		away = "#000000"
	}
	for t := 0.05; t < 1; t += 0.05 {
		if c := blend(fg, away, t); contrast(c, bg) >= target {
			return c
		}
	}
	return away
}

// contrast is the WCAG ratio between two colours, 1 for identical and 21 for black on white.
func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// luminance is WCAG relative luminance. An unparseable colour comes back as black, which only
// makes the check stricter — the safe direction for a readability floor.
func luminance(hex string) float64 {
	r, g, b, ok := rgb(hex)
	if !ok {
		return 0
	}
	lin := func(c float64) float64 {
		c /= 255
		if c <= 0.03928 {
			return c / 12.92
		}
		// The sRGB transfer curve, as WCAG defines it — not an approximation of it, because the
		// number this produces is the one deciding whether a screen gets repainted.
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b)
}

func rgb(hex string) (r, g, b float64, ok bool) {
	h, valid := normalise(hex)
	if !valid {
		return 0, 0, 0, false
	}
	n, err := strconv.ParseUint(h[1:], 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return float64((n >> 16) & 0xff), float64((n >> 8) & 0xff), float64(n & 0xff), true
}

// blend mixes a towards b by t (0 keeps a, 1 becomes b) — how lift walks the foreground towards
// the readable end without abandoning its hue.
func blend(a, b string, t float64) string {
	ar, ag, ab, ok := rgb(a)
	br, bg, bb, ok2 := rgb(b)
	if !ok || !ok2 {
		return a
	}
	mix := func(x, y float64) uint64 { return uint64(x + (y-x)*t + 0.5) }
	return fmt.Sprintf("#%02x%02x%02x", mix(ar, br), mix(ag, bg), mix(ab, bb))
}

// activeColorscheme is the theme lvim-colorscheme says is in force.
//
// The one-line mirror first, because that is precisely what the plugin writes it for; its own
// settings document second, since the mirror is only rewritten when a setting is committed and a
// fresh install has neither. Both are read without lua, without Neovim, and without the plugin.
func activeColorscheme() string {
	dir := lvimDataDir()
	if b, err := os.ReadFile(filepath.Join(dir, "theme")); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return name
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		return ""
	}
	var s struct {
		Colorscheme string `json:"colorscheme"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s.Colorscheme)
}

// lvimDataDir is Neovim's stdpath("data") plus the plugin's own directory.
func lvimDataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "nvim", "lvim-colorscheme")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "nvim", "lvim-colorscheme")
}

// extrasName turns a :colorscheme name into the name the generated files carry.
//
//	lvim-everforest-soft → LvimEverforest_soft
//	lvim-soft            → LvimBase_soft        (the unprefixed family is called base)
//
// The two spellings are the plugin's, not keyforge's invention: the README lists the command as
// `:colorscheme lvim-everforest-soft` and the generated file as `LvimEverforest_soft`.
func extrasName(name string) string {
	low := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(low, "lvim-") {
		return "" // not one of the plugin's names — there is nothing to translate
	}
	parts := strings.Split(strings.TrimPrefix(low, "lvim-"), "-")
	family, variant := "base", parts[len(parts)-1]
	if len(parts) > 1 {
		family = strings.Join(parts[:len(parts)-1], "")
	}
	if family == "" || variant == "" {
		return ""
	}
	return "Lvim" + strings.ToUpper(family[:1]) + family[1:] + "_" + variant
}
