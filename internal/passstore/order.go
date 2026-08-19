package passstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// orderFile is the per-directory listing order, kept INSIDE the store on purpose.
//
// `pass` has no order of its own: `pass ls` shells out to `tree`, which sorts alphabetically, and
// there is nowhere in the format to say that `websites/bank` matters more than `websites/aardvark`.
// The order a person puts their passwords in is part of how the store is organised, so it has to
// travel with the store — through git, onto the other machine — rather than sit in keyforge's own
// config directory where a second machine would never see it.
//
// It is safe to leave here because both readers ignore it. `pass ls` runs `tree` WITHOUT -a, so a
// dotfile is invisible to it — the same reason `.gpg-id` has never shown up in a listing — and this
// package's Entries walks for `*.gpg` and nothing else. It is plain text with one child name per
// line, so it can be edited by hand or resolved in a merge conflict without keyforge.
const orderFile = ".order"

// folderDir resolves a store folder to a directory, with "" meaning the store's own root.
//
// ValidName does the refusing: a folder is a path inside the store like any entry name, and
// ".." in one would put an .order file wherever the caller's imagination reached.
func folderDir(folder string) (string, error) {
	folder = strings.Trim(strings.TrimSpace(folder), "/")
	if folder == "" {
		return dir(), nil
	}
	if err := ValidName(folder); err != nil {
		return "", err
	}
	return filepath.Join(dir(), filepath.FromSlash(folder)), nil
}

// Order returns the child names a folder wants listed first, in the order it wants them.
//
// A missing, unreadable or empty file is not an error but the ordinary case: most folders have
// never been reordered, and they are meant to cost nothing.
func Order(folder string) []string {
	d, err := folderDir(folder)
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(d, orderFile))
	if err != nil {
		return nil
	}
	return parseOrder(string(b))
}

// parseOrder reads the file's lines. Blank lines and comments are dropped, so the file survives
// being annotated by whoever opens it wondering what it is.
func parseOrder(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// SetOrder records the order of one folder's children, creating the file if this is the first
// time that folder has ever been rearranged.
//
// Names are CHILD names, not paths: one segment, with a trailing "/" marking a sub-folder. The
// slash is what keeps a folder and an entry of the same name — `sites/` beside `sites.gpg`, which
// the store allows — from being one line that means either.
func SetOrder(folder string, names []string) error {
	d, err := folderDir(folder)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		return fmt.Errorf("no folder %q in the store", folder)
	}
	var b strings.Builder
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || strings.HasPrefix(n, "#") {
			continue
		}
		if strings.Contains(strings.TrimSuffix(n, "/"), "/") {
			return fmt.Errorf("%q is a path, and .order lists the children of one folder", n)
		}
		b.WriteString(n + "\n")
	}
	// Temp and rename, in the folder itself so the rename cannot cross a filesystem. The order is
	// not a secret, but a store that is a git repository would otherwise be able to catch — and
	// commit — a half-written file.
	tmp, err := os.CreateTemp(d, ".order-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(d, orderFile)); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// Arrange puts `names` in the order `order` asks for, with everything it does not mention
// falling alphabetically after what it does.
//
// That rule is what makes the file usable by hand: pinning the three folders you care about to
// the top does not mean listing the other forty, and an entry added later appears in its
// alphabetical place among the unlisted rather than at a position nobody chose.
//
// A name is matched exactly first and then without its trailing slash, so a line written by hand
// as `websites` still pins the folder keyforge itself would have written as `websites/`.
//
// Pure, and therefore testable without a store — which is the other reason it is here rather
// than inlined where the tree is built.
func Arrange(order, names []string) []string {
	if len(order) == 0 {
		return append([]string(nil), names...)
	}
	rank := make(map[string]int, len(order))
	for i, n := range order {
		if _, seen := rank[n]; !seen {
			rank[n] = i
		}
	}
	at := func(s string) int {
		if r, ok := rank[s]; ok {
			return r
		}
		if r, ok := rank[strings.TrimSuffix(s, "/")]; ok {
			return r
		}
		return len(order)
	}
	out := append([]string(nil), names...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := at(out[i]), at(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}
