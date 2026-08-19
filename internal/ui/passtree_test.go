package ui

import (
	"path"
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/passstore"
)

// entries builds the flat list the store hands over, from paths alone — which is all the tree is
// ever allowed to know, because that is all `passstore.Entries` reads.
func entries(names ...string) []passstore.Entry {
	out := make([]passstore.Entry, 0, len(names))
	for _, n := range names {
		folder, leaf := path.Split(n)
		out = append(out, passstore.Entry{Name: n, Folder: strings.TrimSuffix(folder, "/"), Leaf: leaf})
	}
	return out
}

// rowPaths renders the visible tree the way the screen does: one line per node, indented by depth,
// so a test failure reads as the shape that was drawn.
func rowPaths(rows []*treeNode) []string {
	out := make([]string, 0, len(rows))
	for _, n := range rows {
		name := n.leaf
		if n.folder {
			name += "/"
		}
		out = append(out, strings.Repeat("  ", n.depth)+name)
	}
	return out
}

func rendered(rows []*treeNode) string { return strings.Join(rowPaths(rows), "\n") }

// withOrder swaps the .order reader for a fixed answer, so the shape of the tree can be tested
// without a password store on the machine running the tests.
func withOrder(t *testing.T, orders map[string][]string) {
	t.Helper()
	old := orderOf
	orderOf = func(folder string) []string { return orders[folder] }
	t.Cleanup(func() { orderOf = old })
}

// TestBuildTreeNestsByPath: the folders come from the paths, every level is its own node, and an
// entry at the root sits beside the top-level folders rather than under one.
func TestBuildTreeNestsByPath(t *testing.T) {
	withOrder(t, nil)
	root := buildTree(entries(
		"websites/abv.bg/me",
		"websites/abv.bg/work",
		"websites/github.com/lvim-tech",
		"token/github.com/classic/lvim",
		"standalone",
	))
	open := map[string]bool{
		"websites": true, "websites/abv.bg": true, "websites/github.com": true,
		"token": true, "token/github.com": true, "token/github.com/classic": true,
	}
	got := rendered(visibleRows(root, open, nil))
	want := strings.Join([]string{
		"standalone",
		"token/",
		"  github.com/",
		"    classic/",
		"      lvim",
		"websites/",
		"  abv.bg/",
		"    me",
		"    work",
		"  github.com/",
		"    lvim-tech",
	}, "\n")
	if got != want {
		t.Errorf("the tree came out as\n%s\nwant\n%s", got, want)
	}
}

// TestVisibleRowsHidesFoldedSubtrees: a folded folder hides everything below it, at every level,
// and it is still a row of its own — otherwise folding would be indistinguishable from deleting.
func TestVisibleRowsHidesFoldedSubtrees(t *testing.T) {
	withOrder(t, nil)
	root := buildTree(entries("a/b/c", "a/b/d", "a/e", "f"))

	if got := rendered(visibleRows(root, map[string]bool{}, nil)); got != "a/\nf" {
		t.Errorf("everything folded should leave the top level:\n%s", got)
	}
	got := rendered(visibleRows(root, map[string]bool{"a": true}, nil))
	if got != "a/\n  b/\n  e\nf" {
		t.Errorf("one level open:\n%s", got)
	}
	got = rendered(visibleRows(root, map[string]bool{"a": true, "a/b": true}, nil))
	if got != "a/\n  b/\n    c\n    d\n  e\nf" {
		t.Errorf("both levels open:\n%s", got)
	}
	// An open folder inside a folded one shows nothing: the fold nearest the top wins, which is
	// what makes putting a branch away actually put it away.
	if got := rendered(visibleRows(root, map[string]bool{"a/b": true}, nil)); got != "a/\nf" {
		t.Errorf("a fold above an open folder must still hide it:\n%s", got)
	}
}

// TestBuildTreeAppliesOrderPerFolder: each level reads its OWN .order, and a folder with none
// stays alphabetical — the ordering is per directory, not one list for the whole store.
func TestBuildTreeAppliesOrderPerFolder(t *testing.T) {
	withOrder(t, map[string][]string{
		"":         {"websites/", "zzz"},
		"websites": {"github.com/"},
	})
	root := buildTree(entries("aaa", "zzz", "websites/abv.bg/me", "websites/github.com/lvim"))
	open := map[string]bool{"websites": true, "websites/abv.bg": true, "websites/github.com": true}
	got := rendered(visibleRows(root, open, nil))
	want := strings.Join([]string{
		"websites/",
		"  github.com/",
		"    lvim",
		"  abv.bg/",
		"    me",
		"zzz",
		"aaa",
	}, "\n")
	if got != want {
		t.Errorf("the ordered tree came out as\n%s\nwant\n%s", got, want)
	}
}

// TestShiftMovesOnlyAmongSiblings: reordering rearranges one folder's children and can never lift
// a node out of it — a node leaving its folder would be a rename, which is what [m] is for.
func TestShiftMovesOnlyAmongSiblings(t *testing.T) {
	withOrder(t, nil)
	root := buildTree(entries("a/one", "a/two", "b/three"))
	open := map[string]bool{"a": true, "b": true}

	two := find(root, "a/two")
	if two == nil {
		t.Fatal("a/two is not in the tree")
	}
	if !shift(two, -1) {
		t.Fatal("a/two would not move up")
	}
	if got := rendered(visibleRows(root, open, nil)); got != "a/\n  two\n  one\nb/\n  three" {
		t.Errorf("after moving up:\n%s", got)
	}
	if keys := siblingKeys(two.parent); strings.Join(keys, ",") != "two,one" {
		t.Errorf(".order would be written as %v", keys)
	}
	// Already at the top of its folder: there is no room, and no sideways escape into `b`.
	if shift(two, -1) {
		t.Error("a node moved above the first position in its folder")
	}
	// The folders themselves are nodes too, and reorder at their own level.
	if b := find(root, "b"); b == nil || !shift(b, -1) {
		t.Fatal("the folder b would not move among the top-level nodes")
	}
	if got := rendered(visibleRows(root, open, nil)); got != "b/\n  three\na/\n  two\n  one" {
		t.Errorf("after moving the folder:\n%s", got)
	}
	if keys := siblingKeys(root); strings.Join(keys, ",") != "b/,a/" {
		t.Errorf("the root's .order would be written as %v", keys)
	}
}

// TestRecordsCountsTheSubtree: a folded folder reports how much it is hiding, which is the only
// thing its row can still say once its children are off the screen.
func TestRecordsCountsTheSubtree(t *testing.T) {
	withOrder(t, nil)
	root := buildTree(entries("a/b/c", "a/b/d", "a/e", "f"))
	if n := find(root, "a"); n == nil || n.records() != 3 {
		t.Errorf("a/ holds 3 records, counted %v", n.records())
	}
	if n := find(root, "a/b"); n == nil || n.records() != 2 {
		t.Errorf("a/b/ holds 2 records, counted %v", n.records())
	}
}

// TestAncestorsIsWhatTheFilterUnfolds: the folders on the way to a match, outermost first. A
// match inside a folded branch is a match nobody can see.
func TestAncestorsIsWhatTheFilterUnfolds(t *testing.T) {
	got := strings.Join(ancestors("token/github.com/classic/lvim"), ",")
	if got != "token,token/github.com,token/github.com/classic" {
		t.Errorf("got %q", got)
	}
	if a := ancestors("standalone"); len(a) != 0 {
		t.Errorf("an entry at the root has no folders above it, got %v", a)
	}
}
