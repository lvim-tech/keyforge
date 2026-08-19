package ui

import (
	"sort"
	"strings"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/passstore"
)

// treeNode is one node of the Passwords tree: either a folder or one record.
//
// The tree is built from the FLAT list `passstore.Entries` returns, and that is the whole reason
// it can exist at all: entries are names and timestamps, read by walking the store for *.gpg
// files, so a tree of them is still a tree of things nothing has decrypted.
type treeNode struct {
	path   string // full store path; "" for the root, which is never drawn
	leaf   string // the last segment — what the row shows
	folder bool
	depth  int             // 0 for a top-level node; the root is -1 so its children start at 0
	entry  passstore.Entry // the record itself, on a leaf
	kids   []*treeNode     // on a folder
	parent *treeNode
}

// orderOf is how the tree learns a folder's chosen order.
//
// A variable rather than a direct call so the model can be tested without a password store on
// the machine running the tests — the tree's shape, its folding and its reordering are all pure
// once this is.
var orderOf = passstore.Order

// key is the name this node goes by in its parent's .order file. The trailing slash on a folder
// is what tells `sites/` apart from an entry called `sites` in the same directory.
func (n *treeNode) key() string {
	if n.folder {
		return n.leaf + "/"
	}
	return n.leaf
}

// records counts the entries in a node's subtree, which is what a folded folder shows instead of
// a date: the one thing worth knowing about a folder you cannot currently see into is how much it
// is hiding.
func (n *treeNode) records() int {
	if !n.folder {
		return 1
	}
	total := 0
	for _, k := range n.kids {
		total += k.records()
	}
	return total
}

// buildTree turns the flat entry list into folders and leaves, then puts every level in order.
func buildTree(entries []passstore.Entry) *treeNode {
	root := &treeNode{folder: true, depth: -1}
	folders := map[string]*treeNode{"": root}
	for _, e := range entries {
		segs := strings.Split(e.Name, "/")
		parent, acc := root, ""
		for _, seg := range segs[:len(segs)-1] {
			if acc == "" {
				acc = seg
			} else {
				acc += "/" + seg
			}
			f, ok := folders[acc]
			if !ok {
				f = &treeNode{path: acc, leaf: seg, folder: true, depth: parent.depth + 1, parent: parent}
				folders[acc] = f
				parent.kids = append(parent.kids, f)
			}
			parent = f
		}
		parent.kids = append(parent.kids, &treeNode{
			path:   e.Name,
			leaf:   e.Leaf,
			depth:  parent.depth + 1,
			entry:  e,
			parent: parent,
		})
	}
	sortKids(root)
	return root
}

// sortKids orders one level and then every level below it.
//
// Alphabetically FIRST, and only then by the folder's .order — because Arrange is a stable
// rearrangement, so the names the file does not mention keep the alphabetical order they came in
// with. Doing it the other way round would leave the unlisted children in the arbitrary order the
// filesystem walk happened to produce.
func sortKids(n *treeNode) {
	sort.SliceStable(n.kids, func(i, j int) bool {
		a, b := n.kids[i], n.kids[j]
		if a.leaf != b.leaf {
			return a.leaf < b.leaf
		}
		// A folder and an entry may legitimately share a name; the folder goes first, and their
		// .order keys differ by the slash, so the file can still say otherwise.
		return a.folder && !b.folder
	})
	if ord := orderOf(n.path); len(ord) > 0 {
		n.applyOrder(ord)
	}
	for _, k := range n.kids {
		if k.folder {
			sortKids(k)
		}
	}
}

// applyOrder rearranges the children to match a folder's .order, through the same pure rule the
// store package tests — the nodes are matched back to the arranged names one at a time, so two
// children that cannot be told apart at least keep their relative order.
func (n *treeNode) applyOrder(order []string) {
	keys := make([]string, 0, len(n.kids))
	byKey := map[string][]*treeNode{}
	for _, k := range n.kids {
		keys = append(keys, k.key())
		byKey[k.key()] = append(byKey[k.key()], k)
	}
	out := make([]*treeNode, 0, len(n.kids))
	for _, key := range passstore.Arrange(order, keys) {
		q := byKey[key]
		if len(q) == 0 {
			continue
		}
		out = append(out, q[0])
		byKey[key] = q[1:]
	}
	if len(out) == len(n.kids) {
		n.kids = out
	}
}

// visibleRows flattens the tree into the lines that will be drawn: every child of an open folder,
// in order, and nothing at all under a folded one.
func visibleRows(n *treeNode, open map[string]bool, out []*treeNode) []*treeNode {
	for _, k := range n.kids {
		out = append(out, k)
		if k.folder && open[k.path] {
			out = visibleRows(k, open, out)
		}
	}
	return out
}

// find returns the node at a store path, so a selection survives a rebuild of the tree.
func find(n *treeNode, path string) *treeNode {
	for _, k := range n.kids {
		if k.path == path {
			return k
		}
		if k.folder {
			if got := find(k, path); got != nil {
				return got
			}
		}
	}
	return nil
}

// siblingKeys is a folder's children exactly as .order writes them.
func siblingKeys(n *treeNode) []string {
	out := make([]string, 0, len(n.kids))
	for _, k := range n.kids {
		out = append(out, k.key())
	}
	return out
}

// shift moves a node d places among its SIBLINGS, and reports whether there was room to.
//
// Only among its siblings: a node that could be dragged out of its folder would be a move, and a
// move renames the entry — which is what [m] is for, with a path on screen and a confirmation of
// what it became. Reordering must not be able to do that by accident.
func shift(n *treeNode, d int) bool {
	p := n.parent
	if p == nil {
		return false
	}
	i := -1
	for x, k := range p.kids {
		if k == n {
			i = x
			break
		}
	}
	j := i + d
	if i < 0 || j < 0 || j >= len(p.kids) {
		return false
	}
	p.kids[i], p.kids[j] = p.kids[j], p.kids[i]
	return true
}

// ancestors lists the folders an entry sits under, outermost first.
func ancestors(name string) []string {
	segs := strings.Split(name, "/")
	if len(segs) < 2 {
		return nil
	}
	out := make([]string, 0, len(segs)-1)
	acc := ""
	for _, seg := range segs[:len(segs)-1] {
		if acc == "" {
			acc = seg
		} else {
			acc += "/" + seg
		}
		out = append(out, acc)
	}
	return out
}

// parentName names the folder a node sits in, for the messages a reorder produces. The root has
// no name of its own, and "moved in " followed by nothing reads as a truncated sentence.
func parentName(n *treeNode) string {
	if n.parent == nil || n.parent.path == "" {
		return "the store's root"
	}
	return n.parent.path
}

// folderPaths is every folder the store has, used to keep the saved fold state from accumulating
// paths that no longer exist.
func folderPaths(entries []passstore.Entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		for _, f := range ancestors(e.Name) {
			out[f] = true
		}
	}
	return out
}

// openSet turns the saved state into the map the tree walks with.
func openSet(s config.TreeState) map[string]bool {
	out := make(map[string]bool, len(s.Open))
	for _, p := range s.Open {
		out[p] = true
	}
	return out
}

// treeState turns the map back, dropping folders the store no longer has — but only when the
// store has actually been read. Pruning against an empty list at startup would throw away the
// state the first draw is about to need.
func treeState(open map[string]bool, known map[string]bool) config.TreeState {
	var s config.TreeState
	for p := range open {
		if !open[p] {
			continue
		}
		if len(known) > 0 && !known[p] {
			continue
		}
		s.Open = append(s.Open, p)
	}
	sort.Strings(s.Open)
	return s
}
