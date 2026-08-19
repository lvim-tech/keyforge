package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// TreeState is which folders of the Passwords tree are unfolded, and nothing else.
//
// IT IS DELIBERATELY NOT PART OF Config. The order of a store's entries belongs to the store and
// travels with it — that is why it lives in `.order` files inside the store itself. Which folders
// happen to be open is the opposite kind of fact: it is where this terminal, on this machine, is
// looking right now. It is not organisation, it is not worth a git commit, and syncing it would
// mean one machine's screen rearranging another's.
//
// It holds folder PATHS. Those are already visible in a directory listing of the store to anyone
// who can read this file, so writing them here reveals nothing new — but that is the whole budget:
// no entry names, no metadata, nothing that has ever been decrypted.
type TreeState struct {
	// Open lists the unfolded folders by store path. Sorted when written, so a state file in a
	// dotfile repository does not churn between two runs that changed nothing.
	Open []string `json:"open"`
}

// TreeStatePath is the fold state's file, beside the config and never inside it.
func TreeStatePath() string { return configFile("tree-state.json", "keyforge-tree-state.json") }

// LoadTreeState reads the fold state, and CANNOT fail.
//
// A missing file is the first run. A corrupt one is a file somebody's editor or a half-finished
// write left behind — and unlike the config, where a silent reset would put a rule the user no
// longer believes in back in force, the worst that a reset costs here is a tree that opens folded.
// Refusing to start, or shouting about it, would be out of all proportion to that.
//
// The default is the root level unfolded and everything under it folded: the top of the store on
// one screen, which is the shape of a tree rather than the flat list this replaced.
func LoadTreeState() TreeState {
	var s TreeState
	b, err := os.ReadFile(TreeStatePath())
	if err != nil {
		return TreeState{}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return TreeState{}
	}
	return s
}

// SaveTreeState writes the fold state through a temporary file and a rename.
//
// Two keyforges on one machine is an ordinary thing — one in each of two terminals — and both
// write this file as folders are opened. A rename is atomic, so the other one either reads the
// old state or the new one, and never the empty middle of a truncated write.
func SaveTreeState(s TreeState) error {
	p := TreeStatePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	sort.Strings(s.Open)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "tree-state-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
	if err := os.Rename(name, p); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
