package ui

import (
	"errors"
	"fmt"
	"time"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sheet"
	"github.com/lvim-tech/keyforge/internal/sys"
)

// ruleCache holds the printing rule between the actions that need it.
//
// READ ON DEMAND, NOT AT STARTUP. The rule constrains generation, so the first design read
// it in New() — which meant opening keyforge to look at an SSH audit could raise a passphrase
// prompt for the printing scheme. Nothing needs it until a password is generated or a sheet
// is made, and both of those are deliberate acts.
//
// KEPT IN LOCKED MEMORY, NOT AS A STRING. What is cached is the encrypted entry's plaintext,
// which contains the value standing behind the marker — the one piece of this whole scheme
// that was never supposed to be written down. Holding it in an ordinary Go string would mean
// copies the collector may move and nothing can erase, for as long as the cache lasts. It is
// decoded afresh for each use and the decoded form is dropped immediately.
//
// AND IT IS ADMITTED WHILE IT LASTS. gpg-agent's cache is the agent's business and keyforge
// only reports it; this one is keyforge's own doing. A program that quietly held a decrypted
// secret for an hour while showing nothing would be doing the thing it was written to expose.
type ruleCache struct {
	from string        // the pass entry, "" when there is no rule at all
	ttl  time.Duration // 0 means never keep it

	body  *sys.Secret
	until time.Time
}

// errUnreadableRule is what every caller must refuse on. Worded without naming the thing:
// it says a stored value could not be read, which is true and tells a shoulder-reader nothing.
var errUnreadableRule = errors.New("the stored value could not be understood — refusing to " +
	"generate or print without it")

func newRuleCache(c config.Config) *ruleCache {
	return &ruleCache{
		from: c.Sheet.RuleFrom,
		ttl:  time.Duration(c.Sheet.CacheMinutes) * time.Minute,
	}
}

// configured reports whether a rule exists to be read.
//
// The distinction this draws is the one the whole design turns on: NO rule and a rule that
// cannot be read are different situations. The first is the ordinary state of most machines
// and calls for an offer; the second means something is wrong and calls for a refusal.
func (rc *ruleCache) configured() bool { return rc.from != "" }

// adopt records a rule that has just been written, so the action that prompted it can carry
// straight on rather than sending the user back to do the same thing again.
func (rc *ruleCache) adopt(name string, body string) {
	rc.forget()
	rc.from = name
	if rc.ttl <= 0 {
		return
	}
	sec, err := sys.NewSecret(len(body) + 16)
	if err != nil {
		return
	}
	sec.Append([]byte(body))
	rc.body = sec
	rc.until = time.Now().Add(rc.ttl)
}

// held reports whether the decrypted rule is in this process right now.
func (rc *ruleCache) held() bool {
	return rc.body != nil && time.Now().Before(rc.until)
}

// remaining is how long it will stay, for the line that admits to holding it.
func (rc *ruleCache) remaining() time.Duration {
	if !rc.held() {
		return 0
	}
	return time.Until(rc.until)
}

// forget wipes it now.
func (rc *ruleCache) forget() {
	if rc.body != nil {
		rc.body.Close()
		rc.body = nil
	}
	rc.until = time.Time{}
}

// get returns the rule, reading it if it is not held.
//
// The error is returned rather than swallowed, because the caller must refuse rather than
// carry on: a password generated without the rule looks perfectly good and cannot be put on
// a sheet, which is discovered only when the sheet is needed.
func (rc *ruleCache) get() (sheet.Rule, error) {
	if !rc.configured() {
		return sheet.Rule{}, nil
	}
	if rc.held() {
		var (
			r  sheet.Rule
			ok bool
		)
		rc.body.Use(func(s string) { r, ok = sheet.DecodeRuleStrict(s) })
		if !ok {
			return sheet.Rule{}, errUnreadableRule
		}
		return r, nil
	}
	rc.forget()

	sec, err := passstore.Reveal(rc.from)
	if err != nil {
		return sheet.Rule{}, fmt.Errorf("the rule could not be read: %v", err)
	}
	var (
		r  sheet.Rule
		ok bool
	)
	sec.Use(func(s string) { r, ok = sheet.DecodeRuleStrict(s) })
	if !ok {
		// Read but not understood is NOT the same as absent, and this is the seam that knows
		// the difference: rc.configured() is true, so a rule was expected. Returning the empty
		// rule here would let generation proceed with no reserved characters while the user
		// believes the rule is in force — a password that looks perfectly good and can never go
		// on a sheet, which is the exact failure this cache was written to prevent.
		sec.Close()
		return sheet.Rule{}, errUnreadableRule
	}

	if rc.ttl <= 0 {
		sec.Close()
		return r, nil
	}
	rc.body = sec
	rc.until = time.Now().Add(rc.ttl)
	return r, nil
}

// reserved is the characters nothing may generate, or an error the caller must not ignore.
func (rc *ruleCache) reserved() (string, error) {
	r, err := rc.get()
	if err != nil {
		return "", err
	}
	return r.Mask().Reserved(), nil
}

// warning is the line shown while the rule is held, or "" when it is not.
func (rc *ruleCache) warning() string {
	if !rc.held() {
		return ""
	}
	return fmt.Sprintf("the printing rule is unlocked in keyforge for %s", short(rc.remaining()))
}
