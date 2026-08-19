# keyforge

A terminal layer over `ssh-keygen`, `gpg`, `openssl` and `pass` — for making keys and passwords, and
for answering the question those tools never ask themselves: **which of the secrets on this machine
would actually stop someone who already holds a copy of the files.**

A single static binary. No runtime dependencies; it starts from a recovery shell.

## Two principles

**No secret ever crosses a command line.** `ssh-keygen -N 'passphrase'` leaves it visible in `ps` for
the duration of the run — any local user can read it out of `/proc`. So keyforge steps aside and
hands the terminal to `ssh-keygen`, which asks for the passphrase itself. Passwords written into
`pass` go in over a pipe keyforge builds by hand, not as an argument.

**Nothing cryptographic is reinvented.** The tools that already exist do the work. keyforge only
knows who to call, with which flags, in what order. For the same reason it stores no passwords of its
own but uses `pass`: writing another store would mean new, unreviewed cryptography sitting directly
under the secrets it claims to protect.

## Usage

```sh
keyforge                 # interface
keyforge --audit         # the audit as text (for cron, for a shell prompt)
keyforge --gen           # one phrase on stdout
keyforge --gen --words 7
keyforge --gen --chars 32
```

`--audit` exits according to what it found: `0` clean, `1` warnings, `2` something is open right now.
So it can sit in cron and stay quiet until it has something to say.

## The tabs

**Keys** — every private key in `~/.ssh` with its type, size, whether it has a passphrase, its format
and **which hosts it opens** (from `~/.ssh/config`). From there: a new key, a passphrase change,
copying the public half, deploying it to a server, reading someone else's `authorized_keys` and —
most importantly — **revocation**.

Revocation is the half of a rotation that usually gets skipped. A new key by itself changes nothing:
the old public key keeps opening every machine it was ever installed on, and will go on doing so for
years unless somebody removes it.

**Generator** — word phrases (from a built-in list; the tab reports the entropy it actually drew
from) and random strings. All from `crypto/rand`. It shows the entropy and how long cracking would take, **with the
assumption stated** — a number without its assumption is advertising, not an estimate. It writes
straight into `pass`.

A word phrase is the better choice for a key passphrase: it is long, it is memorable, and once it is
on screen a wrong keyboard layout is obvious at a glance — unlike a string behind asterisks.

When a sheet rule is set up, everything generated here is composed under it: the reserved characters
are never produced, and the piece you remember is inside the value. That is what keeps the printed
page from being enough on its own, so it has to happen where passwords are actually made.

**Passwords** — the `pass` store as a tree, and the operations a store actually needs: add an
existing password, generate one straight into a folder, copy, change, move, delete, filter.

The password is typed into a masked field backed by locked memory (see *Process hardening* below)
and reaches `pass` through a pipe keyforge opens itself — never as an argument, never as a Go string
that cannot be erased afterwards. Copying goes the other way: `pass show --clip` decrypts and hands
the value straight to the clipboard helper, which clears it again after 45 seconds — that path never
brings the password through keyforge at all. `[v]` does, when what you need is to read it rather
than paste it.

The entry is written in the layout the rest of the pass ecosystem reads — the password on the first
line, `login:` and `url:` below it:

```
correct-horse-battery-staple
login: me@example.com
url: https://example.com
```

**The store's master password.** Everything in `pass` is encrypted to one GPG key, so that key's
passphrase is the master password for all of it. `pass` never mentions this; it runs perfectly well
on a key with no passphrase and says nothing. The tab shows the state at the top and `[p]` changes it:

| | |
|---|---|
| `locked` | there is a passphrase and the agent is not holding it |
| `unlocked in the agent` | it was entered recently; until the cache expires, anything that can reach the agent socket reads every entry |
| `NO PASSPHRASE` | a copy of `~/.password-store` opens immediately, with everything in it |

How long "recently" lasts is `default-cache-ttl` in `~/.gnupg/gpg-agent.conf` (10 minutes by
default, 2 hours maximum).

**Audit** — keys with no passphrase, weak algorithms, the old PEM format, wrong permissions, keys
loaded into the agent, invalid lines in `authorized_keys`, and the password store's master password.
As root it also checks `/etc/shadow` and the `sshd` configuration. Without root it **says so**,
rather than reporting a clean bill of health for something it could not read.

**GPG** — the secret keys and their expiry dates. An expiring GPG key stops `pass` and signed commits
without warning.

**Certificates** — what is on disk and how long it is valid.

**Print** — a sheet for paper. Paper is the only backup that survives a compromised machine and a
forgotten master password, so it gets a tab of its own — and the whole tab is built around being
printed and then disappearing.

The file is written into `/dev/shm`, that is, into **memory**: the plaintext secrets never touch
persistent storage, nothing goes into a journal, and there is no block to recover after deletion.
`[S]` wipes it, and a reboot wipes it without you having to remember.

## Secrets on screen

One rule, in every tab that holds a value: **masked until asked, visible for 30 seconds, masked
again.** `[v]` is the only thing that turns it on — nothing reveals itself.

That includes the generator, which used to print its phrase in the clear and leave it there for as
long as the tab was open. A freshly generated password is not less of a password for being new, and
a screen is the easiest place to take one from and the hardest place to notice it being taken. It is
also the reason the reveal expires rather than waiting to be switched off: the case worth defending
against is not the person at the keyboard, it is the person who walks past after they have gone.

Generating a new value hides the old one, and in the password list moving to another entry or leaving
the details puts it away — every exit from a reveal is an exit, not just the timer.

Where the value lives while it is shown depends on where it came from. In the password list `pass
show` writes into a pipe keyforge opens itself and the bytes are read into locked memory, so the
decrypted password never becomes a Go string except for the instant it is drawn. That instant is
unavoidable: a terminal takes strings.

## The lock

One key covers keyforge over. It opens again by proving you can use the GPG key the store is
encrypted to — gpg asks through pinentry, keyforge never sees the passphrase, and there is no second
password to remember and no hash of one on disk.

```json
"lock": { "idle_minutes": 10, "clear_agent": true, "at_start": false, "key": "ctrl+x" }
```

`idle_minutes` locks after that much quiet; `0`, the default, means the lock only happens when you
ask for it. `key` is that ask — `""` removes it and leaves only the timer. `at_start` opens keyforge
already covered, and what that is worth depends entirely on `clear_agent`: with the passphrase still
cached the curtain lifts without asking anything, so it would only be pretending.

The key is configurable because a terminal is already full of bindings that belong to something
else: `ctrl+l` is the obvious choice and is a tmux window binding on many setups, and a redraw
almost everywhere. Note that whatever is set here is taken by the shell **before** any tab sees it,
so binding a key a tab uses takes that key away from the tab.

**Locking clears the gpg agent, and that is the whole of why it is worth having.** keyforge holds
none of the data it shows — `pass` does, `~/.ssh` does — so covering this interface cannot stop
anyone who can reach the account; they would run `pass show`. Worse, with the passphrase still
cached gpg opens the unlock challenge without prompting, so the lock would spring open on an empty
keypress for as long as the cache lasts, which is exactly the window it exists to cover. Clearing
first makes the prompt real, and shuts the store while it is at it: after locking, `pass show` in
another terminal asks too.

The cost is that the agent is shared. Locking keyforge also makes your other terminals and your
signed commits ask again. Set `clear_agent` to `false` if that is not the trade you want, and the
lock will say plainly, on its own screen, that it is now only hiding the screen.

The lock needs a GPG key to exist; without `pass` set up there is nothing to unlock against, and
keyforge says so rather than inventing a password to fill the gap.

## How long the store stays open

The real timer is not keyforge's. Everything in `pass` is shut by the passphrase on one GPG key, and
how long that stays entered is decided by gpg-agent. keyforge can set it, but writes it where the
agent will read it rather than keeping a copy of its own — a lifetime remembered here and enforced
nowhere would describe a protection that is not in force:

```json
"agent": { "default_cache_ttl": 600, "max_cache_ttl": 7200 }
```

Seconds; `0` leaves gpg-agent's own configuration alone. The values are written into
`~/.gnupg/gpg-agent.conf` — with the `-ssh` variants alongside them, or an ssh key would stay open
after the store had shut — and only when they differ from what is already there. Applying them on
every launch would reload the agent every time, and a reload drops every cached passphrase: keyforge
would be logging you out of your own store each time it started.

## The rule for the sheet

The sheet must not be the password itself. Two rules, both carried by ordinary characters that the
generator is forbidden to produce — so what comes out of the printer looks like an ordinary password
and nothing on the page reveals that a rule exists at all:

```
to strip    q, 7        delete them as you read
to insert   z → Qx9     replace them with what you remember

on paper : nebula-zgabble-diego-astq7hma-marsha
password : nebula-Qx9gabble-diego-asthma-marsha
```

The two are **not equally strong**, and it is worth being clear about why. Stripping hides the rule,
not the password: the page contains every character of it plus noise, so whoever learns the rule
reads it straight off. Insertion hides the password itself — a piece is missing from the page that
was never written down anywhere, and no amount of study reconstructs it.

The length is compensated: the value is generated as many characters shorter as will be inserted, so
the sheet ends up showing the round number you asked for.

**Where the rule lives.** Not in the config. The whole of it — the noise characters, how many are
scattered, the markers and what each one stands for — is encrypted into a `pass` entry, and the
config keeps only that entry's name:

```json
"sheet": { "rule_from": "f644307786", "cache_minutes": 60 }
```

The name is random hex, generated once, and says nothing about what is inside; in a listing it is
one more entry among the others. This is a change from how it used to work, and the reason is
worth stating: keeping the STRUCTURE in the config while withholding only the values was defended
on the grounds that structure alone does not open a password. That holds right up until the paper
is in somebody's hands — and then "delete every q and 7" IS the key to reading it. The page is the
one part of this system designed to leave the machine, so the machine must not also hold its
legend.

Reading it needs the store's passphrase, so it is read on demand — never at startup, so opening
keyforge to look at an SSH audit does not raise a prompt — and held for `cache_minutes`
afterwards. **While it is held, the screen says so in red** and `ctrl+f` ends it early. That
admission is not decoration: gpg-agent's cache is the agent's business and keyforge only reports
it, but this one is keyforge's own doing, and a program that quietly held a decrypted secret for
an hour while showing nothing would be doing the very thing it exists to expose.

**The rule cannot be edited.** Once it is set, `[m]` disappears — changing it would invalidate
every sheet already printed under the old one, and a key labelled "rule" on a machine that has one
announces the scheme to anyone reading over a shoulder. It is offered exactly once, before the
first password, and after that nothing in the interface mentions it.

## What is remembered, and what never is

| in `~/.config/keyforge/config.json` | encrypted in `pass` | written nowhere |
|---|---|---|
| the NAME of the rule entry | which characters are noise | **what stands behind the marker** |
| how long the rule may be held | how many are scattered | **any password at all** |
| when to lock, whether to clear the agent | which characters are markers | |
| password length, words, separator | | |

**The value is never built into the binary either.** A string handed to the compiler sits there in
plain text and `strings` finds it with one command — and Go records the whole flag line too, so how
it was passed is visible as well. Encrypting does not help: the key has to be in there too. A
program that knows the value without asking you **contains** the value. (Earlier versions offered
`-ldflags -X …` for the structure; those flags are gone, and with them the temptation.)

## Settings

The seventh tab, for the settings that have nowhere else to live: persistent, invisible, and not
adjustable where their effect can be seen. Password length is none of those — it is `+`/`-` in the
Generator while the result changes in front of you — so it is not there.

| | |
|---|---|
| `lock on opening` | keyforge opens covered (`lock.at_start`) |
| `lock after idle` | minutes, `0` for never |
| `locking clears the agent` | what turns the curtain into a lock — see below |
| `lock key` | claimed by the shell before any tab sees it |
| `agent forgets after idle` | `default-cache-ttl`, restarts on every use |
| `agent forgets regardless` | `max-cache-ttl`, the ceiling from when you typed it |
| `theme` | a palette name or a path — see *Colours* below; `[t]` repaints without restarting |
| `keyforge keeps the sheet rule` | `sheet.cache_minutes` — keyforge's own memory, not the agent's |

Each row says what it costs, and the agent's real state is shown above them: a number without what
it is currently doing is half the information.

## Colours

The palette is **ten roles, not ten colours**: red is "this is open right now", yellow "this will
bite you later", green "verified good", grey is context, blue the interactive accent, purple and
orange the two secondary ones. A theme moves the values; nothing can move the meanings.

keyforge follows [lvim-colorscheme](https://github.com/lvim-tech/lvim-colorscheme). That plugin
writes the active theme's name to `stdpath("data")/lvim-colorscheme/theme` precisely so a
non-Neovim reader can find it without loading anything, and keyforge reads it. Change the
colorscheme in the editor and keyforge is repainted the next time it starts, or immediately with
`[t]` in Settings.

Where a palette is looked for, in order — each step skipped when it does not resolve:

1. `$KEYFORGE_THEME` — a theme name, or a path to a palette file.
2. `$LVIM_COLORSCHEME` — a theme name.
3. whatever lvim-colorscheme says is active (`…/lvim-colorscheme/theme`, then its `settings.json`).
4. `theme` in `~/.config/keyforge/config.json` — a name or a path.
5. the built-in Everforest.

A name is resolved to a per-app theme file in `~/.config/keyforge/themes/`, one file per theme,
under both spellings the plugin uses — the `:colorscheme` one (`lvim-everforest-soft.yaml`) and the
generated-file one (`LvimEverforest_soft.yaml`). lvim-colorscheme generates these files for keyforge
(`extras/keyforge/*.yaml`), the same per-app shape it generates for the other tools in this set.

The palette document is YAML, and its keys are the ten roles:

```yaml
name: LvimEverforest_soft
colors:
    bg: "#292f33"
    bg_alt: "#32393f"
    fg: "#9baf95"
    dim: "#5a6158"
    red: "#cb4f4f"
    yellow: "#af9e6b"
    green: "#75783a"
    blue: "#42728b"
    purple: "#635d71"
    orange: "#cc7942"
```

A flat mapping of role → hex is accepted as well, and a path ending `.json` is read too (the same
parser handles both). **Nothing here can fail the program**: a missing,
unreadable or partial file costs only the colours it could not supply — every role it does not
name comes from the built-in, and Settings says which ones did. The foreground is checked against
the background and lifted, hue intact, if it falls below 3:1 — several editor palettes carry a
deliberately muted `fg` that is unreadable as plain text on a terminal.

## Process hardening

| | |
|---|---|
| `RLIMIT_CORE = 0` | a crash leaves no dump — on this machine it would land in `/var/lib/systemd/coredump` as a readable file |
| `PR_SET_DUMPABLE 0` | another process cannot attach a debugger and read the memory |
| `mmap` + `mlock` + `MADV_DONTDUMP` | the remembered piece lives outside the Go heap, never goes to swap, is excluded from dumps |
| masked field | the value appears only when asked, and not for long |

It is not a Go string, and that is the substance of it: a string is immutable, so it cannot be
zeroed, and the garbage collector may have moved it and left copies nobody can reach. An anonymous
mapping is the only region whose address and lifetime the program genuinely controls.

## How a key with a passphrase is recognised

The only honest way, and the reason the audit here can be trusted:

```sh
ssh-keygen -y -P "" -f <key>     # exit 0 → no passphrase
```

Searching the file for the word `ENCRYPTED` works only for the old PEM format. Every key written by a
modern `ssh-keygen` is in an OpenSSH container where the KDF's name is **inside the base64 block** —
so the grep quietly answers "no passphrase" for every modern key.

The GPG side is the same question with a different answer. There is no honest way to read protection
out of a key file under `~/.gnupg/private-keys-v1.d`, so keyforge asks the agent, which knows:

```sh
gpg-connect-agent 'KEYINFO --list' /bye   # P = passphrase, C = none, - = would not say
```

## How far the protection goes

| Against what | Does it help |
|---|---|
| A stolen disk, a backup, another user | yes |
| Access to the session while `pass` is locked | yes |
| Root on the machine while the agent remembers the passphrase | **no** |
| Root on the machine with the agent locked | in practice, yes |

The third row is true of `pass`, of `ssh-agent`, of `gnome-keyring` and of anything that could be
written here. There is no local construction that beats it. The one thing that does is a hardware
key — the private key never leaves the device.

## Building

```sh
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o keyforge .
```

## Licence

BSD-3-Clause
