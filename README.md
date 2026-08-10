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

**Generator** — word phrases (a built-in list of 13 977 words, 13.8 bits per word) and random
strings. All from `crypto/rand`. It shows the entropy and how long cracking would take, **with the
assumption stated** — a number without its assumption is advertising, not an estimate. It writes
straight into `pass`.

A word phrase is the better choice for a key passphrase: it is long, it is memorable, and a wrong
keyboard layout shows at once — unlike a string hidden behind asterisks.

**Passwords** — the `pass` store as a tree, and the operations a store actually needs: add an
existing password, generate one straight into a folder, copy, change, move, delete, filter.

The password is typed into a masked field backed by locked memory (see *Process hardening* below)
and reaches `pass` through a pipe keyforge opens itself — never as an argument, never as a Go string
that cannot be erased afterwards. Copying goes the other way: `pass show --clip` decrypts and hands
the value straight to the clipboard helper, which clears it again after 45 seconds. keyforge never
sees it, and that is why there is no "reveal" beside it.

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

## What is remembered, and what never is

| written to `~/.config/keyforge/config.json` | written nowhere |
|---|---|
| which characters are stripped | **what stands behind the marker** |
| how many are inserted | |
| which characters are markers | |

The structure can also be built into the binary, if you would rather not have a config file at all:

```sh
P=github.com/lvim-tech/keyforge/internal/config
go build -ldflags "-X $P.buildStrip=q7 -X $P.buildStripCount=2 -X $P.buildMarkers=z" -o keyforge .
```

**The value, however, is never built in.** A string handed to the compiler sits in the binary in
plain text and `strings` finds it with one command — and Go records the whole flag line too, so how
it was passed is visible as well. Encrypting does not help: the key has to be in there too. A program
that knows the value without asking you **contains** the value.

## Process hardening

| | |
|---|---|
| `RLIMIT_CORE = 0` | a crash leaves no dump — on this machine it would land in `/var/lib/systemd/coredump` as a readable file |
| `PR_SET_DUMPABLE 0` | another process cannot attach a debugger and read the memory |
| `mmap` + `mlock` + `MADV_DONTDUMP` | the remembered piece lives outside the Go heap, never goes to swap, is excluded from dumps |
| masked field | the value never appears on screen |

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
