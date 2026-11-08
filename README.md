# git-safe

Quarantines Git downloads until incoming history is covered by an explicitly
trusted OpenPGP signer and updates are fast-forwards. A trusted signature covers
its commit and its ancestors; it does not assert that the code is harmless.

## Installation

Start with a complete source checkout and a current stable Rust toolchain
(Cargo and rustc). Run installers as your regular user.

On Debian/Ubuntu Linux:

```sh
bash install-linux.sh
```

The script installs dependencies using sudo, builds a Debian package with a locked
dependency graph, and installs it. This wraps system Git and sets system-wide
Git hooks. Protected operations require a kernel with Landlock support and
permission to create Bubblewrap user namespaces; restricted containers may
prevent them. Installation does not grant trust to any signer.

On Windows, first set up a Debian/Ubuntu **WSL2** distribution and install
Rust/Cargo inside it. From PowerShell in this checkout:

```powershell
.\install-windows.ps1 -Distribution Ubuntu
```

This runs the Linux installer inside WSL2. Use Git there; Windows Git is unchanged.
The script does not install WSL or change PowerShell execution policy.

On macOS:

```sh
bash install-macos.sh
```

Native macOS protection is not implemented. This script exits with an explanation
and makes no changes. Use the Linux installer inside a Debian/Ubuntu VM instead.

After installation, import and verify a signer's public key as described below.

## Trusted signers

Trust is per operating-system user. The store starts empty and is created on
first use at `$XDG_DATA_HOME/git-safe/trust.sqlite3`, or
`~/.local/share/git-safe/trust.sqlite3` when XDG_DATA_HOME is unset. No package
review key is automatically trusted, including on upgrades. Existing downloads
that relied on that key require explicit registration before they can continue.

A signer has a unique local ID and a unique full primary-key fingerprint. IDs use
letters, digits, dots, underscores and hyphens (up to 64 characters). A key export
must contain exactly one primary public key and can include its signing subkeys.
Git-safe extracts fingerprints itself. It never exports private signing keys.

Find your primary fingerprint with `gpg --list-keys --with-fingerprint`.

### Exchange a public-key file

On the signer's computer:

```sh
git-safe keys export --key PRIMARY_FINGERPRINT --output alice.asc
```

Send `alice.asc` to the recipient using your preferred channel. On their computer:

```sh
git-safe keys import alice alice.asc
git-safe keys list
```

The importer displays the primary fingerprint and asks for approval. Confirm it
with the intended signer through a trusted channel. For automation, supply an
independently verified fingerprint explicitly:

```sh
git-safe keys import alice alice.asc --fingerprint PRIMARY_FINGERPRINT --yes
```

Exports refuse to overwrite an existing file. Private-key exports, files larger
than 1 MiB, bundles containing multiple primary keys, and fingerprint mismatches
are rejected. The personal GPG home (`GNUPGHOME`, if set) is used only for export.
Verification uses a separate temporary public-only keyring populated from SQLite;
GPG ownertrust, email addresses, and repository-selected GPG programs cannot grant
signer authorization.

Import an updated export under the same ID to merge subkeys, expiration updates,
and revocations. Known revocations are retained when older exports are imported.
A different primary fingerprint cannot silently replace an existing signer.

```sh
git-safe keys import alice alice-updated.asc
git-safe keys remove alice
```

There is no automatic update discovery: repeat the file or Tor exchange when a
signer changes their key. Removal affects subsequent verification sessions; it
does not delete commits previously downloaded.

### Exchange over Tor

Install the `tor` executable on both computers (the Debian package depends on it).
Git-safe starts its own client process; no Tor Browser, system Tor service,
public IP, router port forwarding, or account is required. A source build needs
`tor` on PATH, plus GPG at `/usr/bin/gpg`.

On Alice's computer:

```sh
git-safe peer invite --key ALICE_PRIMARY_FINGERPRINT
```

Share the entire `git-safe://...onion/...` invitation privately. On the recipient's
computer:

```sh
git-safe peer connect --id alice
```

Paste the invitation when prompted, inspect the received fingerprint, and approve
it. The received key enters the same SQLite store as a manual import.

For a two-way exchange, Alice specifies the ID she will assign to Bob:

```sh
git-safe peer invite --key ALICE_PRIMARY_FINGERPRINT --peer-id bob
```

Bob supplies his own primary fingerprint:

```sh
git-safe peer connect --id alice --key BOB_PRIMARY_FINGERPRINT
```

Each person approves the other signer independently. One approval may succeed
even if the other person declines or disconnects; the two stores are independent.

Invitations contain a random 256-bit secret and a v3 onion address. They expire
five minutes after creation and are consumed by one connection attempt. A wrong
secret cancels the invitation. Share it only with the intended person; possession
of the full invitation authorizes attempting the exchange. Secrets are entered
interactively rather than passed as command-line arguments.

Tor authenticates the onion address and encrypts the connection; git-safe checks
the invitation secret before accepting application messages. Payload sizes,
network operations, and approval waits are bounded. Ctrl-C cancels the command.
The local listener is bound only to loopback. The temporary onion identity is
discarded when the process stops; Tor's normal client state and directory cache
remain in the private `git-safe/tor` data directory for future sessions.

Both computers must stay online during the exchange. First startup and onion
publication may take a minute or more. Networks blocking Tor may prevent the
exchange; this initial integration does not expose bridge configuration. Use the
file commands as the offline alternative. Once keys are imported, Git verification
does not need Tor or any network service.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Tests generate isolated temporary GPG identities and cover clone/fetch gating,
public-key import/export, subkey updates, duplicate IDs/fingerprints, secret-key
rejection, revocation preservation, and empty-store refusal. Routine tests do not
connect to the public Tor network.

An opt-in real-network test exercises two-way Tor exchange using generated test
keys (requires `tor` on PATH and Python `pexpect`):

```sh
cargo build
python3 tests/tor_live.py
```
