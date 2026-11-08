#!/bin/bash
# The review key covers older commits. A later commit still needs that same key.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${GIT_SAFE_BIN:-$ROOT/target/debug/git-safe}"
if [[ ! -x "$BIN" ]]; then
  echo "git-safe binary is missing: $BIN" >&2
  exit 1
fi

if [[ -x /usr/lib/git-safe/git.real ]]; then
  REAL=/usr/lib/git-safe/git.real
elif [[ -x /usr/local/lib/git-safe/git.real ]]; then
  REAL=/usr/local/lib/git-safe/git.real
else
  REAL=/usr/lib/git-core/git
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home"
export GIT_CONFIG_NOSYSTEM=1
export GIT_SAFE_REAL_GIT="$REAL"
export GIT_AUTHOR_NAME="git-safe-test"
export GIT_AUTHOR_EMAIL="git-safe-test@example.com"
export GIT_COMMITTER_NAME="git-safe-test"
export GIT_COMMITTER_EMAIL="git-safe-test@example.com"
mkdir -p "$HOME"
chmod 700 "$HOME"

GPG_PROGRAM="$WORK/gpg-sign"
cat > "$GPG_PROGRAM" << 'EOF'
#!/bin/sh
exec gpg --batch --pinentry-mode loopback --passphrase '' "$@"
EOF
chmod 755 "$GPG_PROGRAM"

make_key() {
  local home="$1" uid="$2"
  mkdir -p "$home"
  chmod 700 "$home"
  GNUPGHOME="$home" gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "$uid" ed25519 sign never >/dev/null
  GNUPGHOME="$home" gpg --with-colons --list-secret-keys | awk -F: '/^fpr:/ { print $10; exit }'
}

REVIEW_HOME="$WORK/review-secret"
PERSONAL_HOME="$WORK/personal-secret"
TRUST_HOME="$WORK/trust"
REVIEW_FPR="$(make_key "$REVIEW_HOME" "git-safe review <git-safe-review@example.com>")"
PERSONAL_FPR="$(make_key "$PERSONAL_HOME" "personal signer <personal@example.com>")"
mkdir -p "$TRUST_HOME"
chmod 700 "$TRUST_HOME"
GNUPGHOME="$REVIEW_HOME" gpg --export "$REVIEW_FPR" | GNUPGHOME="$TRUST_HOME" gpg --batch --import >/dev/null
printf '%s:6:\n' "$REVIEW_FPR" | GNUPGHOME="$TRUST_HOME" gpg --import-ownertrust
GNUPGHOME="$TRUST_HOME" gpg --batch --update-trustdb >/dev/null
export XDG_DATA_HOME="$WORK/data"
GNUPGHOME="$REVIEW_HOME" "$BIN" keys export --key "$REVIEW_FPR" --output "$WORK/review.asc"
"$BIN" keys import review "$WORK/review.asc" --yes --fingerprint "$REVIEW_FPR"

git() { "$REAL" "$@"; }

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

configure_repo() {
  local repo="$1" home="$2" fpr="$3"
  git -C "$repo" config user.name "git-safe-test"
  git -C "$repo" config user.email "git-safe-test@example.com"
  git -C "$repo" config user.signingkey "$fpr"
  git -C "$repo" config gpg.program "$GPG_PROGRAM"
  git -C "$repo" config commit.gpgsign true
  # The signer is selected by the keyring passed in GNUPGHOME at commit time.
  git -C "$repo" config core.hooksPath /dev/null
}

# Unsigned history, then one review-signed tip, must clone.
origin="$WORK/reviewed.git"
seed="$WORK/reviewed-seed"
down="$WORK/reviewed-down"
git init --bare -b master "$origin"
git init -b master "$seed"
configure_repo "$seed" "$REVIEW_HOME" "$REVIEW_FPR"
git -C "$seed" config commit.gpgsign false
echo base >> "$seed/file"
git -C "$seed" add file
git -C "$seed" commit -m "unsigned base"
echo next >> "$seed/file"
git -C "$seed" add file
git -C "$seed" commit -m "unsigned next"
git -C "$seed" config commit.gpgsign true
GNUPGHOME="$REVIEW_HOME" git -C "$seed" commit --allow-empty -m "git-safe review"
status="$(GNUPGHOME="$TRUST_HOME" git -C "$seed" log -1 --format='%G?')"
[[ "$status" == "G" ]] || fail "review tip status is $status"
git -C "$seed" remote add origin "$origin"
git -C "$seed" push origin master
"$BIN" clone "$origin" "$down" >"$WORK/clone.out" 2>"$WORK/clone.err" || fail "review-signed clone failed: $(cat "$WORK/clone.err")"
grep -q "accepted" "$WORK/clone.err" || fail "review-signed clone was not accepted"
[[ -f "$down/file" ]] || fail "clone did not contain the reviewed tree"

# A personal signature is not the review key.
porigin="$WORK/personal.git"
pseed="$WORK/personal-seed"
pdown="$WORK/personal-down"
git init --bare -b master "$porigin"
git init -b master "$pseed"
configure_repo "$pseed" "$PERSONAL_HOME" "$PERSONAL_FPR"
echo only >> "$pseed/file"
git -C "$pseed" add file
GNUPGHOME="$PERSONAL_HOME" git -C "$pseed" commit -m "personal signature"
git -C "$pseed" remote add origin "$porigin"
git -C "$pseed" push origin master
set +e
"$BIN" clone "$porigin" "$pdown" >"$WORK/personal.out" 2>"$WORK/personal.err"
code=$?
set -e
[[ "$code" -eq 128 ]] || fail "personal signature clone exited $code"
grep -q "not verified" "$WORK/personal.err" || fail "personal signature was not refused"
[[ ! -e "$pdown" ]] || fail "personal signature clone left a destination"

# An unsigned commit after the reviewed tip is refused, and the saved tip stays.
before="$(git -C "$down" rev-parse refs/remotes/origin/master)"
git -C "$seed" config commit.gpgsign false
echo later >> "$seed/file"
git -C "$seed" add file
git -C "$seed" commit -m "unsigned after review"
git -C "$seed" push origin master
set +e
"$BIN" -C "$down" fetch >"$WORK/after.out" 2>"$WORK/after.err"
code=$?
set -e
[[ "$code" -eq 128 ]] || fail "unsigned commit after the tip exited $code"
grep -q "not verified" "$WORK/after.err" || fail "unsigned commit after the tip was not explained"
[[ "$(git -C "$down" rev-parse refs/remotes/origin/master)" == "$before" ]] || fail "unsigned update moved the remote-tracking ref"

# A new review signature on top of that unsigned commit is accepted, because
# the signature covers the commit it points at.
GNUPGHOME="$REVIEW_HOME" git -C "$seed" config commit.gpgsign true
GNUPGHOME="$REVIEW_HOME" git -C "$seed" commit --allow-empty -m "git-safe review again"
git -C "$seed" push origin master
"$BIN" -C "$down" fetch >"$WORK/again.out" 2>"$WORK/again.err" || fail "second review signature was refused: $(cat "$WORK/again.err")"
[[ "$(git -C "$down" rev-parse refs/remotes/origin/master)" == "$(git -C "$seed" rev-parse HEAD)" ]] || fail "second review signature did not fast-forward"

echo "review checks passed"

# Public-only file round trips must not overwrite files or silently grant trust.
expect_refusal() {
  if "$@" >"$WORK/refusal.out" 2>"$WORK/refusal.err"; then fail "unexpectedly accepted: $*"; fi
}
expect_refusal "$BIN" keys export --key "$REVIEW_FPR" --output "$WORK/review.asc"
expect_refusal "$BIN" keys import wrong "$WORK/review.asc" --yes --fingerprint "$PERSONAL_FPR"
expect_refusal "$BIN" keys import blind "$WORK/review.asc" --yes
expect_refusal "$BIN" keys import duplicate "$WORK/review.asc" --yes --fingerprint "$REVIEW_FPR"
GNUPGHOME="$PERSONAL_HOME" "$BIN" keys export --key "$PERSONAL_FPR" --output "$WORK/personal.asc"
expect_refusal "$BIN" keys import review "$WORK/personal.asc" --yes --fingerprint "$PERSONAL_FPR"
GNUPGHOME="$REVIEW_HOME" gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$REVIEW_FPR" > "$WORK/secret.asc"
expect_refusal "$BIN" keys import secret "$WORK/secret.asc" --yes --fingerprint "$REVIEW_FPR"
cat "$WORK/review.asc" "$WORK/personal.asc" > "$WORK/multiple.asc"
expect_refusal "$BIN" keys import multiple "$WORK/multiple.asc" --yes --fingerprint "$REVIEW_FPR"
expect_refusal env XDG_DATA_HOME="$WORK/empty-data" "$BIN" clone "$origin" "$WORK/empty-down"
[[ ! -e "$WORK/empty-down" ]] || fail "empty trust store accepted a clone"

# Explicit primary authorization also covers valid signing subkeys, but only
# after the public-key update has been received.
GNUPGHOME="$REVIEW_HOME" gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$REVIEW_FPR" ed25519 sign never
SUB_FPR="$(GNUPGHOME="$REVIEW_HOME" gpg --with-colons --list-keys "$REVIEW_FPR" | awk -F: '/^sub:/ {subkey=1; next} subkey && /^fpr:/ {print $10; exit}')"
git -C "$seed" config user.signingkey "$SUB_FPR!"
GNUPGHOME="$REVIEW_HOME" git -C "$seed" commit --allow-empty -m "signed with new subkey"
git -C "$seed" push origin master
expect_refusal "$BIN" -C "$down" fetch
GNUPGHOME="$REVIEW_HOME" "$BIN" keys export --key "$REVIEW_FPR" --output "$WORK/updated.asc"
"$BIN" keys import review "$WORK/updated.asc" --yes --fingerprint "$REVIEW_FPR"
"$BIN" -C "$down" fetch || fail "valid signing subkey was refused"

checkpoint="$WORK/checkpoint.git"
git init --bare -b master "$checkpoint"
git -C "$seed" push "$checkpoint" HEAD:refs/heads/master
"$BIN" clone "$checkpoint" "$WORK/checkpoint-before" || fail "checkpoint must be trusted before revocation"

# A repository-controlled GPG executable cannot manufacture authorization.
cat > "$WORK/fake-gpg" <<EOF2
#!/bin/sh
printf '[GNUPG:] VALIDSIG $REVIEW_FPR 2026-01-01 1 0 4 0 22 8 00 $REVIEW_FPR\n' >&2
exit 0
EOF2
chmod 755 "$WORK/fake-gpg"
git -C "$down" config gpg.program "$WORK/fake-gpg"
git -C "$down" config gpg.openpgp.program "$WORK/fake-gpg"
git -C "$seed" config commit.gpgsign false
git -C "$seed" commit --allow-empty -m "unsigned cannot spoof GPG"
git -C "$seed" push origin master
expect_refusal "$BIN" -C "$down" fetch

# Revocations survive importing an older export; removing a signer also revokes
# authorization immediately for future verification snapshots.
sed 's/^://' "$REVIEW_HOME/openpgp-revocs.d/$REVIEW_FPR.rev" > "$WORK/revoke.asc"
GNUPGHOME="$REVIEW_HOME" gpg --batch --import "$WORK/revoke.asc"
GNUPGHOME="$REVIEW_HOME" "$BIN" keys export --key "$REVIEW_FPR" --output "$WORK/revoked.asc"
"$BIN" keys import review "$WORK/revoked.asc" --yes --fingerprint "$REVIEW_FPR"
"$BIN" keys import review "$WORK/updated.asc" --yes --fingerprint "$REVIEW_FPR"
expect_refusal "$BIN" clone "$checkpoint" "$WORK/revoked-down"
"$BIN" keys remove review
[[ -z "$("$BIN" keys list)" ]] || fail "removed signer still listed"
expect_refusal "$BIN" clone "$checkpoint" "$WORK/removed-down"
echo "key management checks passed"
