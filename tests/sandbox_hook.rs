use std::process::Command;

#[test]
fn sandbox_mounts_before_landlock_and_checks_signatures() {
    let temp = tempfile::tempdir().unwrap();
    let script = r#"
set -euo pipefail
export HOME="$WORK/home" GNUPGHOME="$WORK/keys" XDG_DATA_HOME="$WORK/data"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_SAFE_ALLOW_UNVERIFIED
mkdir -m 700 "$HOME" "$GNUPGHOME"
if [[ -x /usr/lib/git-safe/git.real ]]; then
  REAL=/usr/lib/git-safe/git.real
else
  REAL=/usr/lib/git-core/git
fi
export GIT_SAFE_REAL_GIT="$REAL"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'Test <test@example.test>' ed25519 sign never
"$BIN" keys trust-own
"$REAL" init "$WORK/repo"
cd "$WORK/repo"
"$REAL" config user.name Test
"$REAL" config user.email test@example.test
"$REAL" config gpg.program /usr/bin/gpg
"$REAL" -c core.hooksPath=/dev/null commit --allow-empty -S -m signed
signed=$("$REAL" rev-parse HEAD)
ln -s "$BIN" "$WORK/reference-transaction"
printf '%040d %s refs/remotes/origin/master\n' 0 "$signed" | "$WORK/reference-transaction" prepared
"$REAL" -c core.hooksPath=/dev/null commit --allow-empty --no-gpg-sign -m unsigned
unsigned=$("$REAL" rev-parse HEAD)
if printf '%s %s refs/remotes/origin/master\n' "$signed" "$unsigned" | "$WORK/reference-transaction" prepared; then
  echo 'Unsigned update was accepted' >&2
  exit 1
fi
"#;
    let status = Command::new("bash")
        .args(["-c", script])
        .env("WORK", temp.path())
        .env("BIN", env!("CARGO_BIN_EXE_git-safe"))
        .status()
        .unwrap();
    assert!(status.success());
}
