use std::process::Command;

#[test]
fn own_keys_exclude_public_only_keys_and_preserve_names() {
    let temp = tempfile::tempdir().unwrap();
    let script = r#"
set -euo pipefail
export HOME="$WORK/home" GNUPGHOME="$WORK/own" XDG_DATA_HOME="$WORK/data"
mkdir -m 700 "$HOME" "$GNUPGHOME" "$WORK/other"
"$BIN" keys trust-own
[[ -z "$("$BIN" keys list)" ]]
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'Own <own@example.test>' ed25519 sign never
own=$(gpg --with-colons --list-secret-keys | awk -F: '/^fpr:/ {print $10; exit}')
gpg --homedir "$WORK/other" --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'Other <other@example.test>' ed25519 sign never
gpg --homedir "$WORK/other" --export | gpg --batch --import
"$BIN" keys export --key "$own" --output "$WORK/own.asc"
"$BIN" keys import me "$WORK/own.asc" --fingerprint "$own" --yes
"$BIN" keys trust-own
"$BIN" keys trust-own
[[ "$("$BIN" keys list)" == "$(printf 'me\t%s' "$own")" ]]
# Fresh trust store exercises creation, not just refresh.
export XDG_DATA_HOME="$WORK/fresh"
"$BIN" keys trust-own
[[ "$("$BIN" keys list)" == "$(printf '%s\t%s' "$own" "$own")" ]]
"#;
    let status = Command::new("bash")
        .args(["-c", script])
        .env("WORK", temp.path())
        .env("BIN", env!("CARGO_BIN_EXE_git-safe"))
        .status()
        .unwrap();
    assert!(status.success());
}
