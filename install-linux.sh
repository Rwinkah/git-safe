#!/usr/bin/env bash
set -euo pipefail

# Run from a source checkout; build as the invoking user, install via apt.
if [[ "$(uname -s)" != Linux ]]; then
  echo "This installer requires Linux (Debian/Ubuntu)." >&2
  exit 1
fi
if ! command -v apt-get >/dev/null || ! command -v dpkg >/dev/null; then
  echo "This installer supports Debian/Ubuntu. Other distributions need manual packaging." >&2
  exit 1
fi
if [[ $EUID == 0 ]]; then
  echo "Run this script as your regular user, without sudo; it requests sudo when needed." >&2
  exit 1
fi
for tool in cargo rustc sudo; do
  if ! command -v "$tool" >/dev/null; then
    echo "Missing $tool. Install Rust/Cargo and sudo before running this installer." >&2
    exit 1
  fi
done
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_dir"
[[ -f Cargo.toml && -f Cargo.lock && -f debian/postinst ]] || {
  echo "Run this installer from a complete git-safe source checkout." >&2
  exit 1
}
echo "Installing git-safe will wrap system Git and set system-wide Git hooks."
sudo apt-get update
sudo apt-get install -y build-essential git gpg tor bubblewrap ca-certificates
if ! cargo deb --version >/dev/null 2>&1; then
  cargo install cargo-deb --locked
fi
# An explicit output path avoids installing stale packages from earlier builds.
package_dir="$(mktemp -d)"
trap 'rm -rf -- "$package_dir"' EXIT
cargo deb --locked --output "$package_dir/git-safe.deb"
chmod 755 "$package_dir"
chmod 644 "$package_dir/git-safe.deb"
sudo apt-get install -y "$package_dir/git-safe.deb"
git-safe --help
echo "Installed. Trust a signer with: git-safe keys import NAME PUBLIC_KEY_FILE"
