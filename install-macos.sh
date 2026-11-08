#!/usr/bin/env bash
set -euo pipefail

# Do not install a binary that cannot provide protected downloads.
cat >&2 <<'MESSAGE'
Native macOS installation is not supported yet.
git-safe's macOS sandbox backend currently refuses protected operations;
installing a binary alone would not enable protection.

Use a Debian/Ubuntu Linux virtual machine with Rust/Cargo installed instead.
Copy this source checkout into the VM and run:
  bash install-linux.sh
Git protection and trusted keys stay inside that Linux VM.
MESSAGE
exit 1
