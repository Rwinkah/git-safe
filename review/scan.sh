#!/bin/bash
# Scan one checkout. Exit non-zero on the first finding. Print the scanners
# that actually ran, one name per line, on stdout.
set -euo pipefail

root="${1:-.}"
cd "$root"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "git-safe review: $1 is not installed" >&2
    exit 1
  fi
}

run_scanner() {
  local name="$1"
  shift
  echo "git-safe review: running ${name}" >&2
  "$@" >&2
  printf '%s\n' "$name"
}

need gitleaks
run_scanner "gitleaks" gitleaks detect --source . --no-banner --redact --exit-code 1

if [[ -f Cargo.lock ]]; then
  need cargo-audit
  run_scanner "cargo audit" cargo audit
fi

if [[ -f package-lock.json ]]; then
  need npm
  run_scanner "npm audit --omit=dev" npm audit --omit=dev
fi

python_requirements=()
if [[ -f requirements.txt ]]; then
  python_requirements+=(requirements.txt)
fi
if [[ -f poetry.lock ]]; then
  need poetry
  exported="$(mktemp)"
  poetry export -f requirements.txt --without-hashes -o "$exported"
  python_requirements+=("$exported")
fi
if [[ -f Pipfile.lock ]]; then
  need pipenv
  exported="$(mktemp)"
  pipenv requirements > "$exported"
  python_requirements+=("$exported")
fi
if [[ -f pdm.lock ]]; then
  need pdm
  exported="$(mktemp)"
  pdm export -f requirements --without-hashes -o "$exported"
  python_requirements+=("$exported")
fi
if [[ ${#python_requirements[@]} -gt 0 ]]; then
  need pip-audit
  for req in "${python_requirements[@]}"; do
    run_scanner "pip-audit" pip-audit -r "$req"
  done
fi
