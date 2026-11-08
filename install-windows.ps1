# Install inside an existing Debian/Ubuntu WSL2 distribution, not Windows Git.
param([string]$Distribution = "Ubuntu")
$ErrorActionPreference = "Stop"
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL2 is required. Install it with 'wsl --install -d Ubuntu', restart if requested, and set up your Linux user."
}
$installer = Join-Path $PSScriptRoot "install-linux.sh"
if (-not (Test-Path -LiteralPath $installer)) {
    throw "Run this script from a complete git-safe checkout."
}
# A WSL2 kernel is required for Linux sandboxing. Never fall back to WSL1.
& wsl.exe -d $Distribution -- bash -c 'case "$(uname -r)" in *[Ww][Ss][Ll]2*) exit 0;; *) echo "WSL2 is required; convert this distribution with wsl --set-version DISTRO 2" >&2; exit 1;; esac'
if ($LASTEXITCODE -ne 0) { throw "Select an initialized WSL2 Debian/Ubuntu distribution with -Distribution. Install Rust/Cargo inside it first." }
$linuxPath = & wsl.exe -d $Distribution -- wslpath -a -u $installer
if ($LASTEXITCODE -ne 0) { throw "Could not translate the checkout path into WSL." }
Write-Host "Installing git-safe inside $Distribution. Windows Git is unchanged."
& wsl.exe -d $Distribution -- bash $linuxPath.Trim()
if ($LASTEXITCODE -ne 0) { throw "The Linux installer failed. Check the output above." }
Write-Host "Use git-safe from the $Distribution WSL terminal."
