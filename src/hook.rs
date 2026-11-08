use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crate::real;
use crate::verify::Verification;

const CHAIN_HOOKS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "post-index-change",
];

pub fn is_hook_name(name: &str) -> bool {
    name == "reference-transaction" || name == "chain-hook" || CHAIN_HOOKS.contains(&name)
}

pub fn run(name: &str) -> ! {
    if name == "reference-transaction" {
        reference_transaction();
    }
    chain(name);
}

fn reference_transaction() -> ! {
    let mut args = std::env::args_os().skip(1);
    let status = args.next().map(|arg| arg.to_string_lossy().into_owned());
    let mut input = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut input) {
        real::die(&format!("failed to read hook input: {err}"));
    }
    if status.as_deref() == Some("prepared") && !override_requested() {
        if let Some(repo) = git_dir() {
            if !input.is_empty() {
                let text = String::from_utf8_lossy(&input);
                let mut verification = Verification::new();
                for line in text.lines() {
                    let mut parts = line.split_whitespace();
                    let Some(old) = parts.next() else { continue };
                    let Some(new) = parts.next() else { continue };
                    let Some(refname) = parts.next() else {
                        continue;
                    };
                    if !refname.starts_with("refs/remotes/") {
                        continue;
                    }
                    if !verification.verify_update(Path::new(&repo), old, new, refname, "fetch") {
                        std::process::exit(1);
                    }
                }
            }
        }
    }
    if let Some(repo) = git_dir() {
        let local = Path::new(&repo).join("hooks").join("reference-transaction");
        if is_executable(&local) {
            chain_bytes(&local, &input);
        }
    }
    std::process::exit(0);
}

fn chain(name: &str) -> ! {
    if let Some(repo) = git_dir() {
        let local = Path::new(&repo).join("hooks").join(name);
        if is_executable(&local) {
            let args: Vec<_> = std::env::args_os().skip(1).collect();
            real::exec_program(&local, &args);
        }
    }
    std::process::exit(0);
}

fn chain_bytes(local: &Path, input: &[u8]) -> ! {
    let mut child = match Command::new(local)
        .args(std::env::args_os().skip(1))
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => real::die(&format!("failed to run {}: {err}", local.display())),
    };
    if let Some(mut pipe) = child.stdin.take() {
        if let Err(err) = pipe.write_all(input) {
            real::die(&format!("failed to write hook input: {err}"));
        }
    }
    let status = child.wait().unwrap_or_else(|err| {
        real::die(&format!("failed to wait for hook: {err}"));
    });
    std::process::exit(status.code().unwrap_or(1));
}

fn override_requested() -> bool {
    if env::var("GIT_SAFE_ALLOW_UNVERIFIED").ok().as_deref() == Some("1") {
        return true;
    }
    real::stdout_lossy(&real::os_args([
        "config",
        "--bool",
        "--get",
        "safe.allowUnverified",
    ]))
    .as_deref()
        == Some("true")
}

fn git_dir() -> Option<String> {
    real::stdout_lossy(&real::os_args(["rev-parse", "--absolute-git-dir"]))
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}
