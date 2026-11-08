use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use crate::real::{self, ZERO};

pub struct Verification {
    seen: HashSet<String>,
    pub count: u64,
    trust: Option<crate::keys::Snapshot>,
}

impl Verification {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            count: 0,
            trust: None,
        }
    }

    /// Returns false when the ref update must be refused. Reasons are already on stderr.
    pub fn verify_update(
        &mut self,
        repo: &Path,
        old: &str,
        new: &str,
        refname: &str,
        action: &str,
    ) -> bool {
        if real::is_zero_oid(new) || new == ZERO {
            return true;
        }
        let Some(new_commit) = rev_parse(repo, &format!("{new}^{{commit}}")) else {
            eprintln!("git-safe: refusing {action}: {refname} does not point at a commit");
            return false;
        };

        let range = if real::is_zero_oid(old) || old == ZERO {
            new_commit.clone()
        } else if let Some(old_commit) = rev_parse(repo, &format!("{old}^{{commit}}")) {
            if !is_ancestor(repo, &old_commit, &new_commit) {
                eprintln!("git-safe: refusing {action}: update of {refname} is not a fast-forward");
                return false;
            }
            format!("{old_commit}..{new_commit}")
        } else {
            new_commit.clone()
        };

        if self.trust.is_none() {
            self.trust =
                Some(crate::keys::Snapshot::load().unwrap_or_else(|err| {
                    real::die(&format!("cannot load trusted signers: {err}"))
                }));
        }
        let trust = self.trust.as_ref().unwrap();
        let commits = log_commits(repo, &range, trust);
        let covered = commits_covered_by_review(repo, &commits);
        let mut bad = false;
        for commit in commits {
            if !self.seen.insert(commit.sha.clone()) {
                continue;
            }
            self.count += 1;
            if covered.contains(&commit.sha) {
                continue;
            }
            eprintln!(
                "git-safe: refusing {action}: commit {} ({}) is not verified ({})",
                commit.sha,
                commit.subject,
                sig_label(&commit.signature)
            );
            bad = true;
        }
        !bad
    }
}

struct CommitStatus {
    sha: String,
    signature: String,
    subject: String,
}

fn git_in(repo: &Path, args: &[&str]) -> Command {
    let mut command = crate::sandbox::Policy::verification(repo, None)
        .git()
        .unwrap_or_else(|err| real::die(&format!("cannot create verification sandbox: {err}")));
    command.arg("-C").arg(repo);
    command.args(args);
    command
}

fn commits_covered_by_review(repo: &Path, commits: &[CommitStatus]) -> HashSet<String> {
    let mut covered = HashSet::new();
    for commit in commits {
        if commit.signature != "G" {
            continue;
        }
        covered.insert(commit.sha.clone());
        let output = match git_in(repo, &["rev-list", &commit.sha]).output() {
            Ok(output) => output,
            Err(err) => real::die(&format!("failed to read commit history: {err}")),
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            real::die(&format!("failed to read commit history: {}", stderr.trim()));
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if !line.is_empty() {
                covered.insert(line.to_string());
            }
        }
    }
    covered
}

fn rev_parse(repo: &Path, spec: &str) -> Option<String> {
    let output = git_in(repo, &["rev-parse", "--verify", spec])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn is_ancestor(repo: &Path, old: &str, new: &str) -> bool {
    git_in(repo, &["merge-base", "--is-ancestor", old, new])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn log_commits(repo: &Path, range: &str, trust: &crate::keys::Snapshot) -> Vec<CommitStatus> {
    let output = match git_in(repo, &["log", "--format=%H%x09%s", range]).output() {
        Ok(output) => output,
        Err(err) => real::die(&format!("failed to read commits: {err}")),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        real::die(&format!("failed to read commits: {}", stderr.trim()));
    }
    let mut commits = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let Some(sha) = parts.next() else { continue };
        if sha.is_empty() {
            continue;
        }
        commits.push(CommitStatus {
            sha: sha.to_string(),
            signature: signature_status(repo, sha, trust),
            subject: parts.next().unwrap_or("").to_string(),
        });
    }
    commits
}

// Never authorize based on GPG ownertrust, user IDs, or short key IDs. A valid
// signature must resolve to a primary fingerprint explicitly present in SQLite.
fn signature_status(repo: &Path, sha: &str, trust: &crate::keys::Snapshot) -> String {
    let wrapper = Path::new("/usr/bin/git-safe-gpg");
    let mut cmd = crate::sandbox::Policy::verification(repo, Some(trust.ring.home.path()))
        .git()
        .unwrap_or_else(|err| real::die(&format!("cannot create verification sandbox: {err}")));
    cmd.arg("-C").arg(repo);
    cmd.env("GNUPGHOME", trust.ring.home.path())
        .arg("-c")
        .arg("gpg.format=openpgp")
        .arg("-c")
        .arg(format!("gpg.program={}", wrapper.display()))
        .arg("-c")
        .arg(format!("gpg.openpgp.program={}", wrapper.display()))
        .arg("-c")
        .arg("gpg.minTrustLevel=undefined")
        .args(["verify-commit", "--raw", sha]);
    let output = cmd
        .output()
        .unwrap_or_else(|err| real::die(&format!("cannot verify signature: {err}")));
    let status = String::from_utf8_lossy(&output.stderr);
    verified_primary(output.status.success(), &status, &trust.fingerprints).to_string()
}

fn verified_primary(success: bool, status: &str, trusted: &HashSet<String>) -> &'static str {
    let mut valid = None;
    for line in status.lines() {
        let Some(record) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields: Vec<_> = record.split_whitespace().collect();
        match fields.first().copied().unwrap_or("") {
            "BADSIG" => return "B",
            "EXPSIG" | "SIGEXPIRED" => return "X",
            "EXPKEYSIG" | "KEYEXPIRED" => return "Y",
            "REVKEYSIG" | "KEYREVOKED" => return "R",
            "ERRSIG" | "FAILURE" | "NODATA" | "NO_PUBKEY" => return "E",
            "VALIDSIG" => {
                // VALIDSIG has nine required fields after the status word;
                // field ten, when present, is the primary key fingerprint.
                let fpr = fields
                    .get(10)
                    .or_else(|| fields.get(1))
                    .copied()
                    .unwrap_or("");
                if fields.len() >= 10 && crate::keys::fingerprint(fpr).is_ok() {
                    valid = Some(fpr.to_ascii_uppercase());
                }
            }
            _ => {}
        }
    }
    if success && valid.as_ref().is_some_and(|fpr| trusted.contains(fpr)) {
        "G"
    } else if valid.is_some() {
        "U"
    } else {
        "N"
    }
}

pub fn sig_label(status: &str) -> &'static str {
    match status {
        "G" => "trusted signature",
        "B" => "bad signature",
        "U" => "untrusted signature",
        "X" => "expired signature",
        "Y" => "expired key",
        "R" => "revoked key",
        "E" => "signature cannot be checked",
        "N" => "no signature",
        _ => "status unknown",
    }
}

pub fn for_each_ref(location: &Path, skip_symbolic: bool) -> Vec<(String, String)> {
    let location_text = location.display().to_string();
    let mut args = if location.join(".git").exists() {
        real::os_args(["-C", &location_text])
    } else {
        real::os_args(["--git-dir", &location_text])
    };
    args.push(OsString::from("for-each-ref"));
    args.push(OsString::from(
        "--format=%(objectname)%09%(symref)%09%(refname)",
    ));
    let output = crate::sandbox::Policy::verification(location, None)
        .git()
        .and_then(|mut command| command.args(&args).output())
        .unwrap_or_else(|err| real::die(&format!("cannot list refs in sandbox: {err}")));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        real::die(&format!("failed to list refs: {}", stderr.trim()));
    }
    let mut refs = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.splitn(3, '\t');
        let Some(oid) = parts.next() else { continue };
        let Some(symref) = parts.next() else { continue };
        let Some(name) = parts.next() else { continue };
        if skip_symbolic && !symref.is_empty() {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        refs.push((oid.to_string(), name.to_string()));
    }
    refs
}

pub fn ref_map(refs: &[(String, String)]) -> HashMap<String, String> {
    refs.iter()
        .map(|(oid, name)| (name.clone(), oid.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{sig_label, verified_primary};
    use std::collections::HashSet;

    #[test]
    fn primary_authorization_and_failure_statuses() {
        let primary = "A".repeat(40);
        let subkey = "B".repeat(40);
        let trusted = HashSet::from([primary.clone()]);
        let status = format!("[GNUPG:] VALIDSIG {subkey} 2026-01-01 1 0 4 0 22 8 00 {primary}\n");
        assert_eq!(verified_primary(true, &status, &trusted), "G");
        assert_eq!(verified_primary(true, &status, &HashSet::new()), "U");
        assert_ne!(verified_primary(false, &status, &trusted), "G");
        for record in ["EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG", "EXPSIG"] {
            assert_ne!(
                verified_primary(
                    true,
                    &format!("{status}[GNUPG:] {record} anything"),
                    &trusted
                ),
                "G"
            );
        }
    }

    #[test]
    fn labels_match_git_status_letters() {
        assert_eq!(sig_label("G"), "trusted signature");
        assert_eq!(sig_label("N"), "no signature");
        assert_eq!(sig_label("U"), "untrusted signature");
        assert_eq!(sig_label(""), "status unknown");
    }
}
