use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::dispatch::{self, first_positionals, reject_partial};
use crate::real::{self, ZERO};
use crate::verify::{self, Verification};

struct Scratch {
    empty_hooks: Option<tempfile::TempDir>,
    sandbox: Option<tempfile::TempDir>,
}

impl Scratch {
    fn new() -> Self {
        Self {
            empty_hooks: None,
            sandbox: None,
        }
    }

    fn empty_hooks(&mut self) -> PathBuf {
        if self.empty_hooks.is_none() {
            self.empty_hooks = Some(tempfile::tempdir().unwrap_or_else(|err| {
                real::die(&format!("cannot create temporary directory: {err}"));
            }));
        }
        self.empty_hooks.as_ref().unwrap().path().to_path_buf()
    }

    fn sandbox(&mut self) -> PathBuf {
        if self.sandbox.is_none() {
            self.sandbox = Some(tempfile::tempdir().unwrap_or_else(|err| {
                real::die(&format!("cannot create temporary directory: {err}"));
            }));
        }
        self.sandbox.as_ref().unwrap().path().to_path_buf()
    }

    fn cleanup(&mut self) {
        self.sandbox.take();
        self.empty_hooks.take();
    }
}

pub fn fetch(action: &str, args: &[OsString]) {
    reject_partial(args);
    crate::sandbox::validate_options(args, false).unwrap_or_else(|err| real::die(&err.to_string()));
    if !in_repo() {
        real::die("not a git repository");
    }
    let mut verification = Verification::new();
    let git_dir = absolute_git_dir();
    let positionals = first_positionals(args);
    let urls = fetch_urls(args, &positionals);
    log_checking(action, &urls);

    let mut scratch = Scratch::new();
    let empty = scratch.empty_hooks();
    let sandbox = scratch.sandbox();
    let copy = sandbox.join("repo.git");
    copy_git_dir(&git_dir, &copy, &empty);
    let before = verify::for_each_ref(&git_dir, true);

    let mut fetch_args = vec![
        OsString::from("--git-dir"),
        copy.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(format!("core.hooksPath={}", empty.display())),
        OsString::from("-c"),
        OsString::from("maintenance.auto=false"),
        OsString::from("fetch"),
    ];
    if fetch_is_quiet(args) {
        fetch_args.push(OsString::from("--quiet"));
    }
    fetch_args.extend(args.iter().cloned());
    let sources = urls
        .iter()
        .map(|url| crate::sandbox::source(url))
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap_or_else(|err| real::die(&err.to_string()));
    let status = crate::sandbox::Policy::download(&sandbox, &sources)
        .git()
        .and_then(|mut command| command.args(&fetch_args).status())
        .unwrap_or_else(|err| real::die(&format!("cannot start download sandbox: {err}")));
    if !status.success() {
        scratch.cleanup();
        std::process::exit(status.code().unwrap_or(128));
    }

    if !verify_sandbox(&mut verification, &before, &copy, action) {
        scratch.cleanup();
        std::process::exit(128);
    }
    import_sandbox(&before, &copy, &git_dir);
    eprintln!("git-safe: accepted {} commits", verification.count);
}

pub fn clone(args: &[OsString]) {
    reject_partial(args);
    crate::sandbox::validate_options(args, true).unwrap_or_else(|err| real::die(&err.to_string()));
    let positionals = first_positionals(args);
    if positionals.is_empty() {
        real::die("missing clone repository");
    }
    let url = dispatch::lossy(&positionals[0]);
    let dest = if positionals.len() >= 2 {
        dispatch::lossy(&positionals[1])
    } else {
        clone_destination(&url)
    };
    log_checking("clone", std::slice::from_ref(&url));
    if Path::new(&dest).exists() {
        let empty = fs::read_dir(&dest)
            .map(|mut dir| dir.next().is_none())
            .unwrap_or(false);
        if !Path::new(&dest).is_dir() || !empty {
            real::die(&format!(
                "destination path '{dest}' already exists and is not an empty directory"
            ));
        }
    }

    let mut scratch = Scratch::new();
    let empty = scratch.empty_hooks();
    let sandbox = scratch.sandbox();
    let staging = sandbox.join("clone");
    let opts = clone_options(args);
    let (quiet, announce) = clone_verbosity(args);
    if announce && quiet {
        println!("Cloning into '{dest}'...");
    }
    let mut clone_args = vec![
        OsString::from("-c"),
        OsString::from(format!("core.hooksPath={}", empty.display())),
        OsString::from("-c"),
        OsString::from("maintenance.auto=false"),
        OsString::from("clone"),
    ];
    if quiet {
        clone_args.push(OsString::from("-q"));
    }
    clone_args.extend(opts);
    clone_args.extend(real::os_args(["--no-checkout", "--no-local"]));
    clone_args.push(OsString::from(&url));
    clone_args.push(staging.as_os_str().to_os_string());
    let sources =
        vec![crate::sandbox::source(&url).unwrap_or_else(|err| real::die(&err.to_string()))];
    let status = crate::sandbox::Policy::download(&sandbox, &sources)
        .git()
        .and_then(|mut command| command.args(&clone_args).status())
        .unwrap_or_else(|err| real::die(&format!("cannot start clone sandbox: {err}")));
    if !status.success() {
        scratch.cleanup();
        std::process::exit(status.code().unwrap_or(128));
    }

    let mut verification = Verification::new();
    let mut bad = false;
    for (oid, name) in verify::for_each_ref(&staging, false) {
        if !verification.verify_update(&staging, ZERO, &oid, &name, "clone") {
            bad = true;
        }
    }
    if bad {
        scratch.cleanup();
        std::process::exit(128);
    }
    if !args.iter().any(|arg| {
        matches!(
            arg.to_str(),
            Some("--bare" | "--mirror" | "--no-checkout" | "-n")
        )
    }) {
        // Materialize only verified trees, still without host hooks or filters.
        real::exit_unless(
            crate::sandbox::Policy::download(&sandbox, &[])
                .git()
                .and_then(|mut command| {
                    command
                        .args(["-C"])
                        .arg(&staging)
                        .args(["reset", "--hard", "HEAD"])
                        .status()
                })
                .unwrap_or_else(|err| real::die(&format!("cannot check out verified tree: {err}"))),
        );
    }
    move_clone(&staging, Path::new(&dest));
    eprintln!("git-safe: accepted {} commits", verification.count);
}

pub fn pull(args: &[OsString]) {
    let mut fetch_args = Vec::new();
    let mut merge_mode = "merge".to_string();
    let mut ff_flag: Option<OsString> = None;
    let mut autostash: Vec<OsString> = Vec::new();
    for arg in args {
        let text = dispatch::lossy(arg);
        match text.as_str() {
            "--rebase" | "-r" => merge_mode = "rebase".to_string(),
            "--no-rebase" => merge_mode = "merge".to_string(),
            "--ff-only" => ff_flag = Some(OsString::from("--ff-only")),
            "--ff" => ff_flag = None,
            "--no-ff" => ff_flag = Some(OsString::from("--no-ff")),
            "--autostash" => autostash = vec![OsString::from("--autostash")],
            "--no-autostash" => autostash = vec![OsString::from("--no-autostash")],
            _ if text.starts_with("--rebase=") => {
                merge_mode = match text.trim_start_matches("--rebase=") {
                    "false" => "merge".to_string(),
                    _ => "rebase".to_string(),
                };
            }
            _ => fetch_args.push(arg.clone()),
        }
    }
    if merge_mode == "merge" {
        if let Some(value) = config_get("pull.rebase") {
            if matches!(
                value.as_str(),
                "true" | "merges" | "interactive" | "preserve"
            ) {
                merge_mode = "rebase".to_string();
            }
        }
    }
    if ff_flag.is_none() && merge_mode == "merge" {
        let value = config_get("pull.ff").or_else(|| config_get("merge.ff"));
        if value.as_deref() == Some("only") {
            ff_flag = Some(OsString::from("--ff-only"));
        } else if value.as_deref() == Some("false") {
            ff_flag = Some(OsString::from("--no-ff"));
        }
    }
    fetch("pull", &fetch_args);
    if merge_mode == "rebase" {
        let mut rebase = vec![
            OsString::from("-c"),
            OsString::from("maintenance.auto=false"),
            OsString::from("rebase"),
        ];
        rebase.extend(autostash);
        rebase.push(OsString::from("FETCH_HEAD"));
        real::exit_unless(real::status(&rebase));
    } else {
        let mut merge = vec![
            OsString::from("-c"),
            OsString::from("maintenance.auto=false"),
            OsString::from("merge"),
        ];
        if let Some(flag) = ff_flag {
            merge.push(flag);
        }
        merge.push(OsString::from("FETCH_HEAD"));
        real::exit_unless(real::status(&merge));
    }
}

pub fn archive(args: &[OsString]) {
    let mut remote = None;
    let mut kept = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = dispatch::lossy(&args[index]);
        if arg == "--remote" {
            index += 1;
            if index >= args.len() {
                real::die("missing value after --remote");
            }
            remote = Some(dispatch::lossy(&args[index]));
        } else if let Some(value) = arg.strip_prefix("--remote=") {
            remote = Some(value.to_string());
        } else {
            kept.push(args[index].clone());
        }
        index += 1;
    }
    let Some(remote) = remote else {
        let mut full = vec![OsString::from("archive")];
        full.extend(args.iter().cloned());
        real::exec(&full);
    };
    log_checking("archive", std::slice::from_ref(&remote));
    let mut scratch = Scratch::new();
    let empty = scratch.empty_hooks();
    let sandbox = scratch.sandbox();
    let repo = sandbox.join("repo");
    let clone_args = real::os_args([
        "-c",
        &format!("core.hooksPath={}", empty.display()),
        "-c",
        "maintenance.auto=false",
        "clone",
        "--no-checkout",
        "--no-local",
        &remote,
    ]);
    let mut clone_args = clone_args;
    clone_args.push(repo.as_os_str().to_os_string());
    let sources =
        vec![crate::sandbox::source(&remote).unwrap_or_else(|err| real::die(&err.to_string()))];
    let status = crate::sandbox::Policy::download(&sandbox, &sources)
        .git()
        .and_then(|mut command| command.args(&clone_args).status())
        .unwrap_or_else(|err| real::die(&format!("cannot start archive sandbox: {err}")));
    if !status.success() {
        scratch.cleanup();
        std::process::exit(status.code().unwrap_or(128));
    }

    let mut verification = Verification::new();
    let mut bad = false;
    for (oid, name) in verify::for_each_ref(&repo, false) {
        if !verification.verify_update(&repo, ZERO, &oid, &name, "archive") {
            bad = true;
        }
    }
    if bad {
        scratch.cleanup();
        std::process::exit(128);
    }
    eprintln!("git-safe: accepted {} commits", verification.count);
    let mut archive_args = vec![
        OsString::from("-C"),
        repo.as_os_str().to_os_string(),
        OsString::from("archive"),
    ];
    archive_args.extend(kept);
    real::exit_unless(real::status(&archive_args));
}

pub fn maintenance(args: &[OsString]) {
    log_checking("maintenance", &[]);
    if in_repo() && real::success(&real::os_args(["remote"])) {
        fetch("maintenance", &[OsString::from("--all")]);
    }
    let mut command = vec![
        OsString::from("-c"),
        OsString::from("maintenance.prefetch.enable=false"),
        OsString::from("-c"),
        OsString::from("maintenance.auto=false"),
        OsString::from("maintenance"),
    ];
    command.extend(args.iter().cloned());
    real::exec(&command);
}

pub fn remote(args: &[OsString]) {
    if args.first().map(|arg| dispatch::lossy(arg)).as_deref() == Some("update") {
        let mut fetch_args = vec![OsString::from("--all")];
        fetch_args.extend(args.iter().skip(1).cloned());
        fetch("remote update", &fetch_args);
        return;
    }
    let mut command = vec![OsString::from("remote")];
    command.extend(args.iter().cloned());
    real::exec(&command);
}

pub fn lfs(_args: &[OsString]) {
    real::die("LFS is not supported by the sandbox policy; refusing to launch an external helper");
}

pub fn submodule_or_subtree(_kind: &str, _args: &[OsString]) {
    real::die("submodule and subtree commands are not supported by the sandbox policy");
}

fn fetch_urls(args: &[OsString], positionals: &[OsString]) -> Vec<String> {
    if args.iter().any(|arg| dispatch::lossy(arg) == "--all") {
        return real::stdout_lossy(&real::os_args(["remote"]))
            .unwrap_or_default()
            .lines()
            .filter(|name| !name.is_empty())
            .map(remote_url)
            .collect();
    }
    if let Some(name) = positionals.first() {
        return vec![remote_url(&dispatch::lossy(name))];
    }
    default_remote()
        .map(|name| vec![remote_url(&name)])
        .unwrap_or_default()
}

fn remote_url(name: &str) -> String {
    real::stdout_lossy(&real::os_args(["remote", "get-url", name]))
        .unwrap_or_else(|| name.to_string())
}

fn default_remote() -> Option<String> {
    if let Some(upstream) = real::stdout_lossy(&real::os_args([
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{u}",
    ])) {
        if let Some((remote, _)) = upstream.split_once('/') {
            if !remote.is_empty() {
                return Some(remote.to_string());
            }
        }
    }
    if let Some(head) = real::stdout_lossy(&real::os_args(["rev-parse", "--abbrev-ref", "HEAD"])) {
        if let Some(remote) = config_get(&format!("branch.{head}.remote")) {
            if !remote.is_empty() {
                return Some(remote);
            }
        }
    }
    if real::success(&real::os_args(["remote", "get-url", "origin"])) {
        return Some("origin".to_string());
    }
    None
}

fn config_get(key: &str) -> Option<String> {
    let value = real::stdout_lossy(&real::os_args(["config", "--get", key]))?;
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn in_repo() -> bool {
    real::success(&real::os_args(["rev-parse", "--is-inside-work-tree"]))
        || real::success(&real::os_args(["rev-parse", "--is-bare-repository"]))
}

fn absolute_git_dir() -> PathBuf {
    PathBuf::from(
        real::stdout_lossy(&real::os_args(["rev-parse", "--absolute-git-dir"]))
            .unwrap_or_else(|| real::die("not a git repository")),
    )
}

fn log_checking(action: &str, urls: &[String]) {
    if urls.is_empty() {
        eprintln!("git-safe: checking {action}");
    } else {
        eprintln!("git-safe: checking {action} from {}", urls.join(" "));
    }
}

fn copy_git_dir(src: &Path, dest: &Path, empty_hooks: &Path) {
    let init = real::os_args([
        "-c",
        &format!("core.hooksPath={}", empty_hooks.display()),
        "-c",
        "maintenance.auto=false",
        "init",
        "--bare",
        "-q",
    ]);
    let mut init = init;
    init.push(dest.as_os_str().to_os_string());
    real::exit_unless(real::status(&init));
    let _ = fs::remove_dir_all(dest.join("refs"));
    let _ = fs::remove_dir_all(dest.join("objects/pack"));
    let _ = fs::remove_dir_all(dest.join("objects/info"));
    fs::create_dir_all(dest.join("objects/info")).unwrap_or_else(|err| {
        real::die(&format!("cannot prepare quarantine: {err}"));
    });
    fs::create_dir_all(dest.join("refs")).unwrap_or_else(|err| {
        real::die(&format!("cannot prepare quarantine: {err}"));
    });
    if src.join("refs").is_dir() {
        copy_dir(&src.join("refs"), &dest.join("refs"));
    }
    copy_file_if_exists(&src.join("packed-refs"), &dest.join("packed-refs"));
    // Keep only routing and object-format configuration. Never inherit executable
    // helpers, includes, filters, fsmonitor, or URL rewrite rules.
    let configuration = real::output(&real::os_args([
        "--git-dir",
        &src.display().to_string(),
        "config",
        "--null",
        "--get-regexp",
        r"^(remote\..*\.(url|fetch|tagopt)|extensions\.objectformat|core\.repositoryformatversion)$",
    ]));
    if !configuration.status.success() && configuration.status.code() != Some(1) {
        real::die("cannot read remote configuration");
    }
    for entry in configuration
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = std::str::from_utf8(entry)
            .unwrap_or_else(|_| real::die("non-UTF8 remote configuration"));
        let (key, value) = entry
            .split_once('\n')
            .unwrap_or_else(|| real::die("invalid remote configuration"));
        if key.ends_with(".url") {
            crate::sandbox::source(value).unwrap_or_else(|err| real::die(&err.to_string()));
        }
        real::exit_unless(real::status(&real::os_args([
            "config",
            "--file",
            &dest.join("config").display().to_string(),
            "--add",
            key,
            value,
        ])));
    }
    copy_file_if_exists(&src.join("HEAD"), &dest.join("HEAD"));
    if src.join("objects/info/alternates").exists() {
        real::die("repositories with object alternates are not supported by the sandbox policy");
    }
    copy_dir(&src.join("objects"), &dest.join("objects"));
    real::exit_unless(real::status(&real::os_args([
        "--git-dir",
        &dest.display().to_string(),
        "config",
        "core.bare",
        "true",
    ])));
    let _ = real::status(&real::os_args([
        "--git-dir",
        &dest.display().to_string(),
        "config",
        "--unset",
        "core.worktree",
    ]));
}

fn copy_dir(src: &Path, dest: &Path) {
    let status = Command::new("cp")
        .arg("-a")
        .arg(format!("{}/.", src.display()))
        .arg(dest)
        .status()
        .unwrap_or_else(|err| real::die(&format!("cannot copy git directory: {err}")));
    real::exit_unless(status);
}

fn copy_file_if_exists(src: &Path, dest: &Path) {
    if src.is_file() {
        fs::copy(src, dest).unwrap_or_else(|err| {
            real::die(&format!("cannot copy {}: {err}", src.display()));
        });
    }
}

fn verify_sandbox(
    verification: &mut Verification,
    before: &[(String, String)],
    sandbox_git: &Path,
    action: &str,
) -> bool {
    let mut previous = verify::ref_map(before);
    let mut bad = false;
    for (new, name) in verify::for_each_ref(sandbox_git, true) {
        let old = previous.remove(&name).unwrap_or_else(|| ZERO.to_string());
        if old == new {
            continue;
        }
        if !verification.verify_update(sandbox_git, &old, &new, &name, action) {
            bad = true;
        }
    }
    !bad
}

fn import_sandbox(before: &[(String, String)], sandbox_git: &Path, real_git: &Path) {
    let mut previous = verify::ref_map(before);
    let mut spec = Vec::new();
    for (new, name) in verify::for_each_ref(sandbox_git, true) {
        let old = previous.remove(&name).unwrap_or_else(|| ZERO.to_string());
        if old != new && !real::is_zero_oid(&new) {
            spec.push(format!("{name}:{name}"));
        }
    }
    if !spec.is_empty() {
        let mut args = real::os_args([
            "--git-dir",
            &real_git.display().to_string(),
            "-c",
            "maintenance.auto=false",
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--quiet",
            "--no-tags",
        ]);
        args.push(sandbox_git.as_os_str().to_os_string());
        args.extend(spec.into_iter().map(OsString::from));
        real::exit_unless(real::status(&args));
    }
    for (name, old) in previous {
        let _ = real::status(&real::os_args([
            "--git-dir",
            &real_git.display().to_string(),
            "update-ref",
            "-d",
            &name,
            &old,
        ]));
    }
    let fetch_head = sandbox_git.join("FETCH_HEAD");
    if fetch_head.is_file() {
        let _ = fs::copy(&fetch_head, real_git.join("FETCH_HEAD"));
    }
}

fn fetch_is_quiet(args: &[OsString]) -> bool {
    for arg in args {
        if matches!(dispatch::lossy(arg).as_str(), "-v" | "--verbose") {
            return false;
        }
    }
    true
}

fn clone_verbosity(args: &[OsString]) -> (bool, bool) {
    let mut quiet = true;
    let mut announce = true;
    for arg in args {
        match dispatch::lossy(arg).as_str() {
            "-v" | "--verbose" => {
                quiet = false;
                break;
            }
            "-q" | "--quiet" => announce = false,
            _ => {}
        }
    }
    (quiet, announce)
}

fn clone_destination(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let base = base.strip_suffix(".git").unwrap_or(base);
    if base.is_empty() {
        real::die("missing clone destination");
    }
    base.to_string()
}

fn clone_options(args: &[OsString]) -> Vec<OsString> {
    let mut opts = Vec::new();
    let mut seen_url = false;
    let mut index = 0;
    while index < args.len() {
        let arg = dispatch::lossy(&args[index]);
        if arg == "--" {
            break;
        }
        if is_clone_valued(&arg) {
            if index + 1 >= args.len() {
                real::die(&format!("missing value after {arg}"));
            }
            opts.push(args[index].clone());
            opts.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if dispatch::is_partial(&arg) {
            real::die(&format!(
                "partial or shallow downloads are not allowed ({arg})"
            ));
        }
        if arg.starts_with('-') {
            opts.push(args[index].clone());
            index += 1;
            continue;
        }
        if !seen_url {
            seen_url = true;
        }
        index += 1;
    }
    opts
}

fn is_clone_valued(arg: &str) -> bool {
    matches!(
        arg,
        "-c" | "--config"
            | "--template"
            | "--reference"
            | "--reference-if-able"
            | "--separate-git-dir"
            | "--origin"
            | "-o"
            | "--branch"
            | "-b"
            | "--upload-pack"
            | "-u"
            | "--server-option"
            | "--jobs"
            | "-j"
            | "--bundle-uri"
    )
}

fn move_clone(staging: &Path, dest: &Path) {
    if dest.exists() {
        let entries = fs::read_dir(staging).unwrap_or_else(|err| {
            real::die(&format!("cannot read quarantine clone: {err}"));
        });
        for entry in entries {
            let entry = entry.unwrap_or_else(|err| {
                real::die(&format!("cannot read quarantine clone: {err}"));
            });
            let status = Command::new("mv")
                .arg(entry.path())
                .arg(dest)
                .status()
                .unwrap_or_else(|err| real::die(&format!("cannot move clone into place: {err}")));
            real::exit_unless(status);
        }
        let _ = fs::remove_dir_all(staging);
        return;
    }
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).unwrap_or_else(|err| {
                real::die(&format!("cannot create {}: {err}", parent.display()));
            });
        }
    }
    let status = Command::new("mv")
        .arg(staging)
        .arg(dest)
        .status()
        .unwrap_or_else(|err| real::die(&format!("cannot move clone into place: {err}")));
    real::exit_unless(status);
}
