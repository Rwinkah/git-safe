//! Process sandbox policy. Never silently fall back to an ordinary Command.
use std::ffi::OsString;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::PermissionDenied, message.into())
}

/// HTTPS is the only network transport. Local repositories are explicitly exposed
/// read-only; neither remote helpers nor SSH agents are inherited.
pub fn source(url: &str) -> io::Result<Option<PathBuf>> {
    if let Some(authority) = url.strip_prefix("https://") {
        let authority = authority.split('/').next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') || authority.starts_with('-') {
            return Err(invalid(
                "HTTPS URLs must have a host and must not embed credentials",
            ));
        }
        return Ok(None);
    }
    let path = url.strip_prefix("file://").unwrap_or(url);
    if url.contains("::") || path.contains(':') || path.starts_with('-') {
        return Err(invalid(
            "sandbox downloads support only HTTPS and local repository paths",
        ));
    }
    let path = Path::new(path).canonicalize()?;
    let git_dir = if path.join(".git").is_dir() {
        path.join(".git")
    } else {
        path.clone()
    };
    if !git_dir.join("objects").is_dir() || git_dir.join("objects/info/alternates").exists() {
        return Err(invalid(
            "local source must be a repository without external object alternates",
        ));
    }
    Ok(Some(path))
}

/// Keep an intentionally small command-line surface: options that introduce
/// executables, config, extra downloads, or host paths must not pass through.
pub fn validate_options(args: &[OsString], clone: bool) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index]
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 Git arguments"))?;
        if arg == "--" {
            break;
        }
        if !arg.starts_with('-') {
            index += 1;
            continue;
        }
        let plain = matches!(
            arg,
            "-q" | "--quiet" | "-v" | "--verbose" | "--progress" | "--no-progress"
        ) || if clone {
            matches!(
                arg,
                "--bare"
                    | "--mirror"
                    | "-n"
                    | "--no-checkout"
                    | "--single-branch"
                    | "--no-single-branch"
                    | "--no-tags"
                    | "--no-local"
                    | "--no-hardlinks"
            )
        } else {
            matches!(
                arg,
                "--all"
                    | "--tags"
                    | "--no-tags"
                    | "--prune"
                    | "--prune-tags"
                    | "-p"
                    | "--force"
                    | "-f"
                    | "--atomic"
                    | "--dry-run"
                    | "--no-recurse-submodules"
            )
        };
        if plain {
            index += 1;
            continue;
        }
        if clone && matches!(arg, "-b" | "--branch" | "-o" | "--origin") {
            if args.get(index + 1).is_none() {
                return Err(invalid("missing clone option value"));
            }
            index += 2;
            continue;
        }
        if clone && (arg.starts_with("--branch=") || arg.starts_with("--origin=")) {
            index += 1;
            continue;
        }
        return Err(invalid(format!(
            "option is not supported by the sandbox policy: {arg}"
        )));
    }
    Ok(())
}

pub struct Policy {
    repository: PathBuf,
    writable: bool,
    sources: Vec<PathBuf>,
    network: bool,
    keyring: Option<PathBuf>,
}
impl Policy {
    pub fn download(directory: &Path, sources: &[Option<PathBuf>]) -> Self {
        Self {
            repository: directory.to_path_buf(),
            writable: true,
            sources: sources.iter().flatten().cloned().collect(),
            network: sources.iter().any(Option::is_none),
            keyring: None,
        }
    }
    pub fn verification(repository: &Path, keyring: Option<&Path>) -> Self {
        Self {
            repository: repository.to_path_buf(),
            writable: false,
            sources: Vec::new(),
            network: false,
            keyring: keyring.map(Path::to_path_buf),
        }
    }
    pub fn git(&self) -> io::Result<Command> {
        let mut command = self.platform_command()?;
        command.env_clear();
        command.current_dir("/");
        // Overrides appear after repository config and do not rely on user config.
        for setting in [
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "maintenance.auto=false",
            "gc.auto=0",
            "credential.helper=",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "protocol.file.allow=always",
            "http.followRedirects=false",
            "fetch.recurseSubmodules=false",
            "submodule.recurse=false",
            "core.pager=cat",
            "core.askPass=",
            "core.attributesFile=/dev/null",
        ] {
            command.args(["-c", setting]);
        }
        Ok(command)
    }
}

#[derive(Clone)]
struct Runtime {
    files: Vec<(PathBuf, PathBuf)>,
    executables: Vec<PathBuf>,
}
fn runtime() -> io::Result<Runtime> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| build_runtime().map_err(|e| e.to_string()))
        .clone()
        .map_err(invalid)
}
fn build_runtime() -> io::Result<Runtime> {
    let git = crate::real::real_git().canonicalize()?;
    let self_exe = std::env::current_exe()?.canonicalize()?;
    let mut runtime = Runtime {
        files: Vec::new(),
        executables: Vec::new(),
    };
    for (from, to) in [
        (git.clone(), PathBuf::from("/usr/bin/git")),
        (git, PathBuf::from("/runtime/git-core/git-upload-pack")),
        (PathBuf::from("/usr/bin/gpg"), PathBuf::from("/usr/bin/gpg")),
        (self_exe, PathBuf::from("/usr/bin/git-safe-gpg")),
    ] {
        add_executable(&mut runtime, &from, &to)?;
    }
    let helper = [
        "/usr/lib/git-core/git-remote-https",
        "/usr/libexec/git-core/git-remote-https",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
    .ok_or_else(|| invalid("cannot locate the trusted Git HTTPS helper"))?;
    add_executable(
        &mut runtime,
        &helper,
        Path::new("/runtime/git-core/git-remote-https"),
    )?;
    Ok(runtime)
}
fn add_executable(runtime: &mut Runtime, source: &Path, target: &Path) -> io::Result<()> {
    let source = source.canonicalize()?;
    runtime.executables.push(source.clone());
    runtime.files.push((source.clone(), target.to_path_buf()));
    #[cfg(target_os = "linux")]
    {
        // Only distribution executables are inspected, never downloaded binaries.
        let output = Command::new("/usr/bin/ldd")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg(&source)
            .output()?;
        if !output.status.success() {
            return Err(invalid("could not resolve sandbox runtime libraries"));
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = line.split_whitespace().find(|field| field.starts_with('/'));
            if let Some(path) = path {
                let path = PathBuf::from(path);
                runtime.files.push((path.canonicalize()?, path.clone()));
                // ELF interpreters need execute permission; ordinary libraries do not.
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("ld-"))
                {
                    runtime.executables.push(path.canonicalize()?);
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl Policy {
    fn platform_command(&self) -> io::Result<Command> {
        use std::os::unix::process::CommandExt;
        let runtime = runtime()?;
        let bwrap = PathBuf::from("/usr/bin/bwrap");
        if !bwrap.is_file() {
            return Err(invalid("Bubblewrap is required for protected downloads"));
        }
        let mut command = Command::new(&bwrap);
        command.args([
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--new-session",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home/sandbox",
        ]);
        if !self.network {
            command.arg("--unshare-net");
        }
        let mut files = runtime.files;
        files.sort();
        files.dedup();
        for (source, target) in files {
            command.arg("--ro-bind").arg(source).arg(target);
        }
        for path in [
            "/etc/ssl/certs",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/gai.conf",
        ] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        let repository = self.repository.canonicalize()?;
        command
            .arg(if self.writable { "--bind" } else { "--ro-bind" })
            .arg(&repository)
            .arg(&repository);
        for source in &self.sources {
            command.arg("--ro-bind").arg(source).arg(source);
        }
        if let Some(keyring) = &self.keyring {
            let keyring = keyring.canonicalize()?;
            command.arg("--bind").arg(&keyring).arg(&keyring);
            command.arg("--setenv").arg("GNUPGHOME").arg(&keyring);
        }
        for (name, value) in clean_environment() {
            command.args(["--setenv", name, value]);
        }
        command.args(["--chdir", "/", "--", "/usr/bin/git"]);
        let mut executable_paths = runtime.executables;
        executable_paths.push(bwrap);
        // Run before exec: failure to install limits or execution policy aborts spawn.
        unsafe {
            command.pre_exec(move || {
                limits()?;
                restrict_execution(&executable_paths)
            });
        }
        Ok(command)
    }
}
fn clean_environment() -> [(&'static str, &'static str); 12] {
    [
        ("PATH", "/usr/bin:/runtime/git-core"),
        ("HOME", "/home/sandbox"),
        ("LC_ALL", "C"),
        ("GIT_EXEC_PATH", "/runtime/git-core"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("TMPDIR", "/tmp"),
    ]
}

#[cfg(unix)]
fn limits() -> io::Result<()> {
    for (resource, value) in [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_CPU, 120),
        (libc::RLIMIT_FSIZE, 1024 * 1024 * 1024),
        (libc::RLIMIT_NOFILE, 256),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

/// Landlock restricts exec by inode, including descendants and writable mounts.
/// Require ABI v1 rather than silently relying only on PATH filtering.
#[cfg(target_os = "linux")]
fn restrict_execution(paths: &[PathBuf]) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct Rule {
        allowed_access: u64,
        parent_fd: i32,
    }
    let attrs = Ruleset {
        handled_access_fs: 1,
    }; // LANDLOCK_ACCESS_FS_EXECUTE
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attrs,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if fd < 0 {
        return Err(invalid(format!(
            "Landlock execution restrictions are required: {}",
            Error::last_os_error()
        )));
    }
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    for path in paths {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)?;
        let rule = Rule {
            allowed_access: 1,
            parent_fd: file.as_raw_fd(),
        };
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1,
                &rule,
                0,
            )
        } < 0
        {
            return Err(Error::last_os_error());
        }
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::last_os_error());
    }
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } < 0 {
        return Err(Error::last_os_error());
    }
    // Do not leak caller-owned descriptors into the sandbox.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
impl Policy {
    fn platform_command(&self) -> io::Result<Command> {
        // A native backend must be validated on macOS before it may protect data.
        Err(invalid(
            "native macOS sandbox backend is not yet implemented; refusing protected operation",
        ))
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Policy {
    fn platform_command(&self) -> io::Result<Command> {
        Err(invalid(
            "no validated native sandbox backend for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_execution_and_escape_options() {
        for option in [
            "--upload-pack=sh",
            "--config=core.hooksPath=/tmp",
            "--template=/tmp",
            "--recurse-submodules",
            "--separate-git-dir=/tmp",
            "--bundle-uri=https://example.com/a",
        ] {
            assert!(
                validate_options(&[option.into()], true).is_err(),
                "{option}"
            );
        }
        assert!(validate_options(
            &["--branch".into(), "main".into(), "--no-tags".into()],
            true
        )
        .is_ok());
    }
    #[test]
    fn reject_arbitrary_transports_and_credentials() {
        for url in [
            "ext::sh -c evil",
            "ssh://example.com/a",
            "user@example.com:repo",
            "https://user:secret@example.com/a",
            "https:///repo",
        ] {
            assert!(source(url).is_err(), "{url}");
        }
        assert!(source("https://example.com/repo.git").unwrap().is_none());
    }
    #[test]
    fn verification_is_offline_and_read_only() {
        let temp = tempfile::tempdir().unwrap();
        let policy = Policy::verification(temp.path(), None);
        assert!(!policy.network && !policy.writable);
        #[cfg(target_os = "linux")]
        {
            let command = policy.git().unwrap();
            let args: Vec<_> = command
                .get_args()
                .map(|v| v.to_string_lossy().into_owned())
                .collect();
            assert!(args.contains(&"--unshare-net".to_string()));
            assert!(!args.contains(&"--bind".to_string()));
            assert!(command.get_envs().all(|(_, value)| value.is_none()));
        }
    }
}
