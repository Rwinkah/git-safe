use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};

pub const ZERO: &str = "0000000000000000000000000000000000000000";

pub fn die(msg: &str) -> ! {
    eprintln!("git-safe: {msg}");
    std::process::exit(128);
}

pub fn is_zero_oid(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|byte| byte == b'0')
}

pub fn real_git() -> PathBuf {
    if let Some(path) = env::var_os("GIT_SAFE_REAL_GIT") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return path;
        }
    }
    for candidate in [
        "/usr/lib/git-safe/git.real",
        "/usr/local/lib/git-safe/git.real",
        "/usr/lib/git-core/git",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    die("cannot find the real git binary");
}

pub fn command(args: &[OsString]) -> Command {
    let mut command = Command::new(real_git());
    command.args(args);
    command
}

pub fn output(args: &[OsString]) -> Output {
    match command(args).output() {
        Ok(output) => output,
        Err(err) => die(&format!("failed to run git: {err}")),
    }
}

pub fn status(args: &[OsString]) -> ExitStatus {
    match command(args).status() {
        Ok(status) => status,
        Err(err) => die(&format!("failed to run git: {err}")),
    }
}

pub fn exit_unless(status: ExitStatus) {
    if status.success() {
        return;
    }
    std::process::exit(status.code().unwrap_or(128));
}

pub fn success(args: &[OsString]) -> bool {
    output(args).status.success()
}

pub fn stdout_lossy(args: &[OsString]) -> Option<String> {
    let output = output(args);
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn exec(args: &[OsString]) -> ! {
    let err = command(args).exec();
    die(&format!("failed to run git: {err}"));
}

pub fn exec_program(program: &Path, args: &[OsString]) -> ! {
    let err = Command::new(program).args(args).exec();
    die(&format!("failed to run {}: {err}", program.display()));
}

pub fn os_args<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect()
}
