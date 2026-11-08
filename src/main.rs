mod dispatch;
mod hook;
mod keys;
mod peer;
mod quarantine;
mod real;
mod sandbox;
mod verify;

use std::env;
use std::ffi::OsString;
use std::path::Path;

fn invocation_name() -> String {
    env::args_os()
        .next()
        .as_ref()
        .map(|arg0| {
            Path::new(arg0)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn main() {
    let name = invocation_name();
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    if name == "git-safe-sandbox" {
        sandbox::run_restricted(&args);
    }
    if name == "git-safe-gpg" {
        let mut command = std::process::Command::new("/usr/bin/gpg");
        command.args([
            "--no-options",
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
        ]);
        command.args(&args);
        use std::os::unix::process::CommandExt;
        real::die(&format!(
            "cannot execute verification GPG: {}",
            command.exec()
        ));
    }

    if let Some(command) = dispatch::dashed_command(&name) {
        let mut full = vec![OsString::from(command)];
        full.extend(args);
        dispatch::safe_main(full);
        return;
    }
    if hook::is_hook_name(&name) {
        hook::run(&name);
    }
    if name == "git" {
        dispatch::wrapper_main(args);
        return;
    }
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) {
        println!("git-safe: verify downloaded Git history against approved signers\n\n  git-safe keys help    Public-key export/import and trusted signers\n  git-safe peer help    Live key exchange over Tor\n  git-safe <git args>   Run Git with download verification");
        return;
    }
    dispatch::safe_main(args);
}
