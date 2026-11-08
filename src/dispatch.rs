use std::env;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use crate::quarantine;
use crate::real;

const DASHED: &[&str] = &[
    "git-fetch",
    "git-clone",
    "git-pull",
    "git-fetch-pack",
    "git-http-fetch",
    "git-submodule",
    "git-subtree",
    "git-archive",
    "git-maintenance",
    "git-remote",
    "git-lfs",
];

const DOWNLOADS: &[&str] = &[
    "clone",
    "fetch",
    "pull",
    "fetch-pack",
    "http-fetch",
    "maintenance",
    "subtree",
    "submodule",
    "remote",
    "archive",
    "lfs",
];

pub fn dashed_command(argv0: &str) -> Option<&'static str> {
    DASHED
        .iter()
        .find(|name| **name == argv0)
        .map(|name| &name[4..])
}

pub fn wrapper_main(args: Vec<OsString>) {
    match wrapper_route(&args) {
        WrapperRoute::Real => real::exec(&args),
        WrapperRoute::Safe => safe_main(args),
    }
}

enum WrapperRoute {
    Real,
    Safe,
}

fn wrapper_route(args: &[OsString]) -> WrapperRoute {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        if matches!(
            arg.as_ref(),
            "--version" | "--help" | "-h" | "--html-path" | "--man-path" | "--info-path"
        ) {
            return WrapperRoute::Real;
        }
        if matches!(
            arg.as_ref(),
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--config-env"
        ) {
            index += 2;
            continue;
        }
        if arg.starts_with("-c")
            || arg.starts_with("-C")
            || arg.starts_with("--git-dir=")
            || arg.starts_with("--work-tree=")
            || arg.starts_with("--namespace=")
            || arg.starts_with("--super-prefix=")
            || arg.starts_with("--config-env=")
            || arg.starts_with("--exec-path=")
        {
            index += 1;
            continue;
        }
        if arg == "--exec-path" {
            index += 1;
            if index < args.len() && !args[index].to_string_lossy().starts_with('-') {
                index += 1;
            }
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        if DOWNLOADS.iter().any(|command| *command == arg.as_ref()) {
            return WrapperRoute::Safe;
        }
        return WrapperRoute::Real;
    }
    WrapperRoute::Real
}

pub fn safe_main(args: Vec<OsString>) {
    // Handle our own commands before Git's global-option/override processing.
    if let Some(command) = args.first().and_then(|arg| arg.to_str()) {
        let result = match command {
            "keys" => Some(crate::keys::run(&args[1..])),
            "peer" => Some(crate::peer::run(&args[1..])),
            _ => None,
        };
        if let Some(result) = result {
            if let Err(err) = result {
                real::die(&err.to_string());
            }
            return;
        }
    }
    let prepared = strip_override(&args);
    if prepared.override_on {
        // The hook reads this even when the download goes straight to real git.
        env::set_var("GIT_SAFE_ALLOW_UNVERIFIED", "1");
    }
    if prepared.args.is_empty() {
        real::exec(&prepared.args);
    }
    if !prepared.override_on {
        for arg in &prepared.args {
            let text = arg.to_string_lossy();
            if text == "-c"
                || text.starts_with("-c")
                || text.starts_with("--config-env")
                || text.starts_with("--exec-path")
            {
                real::die("Git configuration overrides are not accepted in protected mode");
            }
        }
    }
    let invocation = parse_invocation(&prepared.args);
    let Some(cmd) = invocation.cmd else {
        real::exec(&prepared.args);
    };
    if prepared.override_on {
        eprintln!("git-safe: override on, checks skipped for this {cmd}");
        real::exec(&prepared.args);
    }

    let cmd_args = invocation.cmd_args;
    match cmd.as_str() {
        "fetch" => quarantine::fetch("fetch", &cmd_args),
        "clone" => quarantine::clone(&cmd_args),
        "pull" => quarantine::pull(&cmd_args),
        "fetch-pack" | "http-fetch" => {
            eprintln!("git-safe: checking {cmd}");
            real::die(&format!(
                "refusing {cmd}; it downloads objects without a ref update that can be verified. Use git fetch"
            ));
        }
        "archive" => quarantine::archive(&cmd_args),
        "maintenance" => quarantine::maintenance(&cmd_args),
        "remote" => quarantine::remote(&cmd_args),
        "lfs" => quarantine::lfs(&cmd_args),
        "submodule" | "subtree" => quarantine::submodule_or_subtree(&cmd, &cmd_args),
        _ => real::exec(&prepared.args),
    }
}

struct Prepared {
    args: Vec<OsString>,
    override_on: bool,
}

fn strip_override(args: &[OsString]) -> Prepared {
    let mut override_on = env::var("GIT_SAFE_ALLOW_UNVERIFIED").ok().as_deref() == Some("1");
    let mut kept = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        if arg == "--allow-unverified" {
            override_on = true;
            index += 1;
            continue;
        }
        if arg == "-c" && index + 1 < args.len() {
            let value = args[index + 1].to_string_lossy();
            if let Some(setting) = value.strip_prefix("safe.allowUnverified=") {
                if truthy(setting) {
                    override_on = true;
                }
            }
            kept.push(args[index].clone());
            kept.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if let Some(setting) = arg
            .strip_prefix("-csafe.allowUnverified=")
            .or_else(|| arg.strip_prefix("safe.allowUnverified="))
        {
            if truthy(setting) {
                override_on = true;
            }
            kept.push(args[index].clone());
            index += 1;
            continue;
        }
        kept.push(args[index].clone());
        index += 1;
    }
    Prepared {
        args: kept,
        override_on,
    }
}

fn truthy(value: &str) -> bool {
    matches!(value, "true" | "yes" | "1" | "on")
}

struct Invocation {
    cmd: Option<String>,
    cmd_args: Vec<OsString>,
}

fn parse_invocation(args: &[OsString]) -> Invocation {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        if arg == "--" {
            index += 1;
            break;
        }
        if matches!(arg.as_ref(), "--version" | "-h" | "--help") {
            real::exec(args);
        }
        if let Some(path) = option_value(args, &mut index, &arg, "-C") {
            if env::set_current_dir(Path::new(&path)).is_err() {
                real::die(&format!("cannot enter {}", path.to_string_lossy()));
            }
            continue;
        }
        if let Some(path) = option_value(args, &mut index, &arg, "--git-dir") {
            env::set_var("GIT_DIR", &path);
            continue;
        }
        if let Some(path) = option_value(args, &mut index, &arg, "--work-tree") {
            env::set_var("GIT_WORK_TREE", &path);
            continue;
        }
        if option_value(args, &mut index, &arg, "--namespace").is_some()
            || option_value(args, &mut index, &arg, "--super-prefix").is_some()
            || option_value(args, &mut index, &arg, "--config-env").is_some()
            || option_value(args, &mut index, &arg, "-c").is_some()
        {
            continue;
        }
        if arg.starts_with("-c")
            || arg.starts_with("--git-dir=")
            || arg.starts_with("--work-tree=")
            || arg.starts_with("--namespace=")
            || arg.starts_with("--super-prefix=")
            || arg.starts_with("--config-env=")
            || is_flag(&arg)
        {
            if let Some(path) = arg.strip_prefix("--git-dir=") {
                env::set_var("GIT_DIR", path);
            } else if let Some(path) = arg.strip_prefix("--work-tree=") {
                env::set_var("GIT_WORK_TREE", path);
            }
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Invocation {
            cmd: Some(arg.into_owned()),
            cmd_args: args[index + 1..].to_vec(),
        };
    }
    Invocation {
        cmd: None,
        cmd_args: args.get(index..).unwrap_or_default().to_vec(),
    }
}

fn option_value(args: &[OsString], index: &mut usize, arg: &str, name: &str) -> Option<OsString> {
    if arg != name {
        return None;
    }
    *index += 1;
    if *index >= args.len() {
        real::die(&format!("missing value after {name}"));
    }
    let value = args[*index].clone();
    *index += 1;
    Some(value)
}

fn is_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--exec-path"
            | "--bare"
            | "--no-replace-objects"
            | "--literal-pathspecs"
            | "--glob-pathspecs"
            | "--noglob-pathspecs"
            | "--icase-pathspecs"
            | "--no-lazy-fetch"
            | "--no-optional-locks"
            | "--no-advice"
            | "--paginate"
            | "--no-pager"
            | "-p"
            | "-P"
    ) || arg.starts_with("--exec-path=")
}

pub fn reject_partial(args: &[OsString]) {
    for arg in args {
        let text = arg.to_string_lossy();
        if is_partial(&text) {
            real::die(&format!(
                "partial or shallow downloads are not allowed ({text})"
            ));
        }
    }
}

pub fn is_partial(arg: &str) -> bool {
    arg == "--unshallow"
        || arg == "--filter"
        || arg.starts_with("--filter=")
        || arg == "--depth"
        || arg.starts_with("--depth=")
        || arg == "--shallow-since"
        || arg.starts_with("--shallow-since=")
        || arg == "--shallow-exclude"
        || arg.starts_with("--shallow-exclude=")
}

pub fn first_positionals(args: &[OsString]) -> Vec<OsString> {
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        if arg == "--" {
            positionals.extend(args[index + 1..].iter().cloned());
            break;
        }
        if is_partial(&arg) {
            real::die(&format!(
                "partial or shallow downloads are not allowed ({arg})"
            ));
        }
        if takes_value(&arg) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        positionals.push(args[index].clone());
        index += 1;
    }
    positionals
}

fn takes_value(arg: &str) -> bool {
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
            | "--depth"
            | "--shallow-since"
            | "--shallow-exclude"
            | "--server-option"
            | "--jobs"
            | "-j"
            | "--bundle-uri"
            | "--reference-exclude"
            | "--recurse-submodules"
    )
}

pub fn lossy(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_flag_is_removed_and_recorded() {
        let prepared = strip_override(&[
            OsString::from("fetch"),
            OsString::from("--allow-unverified"),
            OsString::from("origin"),
        ]);
        assert!(prepared.override_on);
        assert_eq!(
            prepared
                .args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["fetch", "origin"]
        );
    }

    #[test]
    fn config_override_stays_on_the_command_line() {
        let prepared = strip_override(&[
            OsString::from("-c"),
            OsString::from("safe.allowUnverified=true"),
            OsString::from("fetch"),
        ]);
        assert!(prepared.override_on);
        assert_eq!(prepared.args.len(), 3);
    }

    #[test]
    fn shallow_flags_are_partial() {
        assert!(is_partial("--depth=1"));
        assert!(is_partial("--filter=blob:none"));
        assert!(is_partial("--unshallow"));
        assert!(!is_partial("--all"));
    }
}
