use std::process::Command;

#[test]
fn port_scenarios() {
    let status = Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/scenarios.sh"))
        .env("GIT_SAFE_BIN", env!("CARGO_BIN_EXE_git-safe"))
        .status()
        .expect("run scenario script");
    assert!(status.success(), "scenario script failed");
}
