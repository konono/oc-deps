use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_oc-deps")
}

fn run_offline(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .env("KUBECONFIG", "/definitely/missing/kubeconfig")
        .output()
        .expect("run oc-deps")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("oc-deps-cli-ux-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("create temp directory");
    path
}

#[test]
fn help_and_version_are_offline() {
    for args in [&["--help"][..], &["--version"][..]] {
        let output = run_offline(args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(!output.stdout.is_empty());
        assert!(!output.stdout.contains(&0x1b));
        assert!(!output.stderr.contains(&0x1b));
    }
}

#[test]
fn completions_are_offline_for_every_documented_shell() {
    for shell in ["bash", "elvish", "fish", "power-shell", "zsh"] {
        let output = run_offline(&["completion", shell]);
        assert!(output.status.success(), "{shell}: {output:?}");
        assert!(output.stdout.len() > 100, "{shell} completion was empty");
        assert!(output.stderr.is_empty(), "{shell}: {output:?}");
        assert!(!output.stdout.contains(&0x1b));
    }
}

#[test]
fn redirected_offline_output_has_no_ansi() {
    let dir = temp_dir();
    let snapshot = dir.join("snapshot.json");
    fs::write(
        &snapshot,
        r#"{
  "schema_version": 3,
  "resources": {},
  "scan_warnings": [],
  "cluster_url": "offline",
  "taken_at": "2026-09-27T00:00:00Z",
  "namespaces": [],
  "scope": null
}"#,
    )
    .expect("write snapshot");

    let path = snapshot.to_string_lossy();
    let output = run_offline(&["snapshot", "diff", &path, &path]);
    assert!(output.status.success(), "{output:?}");
    assert!(!output.stdout.contains(&0x1b), "stdout contains ANSI");
    assert!(!output.stderr.contains(&0x1b), "stderr contains ANSI");

    fs::remove_dir_all(dir).expect("remove temp directory");
}
