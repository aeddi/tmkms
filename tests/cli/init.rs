//! Integration tests for the `init` subcommand

use crate::cli;
use abscissa_core::Config;
use std::{ffi::OsStr, fs};
use tmkms::{commands::init::networks::Network, config::KmsConfig};

#[test]
fn test_command() {
    let parent_dir = tempfile::tempdir().unwrap();

    let output_dir = parent_dir.path().join("tmkms");
    assert!(!output_dir.exists());

    // Network names to test with
    let networks = Network::all()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let result = cli::run([
        OsStr::new("init"),
        OsStr::new("-n"),
        OsStr::new(&networks.join(",")),
        output_dir.as_os_str(),
    ]);

    assert!(result.status.success());

    // Ensure generated configuration file parses
    let kms_config_path = output_dir.join("tmkms.toml");
    let kms_config = KmsConfig::load_toml(fs::read_to_string(kms_config_path).unwrap()).unwrap();

    // Ensure all expected chain IDs are present
    assert_eq!(
        &kms_config
            .chain
            .iter()
            .map(|c| c.id.as_str().split('-').next().unwrap().to_owned())
            .collect::<Vec<_>>(),
        &networks
    )
}

/// Run `tmkms init` into the given directory, with any extra leading arguments
fn run_init(output_dir: &std::path::Path, extra_args: &[&str]) -> std::process::Output {
    let mut args = vec![OsStr::new("init")];
    args.extend(extra_args.iter().map(OsStr::new));
    args.push(output_dir.as_os_str());
    cli::run(args)
}

#[test]
fn test_rerun_does_not_clobber_existing_files() {
    let parent_dir = tempfile::tempdir().unwrap();
    let output_dir = parent_dir.path().join("tmkms");

    assert!(run_init(&output_dir, &[]).status.success());

    let identity_key_path = output_dir.join("secrets").join("kms-identity.key");
    let original_key = fs::read(&identity_key_path).unwrap();

    let result = run_init(&output_dir, &[]);

    assert!(
        !result.status.success(),
        "re-running init must not silently overwrite an existing KMS home"
    );
    assert_eq!(
        fs::read(&identity_key_path).unwrap(),
        original_key,
        "the existing identity key must be preserved"
    );
}

#[test]
fn test_rerun_with_force_regenerates_files() {
    let parent_dir = tempfile::tempdir().unwrap();
    let output_dir = parent_dir.path().join("tmkms");

    assert!(run_init(&output_dir, &[]).status.success());

    let identity_key_path = output_dir.join("secrets").join("kms-identity.key");
    let original_key = fs::read(&identity_key_path).unwrap();

    let result = run_init(&output_dir, &["-f"]);

    assert!(
        result.status.success(),
        "-f should be accepted and overwrite the existing KMS home"
    );
    assert_ne!(
        fs::read(&identity_key_path).unwrap(),
        original_key,
        "-f should regenerate the identity key"
    );
}
