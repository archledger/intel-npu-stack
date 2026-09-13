// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use stack_core::Channel;
use stack_install::{InstallOptions, validate_request};
use stack_platform::PlatformFacts;
use stack_schema::{KernelVersion, PciId, Profile, ProfileStatus, QualificationRecord};

fn facts() -> PlatformFacts {
    PlatformFacts {
        os_id: "fedora".into(),
        os_version_id: "44".into(),
        arch: "x86_64".into(),
        kernel: KernelVersion {
            major: 7,
            minor: 1,
            patch: 13,
        },
        pci_ids: vec![PciId {
            vendor: "8086".into(),
            device: "643e".into(),
        }],
        intel_vpu_loaded: true,
        accel_node_present: true,
        effective_root: false,
        boot_time_epoch: 1_700_000_000,
    }
}

fn profile(status: ProfileStatus) -> Profile {
    let mut profile = Profile::parse_toml(include_str!("fixtures/profile.toml")).unwrap();
    // Synthetic admission evidence is never written to a production profile.
    profile.status = status;
    profile.qualification = (status == ProfileStatus::Qualified).then(|| QualificationRecord {
        evidence_id: "synthetic-policy-test".into(),
        evidence_sha256: "a".repeat(64),
        qualified_at: "2026-09-11T00:00:00Z".into(),
        hardware_class: "synthetic-lunar-lake".into(),
        test_suite_version: "fixture-1".into(),
    });
    profile
}

fn options(args: &[&str]) -> InstallOptions {
    InstallOptions::try_parse_from(
        std::iter::once("intel-npu-stack-install").chain(args.iter().copied()),
    )
    .unwrap()
}

#[test]
fn defaults_are_stable_and_non_mutating_until_confirmed() {
    let options = options(&[]);
    assert_eq!(options.channel, Channel::Stable);
    assert!(!options.yes && !options.accept_experimental_risk);
    assert!(!options.dry_run && !options.with_python && !options.with_devel);
    assert_eq!(
        validate_request(&options, &facts(), &[profile(ProfileStatus::Qualified)]).unwrap(),
        0
    );
}

#[test]
fn all_published_transaction_flags_parse() {
    let options = options(&[
        "--dry-run",
        "--yes",
        "--channel",
        "experimental",
        "--accept-experimental-risk",
        "--with-python",
        "--with-devel",
    ]);
    assert!(options.dry_run && options.yes && options.accept_experimental_risk);
    assert!(options.with_python && options.with_devel);
    assert_eq!(options.channel, Channel::Experimental);
}

#[test]
fn help_and_version_exit_without_platform_or_transport_work() {
    for flag in ["--help", "--version"] {
        let error = InstallOptions::try_parse_from(["intel-npu-stack-install", flag]).unwrap_err();
        assert_eq!(error.exit_code(), 0);
        assert!(!error.use_stderr());
    }
}

#[test]
fn unknown_flags_channels_and_operands_are_misuse() {
    for args in [
        vec!["--force"],
        vec!["--profile", "custom"],
        vec!["--root", "/tmp"],
        vec!["--channel", "candidate"],
        vec!["--channel", ""],
        vec!["install"],
        vec!["--yes=true"],
        vec!["--channel"],
    ] {
        let error =
            InstallOptions::try_parse_from(std::iter::once("intel-npu-stack-install").chain(args))
                .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}

#[test]
fn effective_root_is_rejected_even_for_dry_run_and_yes() {
    let mut platform = facts();
    platform.effective_root = true;
    for args in [vec![], vec!["--dry-run"], vec!["--yes"]] {
        let error = validate_request(
            &options(&args),
            &platform,
            &[profile(ProfileStatus::Qualified)],
        )
        .unwrap_err();
        assert_eq!(error.exit_code, 2);
        assert_eq!(error.code, "INSTALL_ROOT_REFUSED");
    }
}

#[test]
fn yes_is_not_experimental_risk_acknowledgement() {
    for args in [
        vec!["--channel", "experimental"],
        vec!["--channel", "experimental", "--yes"],
    ] {
        assert_eq!(
            validate_request(
                &options(&args),
                &facts(),
                &[profile(ProfileStatus::Experimental)]
            )
            .unwrap_err()
            .exit_code,
            2
        );
    }
    assert_eq!(
        validate_request(
            &options(&["--accept-experimental-risk"]),
            &facts(),
            &[profile(ProfileStatus::Qualified)]
        )
        .unwrap_err()
        .exit_code,
        2
    );
}

#[test]
fn candidates_are_refused_by_both_channels() {
    let candidate = profile(ProfileStatus::Candidate);
    for args in [
        vec![],
        vec!["--channel", "experimental", "--accept-experimental-risk"],
    ] {
        assert_eq!(
            validate_request(&options(&args), &facts(), std::slice::from_ref(&candidate))
                .unwrap_err()
                .exit_code,
            10
        );
    }
}

#[test]
fn experimental_profile_requires_the_explicit_experimental_policy() {
    let profiles = [profile(ProfileStatus::Experimental)];
    assert_eq!(
        validate_request(&options(&[]), &facts(), &profiles)
            .unwrap_err()
            .exit_code,
        10
    );
    assert_eq!(
        validate_request(
            &options(&["--channel", "experimental", "--accept-experimental-risk"]),
            &facts(),
            &profiles
        )
        .unwrap(),
        0
    );
}

#[test]
fn exact_platform_hardware_kernel_and_module_are_required() {
    for field in [
        "id", "release", "arch", "pci", "minimum", "maximum", "module",
    ] {
        let mut platform = facts();
        match field {
            "id" => platform.os_id = "derivative".into(),
            "release" => platform.os_version_id = "43".into(),
            "arch" => platform.arch = "aarch64".into(),
            "pci" => platform.pci_ids[0].device = "abcd".into(),
            "minimum" => platform.kernel.patch = 12,
            "maximum" => platform.kernel.patch = 14,
            "module" => platform.intel_vpu_loaded = false,
            _ => unreachable!(),
        }
        assert_eq!(
            validate_request(
                &options(&[]),
                &platform,
                &[profile(ProfileStatus::Qualified)]
            )
            .unwrap_err()
            .exit_code,
            10,
            "{field}"
        );
    }
}

#[test]
fn zero_or_multiple_matches_are_refused() {
    assert_eq!(
        validate_request(&options(&[]), &facts(), &[])
            .unwrap_err()
            .exit_code,
        10
    );
    let mut second = profile(ProfileStatus::Qualified);
    second.id = "other-qualified-profile".into();
    assert_eq!(
        validate_request(
            &options(&[]),
            &facts(),
            &[profile(ProfileStatus::Qualified), second]
        )
        .unwrap_err()
        .exit_code,
        10
    );
}

#[test]
fn index_identifies_the_actual_selected_profile() {
    let mut unsupported = profile(ProfileStatus::Qualified);
    unsupported.hardware[0].device = "abcd".into();
    let profiles = [unsupported, profile(ProfileStatus::Qualified)];
    assert_eq!(
        validate_request(&options(&[]), &facts(), &profiles).unwrap(),
        1
    );
}

#[test]
fn invalid_qualification_metadata_is_not_admitted() {
    let mut invalid = profile(ProfileStatus::Qualified);
    invalid.qualification = None;
    assert_eq!(
        validate_request(&options(&[]), &facts(), &[invalid])
            .unwrap_err()
            .exit_code,
        20
    );
}
