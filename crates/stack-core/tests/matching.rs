// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use stack_core::{Channel, SelectionError, SelectionPolicy, select_profile};
use stack_platform::PlatformFacts;
use stack_schema::{
    ActivationRequirement, ComponentRequirement, InstalledFile, KernelRange, KernelVersion,
    LicenseRecord, NativeProvider, PackageManager, PciId, PlatformSelector, Profile, ProfileStatus,
    QualificationRecord, RedistributionVerdict,
};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn components() -> BTreeMap<String, ComponentRequirement> {
    [
        "npu_firmware",
        "level_zero_loader",
        "npu_userspace_driver",
        "npu_compiler",
        "openvino_runtime",
        "openvino_npu_plugin",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            ComponentRequirement {
                version: "1.0.0".to_owned(),
                source: format!("https://example.invalid/{name}"),
                sha256: HASH.to_owned(),
                provider: NativeProvider {
                    package: format!("fixture-{name}"),
                    version: "0:1.0.0-1.fc44".to_owned(),
                    activation: ActivationRequirement::Immediate,
                    files: vec![InstalledFile {
                        path: format!("/usr/lib64/{name}.fixture.so"),
                        sha256: HASH.to_owned(),
                    }],
                },
                license: LicenseRecord {
                    expression: "Apache-2.0".to_owned(),
                    redistribution: RedistributionVerdict::Allowed,
                    evidence_sha256: HASH.to_owned(),
                },
            },
        )
    })
    .collect()
}

fn profile(id: &str, status: ProfileStatus) -> Profile {
    Profile {
        schema_version: 1,
        id: id.to_owned(),
        stack_release: "0.1.0".to_owned(),
        status,
        package_manager: PackageManager::Rpm,
        conflicts: Vec::new(),
        platform: PlatformSelector {
            id: "testos".to_owned(),
            version_id: "1".to_owned(),
            arch: "x86_64".to_owned(),
        },
        hardware: vec![PciId {
            vendor: "8086".to_owned(),
            device: "abcd".to_owned(),
        }],
        kernel: KernelRange {
            min: "6.10.0".to_owned(),
            max_exclusive: "6.20.0".to_owned(),
            module: "intel_vpu".to_owned(),
        },
        components: components(),
        qualification: (status == ProfileStatus::Qualified).then(|| QualificationRecord {
            evidence_id: "fixture-evidence-001".to_owned(),
            evidence_sha256: HASH.to_owned(),
            qualified_at: "2026-09-03T19:00:00Z".to_owned(),
            hardware_class: "fixture-lunar-lake-class".to_owned(),
            test_suite_version: "fixture-suite-v1".to_owned(),
        }),
    }
}

fn facts() -> PlatformFacts {
    PlatformFacts {
        os_id: "testos".to_owned(),
        os_version_id: "1".to_owned(),
        arch: "x86_64".to_owned(),
        kernel: KernelVersion {
            major: 6,
            minor: 17,
            patch: 3,
        },
        pci_ids: vec![PciId {
            vendor: "8086".to_owned(),
            device: "abcd".to_owned(),
        }],
        intel_vpu_loaded: true,
        accel_node_present: true,
        effective_root: false,
        boot_time_epoch: 1_700_000_000,
    }
}

fn stable() -> SelectionPolicy {
    SelectionPolicy {
        channel: Channel::Stable,
        acknowledge_risk: false,
    }
}

#[test]
fn stable_selects_one_exact_qualified_profile() {
    let profiles = vec![profile("qualified", ProfileStatus::Qualified)];
    let selected = select_profile(&profiles, &facts(), &stable()).expect("profile must match");
    assert_eq!(selected.id, "qualified");
}

#[test]
fn stable_rejects_candidate_profile() {
    let profiles = vec![profile("candidate", ProfileStatus::Candidate)];
    assert_eq!(
        select_profile(&profiles, &facts(), &stable()),
        Err(SelectionError::NoCompatibleProfile)
    );
}

#[test]
fn stable_rejects_experimental_profile() {
    let profiles = vec![profile("experimental", ProfileStatus::Experimental)];
    assert_eq!(
        select_profile(&profiles, &facts(), &stable()),
        Err(SelectionError::NoCompatibleProfile)
    );
}

#[test]
fn experimental_requires_risk_acknowledgement() {
    let profiles = vec![profile("experimental", ProfileStatus::Experimental)];
    let policy = SelectionPolicy {
        channel: Channel::Experimental,
        acknowledge_risk: false,
    };
    assert_eq!(
        select_profile(&profiles, &facts(), &policy),
        Err(SelectionError::RiskAcknowledgementRequired)
    );
}

#[test]
fn experimental_accepts_qualified_or_experimental_only() {
    let policy = SelectionPolicy {
        channel: Channel::Experimental,
        acknowledge_risk: true,
    };
    for status in [ProfileStatus::Qualified, ProfileStatus::Experimental] {
        let profiles = vec![profile("accepted", status)];
        assert_eq!(
            select_profile(&profiles, &facts(), &policy)
                .expect("status must be accepted")
                .id,
            "accepted"
        );
    }
}

#[test]
fn never_selects_unsupported_or_deprecated() {
    for status in [ProfileStatus::Unsupported, ProfileStatus::Deprecated] {
        let profiles = vec![profile("rejected", status)];
        let policy = SelectionPolicy {
            channel: Channel::Experimental,
            acknowledge_risk: true,
        };
        assert_eq!(
            select_profile(&profiles, &facts(), &policy),
            Err(SelectionError::NoCompatibleProfile)
        );
    }
}

#[test]
fn rejects_os_id_mismatch_even_when_id_like_would_match() {
    let mut profile = profile("wrong-os", ProfileStatus::Qualified);
    profile.platform.id = "fedora-like-testos".to_owned();
    assert_eq!(
        select_profile(&[profile], &facts(), &stable()),
        Err(SelectionError::NoCompatibleProfile)
    );
}

#[test]
fn rejects_version_arch_pci_kernel_or_module_mismatch() {
    let base = profile("exact-only", ProfileStatus::Qualified);

    let mut wrong_version = base.clone();
    wrong_version.platform.version_id = "2".to_owned();
    let mut wrong_arch = base.clone();
    wrong_arch.platform.arch = "aarch64".to_owned();
    let mut wrong_pci = base.clone();
    wrong_pci.hardware[0].device = "ffff".to_owned();
    let mut above_kernel = base.clone();
    above_kernel.kernel.max_exclusive = "6.17.3".to_owned();
    let mut below_kernel = base.clone();
    below_kernel.kernel.min = "6.17.4".to_owned();

    for mismatch in [
        wrong_version,
        wrong_arch,
        wrong_pci,
        above_kernel,
        below_kernel,
    ] {
        assert_eq!(
            select_profile(&[mismatch], &facts(), &stable()),
            Err(SelectionError::NoCompatibleProfile)
        );
    }

    let mut module_missing = facts();
    module_missing.intel_vpu_loaded = false;
    assert_eq!(
        select_profile(&[base], &module_missing, &stable()),
        Err(SelectionError::NoCompatibleProfile)
    );
}

#[test]
fn rejects_ambiguous_exact_matches() {
    let profiles = vec![
        profile("profile-z", ProfileStatus::Qualified),
        profile("profile-a", ProfileStatus::Qualified),
    ];
    assert_eq!(
        select_profile(&profiles, &facts(), &stable()),
        Err(SelectionError::AmbiguousProfiles(vec![
            "profile-a".to_owned(),
            "profile-z".to_owned(),
        ]))
    );
}

#[test]
fn selection_is_independent_of_input_order() {
    let forward = vec![
        profile("profile-b", ProfileStatus::Qualified),
        profile("profile-a", ProfileStatus::Qualified),
    ];
    let mut reverse = forward.clone();
    reverse.reverse();

    let first = select_profile(&forward, &facts(), &stable()).expect_err("must be ambiguous");
    let second = select_profile(&reverse, &facts(), &stable()).expect_err("must be ambiguous");
    assert_eq!(first, second);
}
