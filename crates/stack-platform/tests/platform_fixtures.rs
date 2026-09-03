// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use stack_platform::{PlatformPaths, detect_platform, parse_os_release};
use tempfile::TempDir;

const INJECTION_MARKER: &str = "/tmp/intel-npu-stack-must-not-exist";

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture path has a parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn add_pci(root: &Path, bus_address: &str, vendor: &str, device: &str) {
    write(
        root,
        &format!("sys/bus/pci/devices/{bus_address}/vendor"),
        vendor,
    );
    write(
        root,
        &format!("sys/bus/pci/devices/{bus_address}/device"),
        device,
    );
}

fn platform_fixture() -> TempDir {
    let fixture = tempfile::tempdir().expect("create platform fixture");
    write(
        fixture.path(),
        "etc/os-release",
        "ID=testos\nVERSION_ID=1\nID_LIKE=fedora\n",
    );
    write(
        fixture.path(),
        "proc/sys/kernel/osrelease",
        "6.17.3-200.testos.x86_64\n",
    );
    write(
        fixture.path(),
        "proc/modules",
        "intel_vpu 123 0 - Live 0x00000000\nintel_vpu_aux 1 0 - Live 0x0\n",
    );
    add_pci(fixture.path(), "0000:00:0b.0", "0x8086\n", "0xABCD\n");
    write(fixture.path(), "dev/accel/accel0", "");
    fixture
}

#[test]
fn parse_quoted_os_release_without_shell_evaluation() {
    assert!(
        !Path::new(INJECTION_MARKER).exists(),
        "injection marker must be absent before test"
    );
    let parsed = parse_os_release(
        "ID='testos'\nVERSION_ID=\"1\"\nPRETTY_NAME=\"$(touch /tmp/intel-npu-stack-must-not-exist)\"\n",
    )
    .expect("quoted os-release must parse as data");

    assert_eq!(parsed.id, "testos");
    assert_eq!(parsed.version_id, "1");
    assert!(!Path::new(INJECTION_MARKER).exists());
}

#[test]
fn reject_duplicate_os_release_id() {
    let error = parse_os_release("ID=testos\nID=other\nVERSION_ID=1\n")
        .expect_err("duplicate ID must be rejected");
    assert_eq!(error.code, "PLATFORM_OS_RELEASE_INVALID");
}

#[test]
fn reject_invalid_os_release_key() {
    let error = parse_os_release("ID=testos\nVERSION_ID=1\nlowercase=bad\n")
        .expect_err("invalid key must be rejected");
    assert_eq!(error.code, "PLATFORM_OS_RELEASE_INVALID");
}

#[test]
fn detect_exact_platform_facts_from_fixture_root() {
    let fixture = platform_fixture();
    let facts = detect_platform(
        &PlatformPaths {
            root: fixture.path().to_path_buf(),
        },
        "x86_64",
    )
    .expect("fixture platform must be detected");

    assert_eq!(facts.os_id, "testos");
    assert_eq!(facts.os_version_id, "1");
    assert_eq!(facts.arch, "x86_64");
    assert_eq!(
        (facts.kernel.major, facts.kernel.minor, facts.kernel.patch),
        (6, 17, 3)
    );
    assert_eq!(facts.pci_ids.len(), 1);
    assert_eq!(facts.pci_ids[0].vendor, "8086");
    assert_eq!(facts.pci_ids[0].device, "abcd");
    assert!(facts.intel_vpu_loaded);
    assert!(facts.accel_node_present);
}

#[test]
fn normalize_sort_and_deduplicate_pci_ids() {
    let fixture = platform_fixture();
    add_pci(fixture.path(), "0000:00:0c.0", "0X8086\n", "0xabcd\n");
    add_pci(fixture.path(), "0000:00:0a.0", "0x1234\n", "0x00EF\n");

    let facts = detect_platform(
        &PlatformPaths {
            root: fixture.path().to_path_buf(),
        },
        "x86_64",
    )
    .expect("fixture platform must be detected");

    let ids = facts
        .pci_ids
        .iter()
        .map(|id| format!("{}:{}", id.vendor, id.device))
        .collect::<Vec<_>>();
    assert_eq!(ids, ["1234:00ef", "8086:abcd"]);
}

#[test]
fn report_missing_intel_vpu_and_accel_node() {
    let fixture = platform_fixture();
    write(
        fixture.path(),
        "proc/modules",
        "intel_vpu_aux 1 0 - Live 0x0\n",
    );
    fs::remove_file(fixture.path().join("dev/accel/accel0")).expect("remove fixture node");

    let facts = detect_platform(
        &PlatformPaths {
            root: fixture.path().to_path_buf(),
        },
        "x86_64",
    )
    .expect("fixture platform must be detected");

    assert!(!facts.intel_vpu_loaded);
    assert!(!facts.accel_node_present);
}

#[test]
fn never_include_pci_bus_addresses_in_facts() {
    let fixture = platform_fixture();
    let bus_address = "0000:00:0b.0";
    let facts = detect_platform(
        &PlatformPaths {
            root: fixture.path().to_path_buf(),
        },
        "x86_64",
    )
    .expect("fixture platform must be detected");

    assert!(!format!("{facts:?}").contains(bus_address));
    assert!(
        !facts
            .arch
            .contains(&PathBuf::from(fixture.path()).display().to_string())
    );
}
