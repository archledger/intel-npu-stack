// SPDX-License-Identifier: Apache-2.0

use stack_install::{NativeInventory, compare_rpm_versions};
use stack_runtime::{
    ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, SystemProcessRunner, Termination,
};
use std::cmp::Ordering;

const INVENTORY: &[u8] = b"kernel-core|0:7.1.12-300.fc44|x86_64|1789000000\nkernel-core|0:7.1.13-300.fc44|x86_64|1789000001\nintel-npu-driver|0:1.32.0-1.fc44|x86_64|1789000000\noneapi-level-zero|0:1.28.6-1.fc44|x86_64|1789000000\n";

#[test]
fn public_key_records_remain_part_of_the_package_state() {
    let original =
        b"gpg-pubkey|0:36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6-6786af3b|(none)|1784789294\n";
    let state = NativeInventory::parse_query(original).unwrap();
    assert_eq!(state.packages()[0].name, "gpg-pubkey");
    assert_eq!(state.packages()[0].arch, "(none)");
    let changed = String::from_utf8(original.to_vec())
        .unwrap()
        .replace("36f612dc", "00000000");
    assert_ne!(
        state.fingerprint(),
        NativeInventory::parse_query(changed.as_bytes())
            .unwrap()
            .fingerprint()
    );
    assert!(NativeInventory::parse_query(b"other|0:1-1.fc44|(none)|0\n").is_err());
}

#[test]
fn native_inventory_preserves_installonly_versions_and_multilib() {
    let mut bytes = INVENTORY.to_vec();
    bytes.extend_from_slice(b"oneapi-level-zero|0:1.28.6-1.fc44|i686|1789000000\n");
    let state = NativeInventory::parse_query(&bytes).unwrap();
    assert_eq!(state.packages().len(), 5);
    assert_eq!(
        state
            .packages()
            .iter()
            .filter(|p| p.name == "kernel-core")
            .count(),
        2
    );
    assert_eq!(
        state
            .packages()
            .iter()
            .filter(|p| p.name == "oneapi-level-zero")
            .count(),
        2
    );
}

#[test]
fn inventory_fingerprint_ignores_query_order_but_detects_package_state_changes() {
    let state = NativeInventory::parse_query(INVENTORY).unwrap();
    let reversed = String::from_utf8(INVENTORY.to_vec())
        .unwrap()
        .lines()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_eq!(
        state.fingerprint(),
        NativeInventory::parse_query(reversed.as_bytes())
            .unwrap()
            .fingerprint()
    );
    for altered in [
        String::from_utf8(INVENTORY.to_vec())
            .unwrap()
            .replace("1.32.0", "1.35.0"),
        String::from_utf8(INVENTORY.to_vec())
            .unwrap()
            .replace("1789000001", "1789000002"),
        reversed.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n",
    ] {
        assert_ne!(
            state.fingerprint(),
            NativeInventory::parse_query(altered.as_bytes())
                .unwrap()
                .fingerprint()
        );
    }
}

#[test]
fn corrupt_duplicate_or_truncated_inventory_is_refused() {
    for bytes in [
        b"".as_slice(),
        b"pkg|0:1-1.fc44|x86_64|0",
        b"pkg|1-1.fc44|x86_64|0\n",
        b"pkg|0:1-1.fc44|x86_64|-1\n",
        b"pkg|0:1-1.fc44|x86_64|0|extra\n",
        b"pkg|0:1-1.fc44|x86_64|0\npkg|0:1-1.fc44|x86_64|1\n",
        b"pkg|0:1-1.fc44|x86_64|0\n\n",
    ] {
        assert_eq!(
            NativeInventory::parse_query(bytes).unwrap_err().exit_code,
            30
        );
    }
    assert!(NativeInventory::parse_query(&vec![b' '; 8_388_609]).is_err());
}

struct QueryFixture;
impl ProcessRunner for QueryFixture {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert_eq!(request.executable.to_str(), Some("/usr/bin/rpm"));
        assert!(request.environment.is_empty());
        let args = request
            .args
            .iter()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(args.contains(&"-qa"));
        assert!(
            args.windows(2)
                .any(|a| a == ["--dbpath", "/usr/lib/sysimage/rpm"])
        );
        assert!(
            args.windows(2)
                .any(|a| a == ["--macros", "/usr/lib/rpm/macros"])
        );
        assert_eq!(
            args.last(),
            Some(&"%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n")
        );
        Ok(ProcessOutput {
            termination: Termination::Exit(0),
            stdout: INVENTORY.to_vec(),
            stdout_overflow: false,
            stderr_overflow: false,
        })
    }
}

#[test]
fn query_reads_the_system_database_and_checks_a_fresh_snapshot() {
    let state = NativeInventory::query(&QueryFixture).unwrap();
    state.verify_unchanged(&QueryFixture).unwrap();
    let changed = NativeInventory::parse_query(b"pkg|0:1-1.fc44|x86_64|0\n").unwrap();
    assert_eq!(
        changed.verify_unchanged(&QueryFixture).unwrap_err().code,
        "INSTALL_STATE_CHANGED"
    );
}

#[test]
fn native_rpm_orders_epoch_release_and_prerelease_versions() {
    for (left, right, want) in [
        (
            "0:1.32.0-1.fc44",
            "0:1.35.0-1.intelnpu.fc44",
            Ordering::Less,
        ),
        ("1:1.0-1.fc44", "0:99.0-1.fc44", Ordering::Greater),
        ("0:1.0~rc1-1.fc44", "0:1.0-1.fc44", Ordering::Less),
        ("0:1.0^git1-1.fc44", "0:1.0-1.fc44", Ordering::Greater),
        ("0:1.0-2.fc44", "0:1.0-10.fc44", Ordering::Less),
        ("0:01.0-1.fc44", "0:1.0-1.fc44", Ordering::Equal),
    ] {
        assert_eq!(
            compare_rpm_versions(left, right, &SystemProcessRunner).unwrap(),
            want
        );
    }
}

#[test]
fn real_native_query_reads_the_system_rpm_package() {
    let state = NativeInventory::query(&SystemProcessRunner).unwrap();
    assert!(
        state
            .packages()
            .iter()
            .any(|p| p.name == "rpm" && p.arch == "x86_64")
    );
    state.verify_unchanged(&SystemProcessRunner).unwrap();
}

struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("unsafe version must be refused before invoking RPM")
    }
}

#[test]
fn unsafe_version_data_never_reaches_macro_evaluation() {
    for value in [
        "0:1-1.fc44\");os.execute(\"id\");--",
        "0:1-1.fc44\n",
        "01:1-1.fc44",
        "1-1.fc44",
        "0:1-",
        "",
    ] {
        assert!(compare_rpm_versions(value, "0:1-1.fc44", &MustNotRun).is_err());
        assert!(compare_rpm_versions("0:1-1.fc44", value, &MustNotRun).is_err());
    }
}

struct Failed(ProcessOutput);
impl ProcessRunner for Failed {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        Ok(self.0.clone())
    }
}

#[test]
fn failed_or_unbounded_native_observations_do_not_become_valid_state() {
    for output in [
        ProcessOutput {
            termination: Termination::Exit(1),
            stdout: b"1".to_vec(),
            stdout_overflow: false,
            stderr_overflow: false,
        },
        ProcessOutput {
            termination: Termination::Exit(0),
            stdout: b"1".to_vec(),
            stdout_overflow: true,
            stderr_overflow: false,
        },
        ProcessOutput {
            termination: Termination::Exit(0),
            stdout: b"1".to_vec(),
            stdout_overflow: false,
            stderr_overflow: true,
        },
        ProcessOutput {
            termination: Termination::Exit(0),
            stdout: b"unknown".to_vec(),
            stdout_overflow: false,
            stderr_overflow: false,
        },
    ] {
        let runner = Failed(output);
        assert!(compare_rpm_versions("0:1-1.fc44", "0:2-1.fc44", &runner).is_err());
        assert!(NativeInventory::query(&runner).is_err());
    }
}
