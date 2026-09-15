// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use xtask::fedora_package::{
    DriverPackagePolicy, FedoraDriverPackagePaths, validate_fedora_driver_packages,
};

const FIRMWARE_PAYLOAD: &[u8] = b"fixture Lunar Lake firmware\n";

#[test]
fn production_driver_header_dependencies_exclude_test_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a repository parent");
    let output = Command::new("python3")
        .arg(root.join("packaging/fedora/44/rpm/intel-npu-driver/test-driver-headers.py"))
        .output()
        .expect("run production driver header contract");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[derive(Default)]
struct FixtureOptions {
    omit_loader_requirement: bool,
    omit_firmware_provide: bool,
    driver_script: Option<&'static str>,
    install_driver_outside_prefixes: bool,
    install_unversioned_driver: bool,
    install_production_directory_entries: bool,
    omit_driver_license: bool,
    firmware_executable: bool,
    omit_firmware_license: bool,
    firmware_notice_mode: Option<&'static str>,
    firmware_notice_unlicensed: bool,
    extra_firmware_notice: bool,
    firmware_license_directory_mode: Option<&'static str>,
    firmware_payload: Option<&'static [u8]>,
}

struct FixtureRpms {
    _root: TempDir,
    driver: PathBuf,
    firmware: PathBuf,
    firmware_sha256: String,
}

fn build_rpm(topdir: &Path, spec_name: &str, spec: &str) -> PathBuf {
    for directory in [
        "BUILD",
        "BUILDROOT",
        "RPMS",
        "SOURCES",
        "SPECS",
        "SRPMS",
        "TMP",
    ] {
        fs::create_dir_all(topdir.join(directory)).expect("create rpmbuild directory");
    }
    let spec_path = topdir.join("SPECS").join(spec_name);
    fs::write(&spec_path, spec).expect("write fixture spec");
    let output = Command::new("/usr/bin/rpmbuild")
        .arg("--noplugins")
        .args(["--define", &format!("_topdir {}", topdir.display())])
        .args([
            "--define",
            &format!("_tmppath {}", topdir.join("TMP").display()),
        ])
        .args(["--define", "_buildhost fixture.invalid"])
        .args(["--define", "source_date_epoch_from_changelog 0"])
        .arg("-bb")
        .arg(&spec_path)
        .env("LC_ALL", "C")
        .output()
        .expect("run rpmbuild");
    assert!(
        output.status.success(),
        "fixture rpmbuild failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let architecture_dir = topdir.join("RPMS");
    let mut rpms = Vec::new();
    for architecture in fs::read_dir(&architecture_dir).expect("read RPM architecture dirs") {
        let architecture = architecture.expect("read RPM architecture entry").path();
        if !architecture.is_dir() {
            continue;
        }
        for entry in fs::read_dir(architecture).expect("read built RPMs") {
            let path = entry.expect("read RPM entry").path();
            if path.extension().is_some_and(|extension| extension == "rpm") {
                rpms.push(path);
            }
        }
    }
    assert_eq!(rpms.len(), 1, "fixture spec must build exactly one RPM");
    rpms.pop().expect("one fixture RPM")
}

fn fixture_packages(options: &FixtureOptions) -> FixtureRpms {
    let root = TempDir::new().expect("create RPM fixture root");
    let driver_topdir = root.path().join("driver");
    let firmware_topdir = root.path().join("firmware");
    fs::create_dir_all(driver_topdir.join("SOURCES")).expect("create driver sources");
    fs::create_dir_all(firmware_topdir.join("SOURCES")).expect("create firmware sources");
    fs::write(
        driver_topdir.join("SOURCES/libze_intel_npu.so.1.38.0"),
        "fixture driver library\n",
    )
    .expect("write driver payload");
    fs::write(
        driver_topdir.join("SOURCES/LICENSE.md"),
        "fixture driver license\n",
    )
    .expect("write driver license");
    fs::write(
        firmware_topdir.join("SOURCES/vpu_40xx_v1.bin"),
        options.firmware_payload.unwrap_or(FIRMWARE_PAYLOAD),
    )
    .expect("write firmware payload");
    fs::write(
        firmware_topdir.join("SOURCES/COPYRIGHT"),
        "fixture firmware license\n",
    )
    .expect("write firmware license");

    let driver_spec = r#"
Name: intel-npu-driver
Version: 1.38.0
Release: 1.intelnpu.fc44
Summary: Intel NPU driver fixture
License: MIT
BuildArch: x86_64
Source0: libze_intel_npu.so.1.38.0
Source1: LICENSE.md
@LOADER_REQUIREMENT@

%description
Package-contract fixture.

%prep

%build

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_libdir}/libze_intel_npu.so.1.38.0
ln -s libze_intel_npu.so.1.38.0 %{buildroot}%{_libdir}/libze_intel_npu.so.1
@DRIVER_LICENSE_INSTALL@
@DRIVER_DIRECTORY_INSTALL@
@DRIVER_EXTRA_INSTALL@

%files
@DRIVER_DIRECTORY_FILES@
@DRIVER_LICENSE_FILE@
%{_libdir}/libze_intel_npu.so.1
%{_libdir}/libze_intel_npu.so.1.38.0
@DRIVER_EXTRA_FILES@
@DRIVER_SCRIPT@
"#
    .replace(
        "@LOADER_REQUIREMENT@",
        if options.omit_loader_requirement {
            ""
        } else {
            "Requires: oneapi-level-zero(x86-64) = 1.32.0-1.intelnpu.fc44"
        },
    )
    .replace(
        "@DRIVER_LICENSE_INSTALL@",
        if options.omit_driver_license {
            ""
        } else {
            "install -Dm0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE.md"
        },
    )
    .replace(
        "@DRIVER_LICENSE_FILE@",
        if options.omit_driver_license {
            ""
        } else {
            "%license %{_licensedir}/%{name}/LICENSE.md"
        },
    )
    .replace(
        "@DRIVER_DIRECTORY_INSTALL@",
        if options.install_production_directory_entries {
            "install -d %{buildroot}/usr/lib/.build-id %{buildroot}%{_docdir}/%{name}"
        } else {
            ""
        },
    )
    .replace(
        "@DRIVER_DIRECTORY_FILES@",
        if options.install_production_directory_entries {
            "%dir /usr/lib/.build-id\n%dir %{_docdir}/%{name}\n%dir %{_licensedir}/%{name}"
        } else {
            ""
        },
    )
    .replace(
        "@DRIVER_EXTRA_INSTALL@",
        if options.install_driver_outside_prefixes {
            "install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/intel-npu-driver.conf"
        } else if options.install_unversioned_driver {
            "ln -s libze_intel_npu.so.1 %{buildroot}%{_libdir}/libze_intel_npu.so"
        } else {
            ""
        },
    )
    .replace(
        "@DRIVER_EXTRA_FILES@",
        if options.install_driver_outside_prefixes {
            "%{_sysconfdir}/intel-npu-driver.conf"
        } else if options.install_unversioned_driver {
            "%{_libdir}/libze_intel_npu.so"
        } else {
            ""
        },
    )
    .replace("@DRIVER_SCRIPT@", options.driver_script.unwrap_or(""));

    let firmware_spec = r#"
Name: intel-npu-stack-firmware
Version: 1.38.0
Release: 1.intelnpu.fc44
Summary: Intel NPU firmware fixture
License: LicenseRef-Intel-NPU-Firmware
BuildArch: noarch
Source0: vpu_40xx_v1.bin
Source1: COPYRIGHT
@FIRMWARE_PROVIDE@

%description
Package-contract fixture.

%prep

%build

%install
install -Dm@FIRMWARE_MODE@ %{SOURCE0} %{buildroot}/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin
@FIRMWARE_LICENSE_INSTALL@
@FIRMWARE_NOTICES_INSTALL@

%files
@FIRMWARE_LICENSE_FILE@
@FIRMWARE_NOTICES_FILES@
@FIRMWARE_FILE@
"#
        .replace(
            "@FIRMWARE_PROVIDE@",
            if options.omit_firmware_provide {
                ""
            } else {
                "Provides: intel-npu-firmware = 1.38.0"
            },
        )
        .replace(
            "@FIRMWARE_MODE@",
            if options.firmware_executable {
                "0755"
            } else {
                "0644"
            },
        )
        .replace(
            "@FIRMWARE_LICENSE_INSTALL@",
            if options.omit_firmware_license {
                ""
            } else {
                "install -Dm0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/COPYRIGHT"
            },
        )
        .replace(
            "@FIRMWARE_LICENSE_FILE@",
            if options.omit_firmware_license {
                ""
            } else {
                "%license %{_licensedir}/%{name}/COPYRIGHT"
            },
        )
        .replace(
            "@FIRMWARE_NOTICES_INSTALL@",
            &if options.install_production_directory_entries {
                format!(
                    "printf '{{}}\\n' > %{{buildroot}}%{{_licensedir}}/%{{name}}/SHA256.json\n{}",
                    if options.extra_firmware_notice {
                        "touch %{buildroot}%{_licensedir}/%{name}/unexpected"
                    } else {
                        ""
                    }
                )
            } else {
                String::new()
            },
        )
        .replace(
            "@FIRMWARE_NOTICES_FILES@",
            &if options.install_production_directory_entries {
                format!(
                    "%dir %attr({},root,root) %{{_licensedir}}/%{{name}}\n{} %attr({},root,root) %{{_licensedir}}/%{{name}}/SHA256.json\n{}",
                    options.firmware_license_directory_mode.unwrap_or("0755"),
                    if options.firmware_notice_unlicensed { "" } else { "%license" },
                    options.firmware_notice_mode.unwrap_or("0644"),
                    if options.extra_firmware_notice {
                        "%license %{_licensedir}/%{name}/unexpected"
                    } else {
                        ""
                    }
                )
            } else {
                String::new()
            },
        )
        .replace(
            "@FIRMWARE_FILE@",
            if options.firmware_executable {
                "%attr(0755,root,root) /usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin"
            } else {
                "/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin"
            },
        );

    let driver = build_rpm(&driver_topdir, "intel-npu-driver.spec", &driver_spec);
    let firmware = build_rpm(
        &firmware_topdir,
        "intel-npu-stack-firmware.spec",
        &firmware_spec,
    );
    let firmware_sha256 = format!(
        "{:x}",
        Sha256::digest(options.firmware_payload.unwrap_or(FIRMWARE_PAYLOAD))
    );
    FixtureRpms {
        _root: root,
        driver,
        firmware,
        firmware_sha256,
    }
}

fn policy(firmware_sha256: &str) -> DriverPackagePolicy {
    DriverPackagePolicy {
        driver_nevr: "0:1.38.0-1.intelnpu.fc44".to_owned(),
        loader_requirement: "oneapi-level-zero(x86-64) = 1.32.0-1.intelnpu.fc44".to_owned(),
        firmware_nevr: "0:1.38.0-1.intelnpu.fc44".to_owned(),
        firmware_sha256: firmware_sha256.to_owned(),
    }
}

fn validate_fixture(fixture: &FixtureRpms, expected_firmware_sha256: &str) -> Result<(), String> {
    validate_fedora_driver_packages(
        &FedoraDriverPackagePaths {
            driver: fixture.driver.clone(),
            firmware: fixture.firmware.clone(),
        },
        &policy(expected_firmware_sha256),
    )
    .map_err(|error| error.code)
}

#[test]
fn fixture_rpm_construction_succeeds_before_contract_work() {
    let fixture = fixture_packages(&FixtureOptions::default());
    for (path, expected_name) in [
        (&fixture.driver, "intel-npu-driver"),
        (&fixture.firmware, "intel-npu-stack-firmware"),
    ] {
        let output = Command::new("/usr/bin/rpm")
            .args(["-qp", "--queryformat", "%{NAME}\\n"])
            .arg(path)
            .env("LC_ALL", "C")
            .output()
            .expect("query fixture RPM");
        assert!(output.status.success(), "query fixture RPM");
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 name"),
            format!("{expected_name}\n")
        );
    }
    assert_eq!(fixture.firmware_sha256.len(), 64);
}

#[test]
fn accepts_exact_driver_and_firmware_package_contract() {
    let fixture = fixture_packages(&FixtureOptions::default());
    assert_eq!(validate_fixture(&fixture, &fixture.firmware_sha256), Ok(()));
}

#[test]
fn accepts_approved_production_directory_ownership() {
    let fixture = fixture_packages(&FixtureOptions {
        install_production_directory_entries: true,
        ..FixtureOptions::default()
    });
    assert_eq!(validate_fixture(&fixture, &fixture.firmware_sha256), Ok(()));
}

#[test]
fn rejects_unapproved_firmware_notice_paths_and_modes() {
    for options in [
        FixtureOptions {
            extra_firmware_notice: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            firmware_notice_mode: Some("0755"),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            firmware_notice_unlicensed: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            firmware_license_directory_mode: Some("0777"),
            ..FixtureOptions::default()
        },
    ] {
        let fixture = fixture_packages(&FixtureOptions {
            install_production_directory_entries: true,
            ..options
        });
        assert!(validate_fixture(&fixture, &fixture.firmware_sha256).is_err());
    }
}

#[test]
fn rejects_missing_exact_runtime_dependency_or_firmware_provide() {
    for options in [
        FixtureOptions {
            omit_loader_requirement: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            omit_firmware_provide: true,
            ..FixtureOptions::default()
        },
    ] {
        let fixture = fixture_packages(&options);
        assert_eq!(
            validate_fixture(&fixture, &fixture.firmware_sha256),
            Err("FEDORA_PACKAGE_DEPENDENCY_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_module_or_network_maintainer_scripts() {
    for script in [
        "%post\n/usr/sbin/modprobe intel_vpu",
        "%post\n/usr/bin/curl https://example.invalid/payload",
        "%filetriggerin -- /usr/lib64\n/usr/bin/curl https://example.invalid/payload",
    ] {
        let fixture = fixture_packages(&FixtureOptions {
            driver_script: Some(script),
            ..FixtureOptions::default()
        });
        assert_eq!(
            validate_fixture(&fixture, &fixture.firmware_sha256),
            Err("FEDORA_PACKAGE_SCRIPT_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_driver_ownership_outside_prefixes_or_unversioned_link() {
    for options in [
        FixtureOptions {
            install_driver_outside_prefixes: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            install_unversioned_driver: true,
            ..FixtureOptions::default()
        },
    ] {
        let fixture = fixture_packages(&options);
        assert_eq!(
            validate_fixture(&fixture, &fixture.firmware_sha256),
            Err("FEDORA_PACKAGE_FILE_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_missing_package_license_files() {
    for options in [
        FixtureOptions {
            omit_driver_license: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            omit_firmware_license: true,
            ..FixtureOptions::default()
        },
    ] {
        let fixture = fixture_packages(&options);
        assert_eq!(
            validate_fixture(&fixture, &fixture.firmware_sha256),
            Err("FEDORA_PACKAGE_LICENSE_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_executable_or_wrong_digest_firmware() {
    let executable = fixture_packages(&FixtureOptions {
        firmware_executable: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&executable, &executable.firmware_sha256),
        Err("FEDORA_PACKAGE_FIRMWARE_INVALID".to_owned())
    );

    let changed = fixture_packages(&FixtureOptions {
        firmware_payload: Some(b"different firmware\n"),
        ..FixtureOptions::default()
    });
    let expected = format!("{:x}", Sha256::digest(FIRMWARE_PAYLOAD));
    assert_eq!(
        validate_fixture(&changed, &expected),
        Err("FEDORA_PACKAGE_FIRMWARE_INVALID".to_owned())
    );
}

#[test]
fn production_specs_are_present_at_the_reviewed_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    assert!(
        root.join("packaging/fedora/44/rpm/intel-npu-driver/intel-npu-driver.spec")
            .is_file()
    );
    assert!(
        root.join("packaging/fedora/44/rpm/intel-npu-stack-firmware/intel-npu-stack-firmware.spec")
            .is_file()
    );
}

#[test]
fn production_driver_spec_runs_the_self_contained_test_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let spec = fs::read_to_string(
        root.join("packaging/fedora/44/rpm/intel-npu-driver/intel-npu-driver.spec"),
    )
    .expect("read production driver spec");

    assert!(spec.contains("redhat-linux-build/bin/npu_shared_tests"));
    assert!(spec.contains("redhat-linux-build/bin/ze_intel_npu_tests"));
    assert!(spec.contains("--test-dir redhat-linux-build/third_party/npu_compiler_elf"));
    assert!(spec.contains(
        "--gtest_filter=-GraphExecution.*:CompilerInDriver.*:GraphNativeTest.*:CommandListGraphApiTest.*"
    ));
}
