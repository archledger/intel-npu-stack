// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use xtask::fedora_openvino_package::{
    FedoraOpenvinoPackageSet, OpenvinoPackagePolicy, validate_fedora_openvino_packages,
};

const PACKAGE_NAMES: [&str; 10] = [
    "intel-npu-compiler",
    "libopenvino-ir-frontend",
    "libopenvino-onnx-frontend",
    "libopenvino-paddle-frontend",
    "libopenvino-pytorch-frontend",
    "libopenvino-tensorflow-frontend",
    "libopenvino-tensorflow-lite-frontend",
    "openvino",
    "openvino-devel",
    "openvino-plugins",
];

struct FixtureRpms {
    _root: TempDir,
    packages: Vec<PathBuf>,
    payload_root: PathBuf,
}

#[derive(Default)]
struct FixtureOptions {
    omit_driver_requirement: bool,
    install_opt_payload: bool,
    invalid_plugin_soname: bool,
    ubuntu_elf_marker: bool,
    duplicate_runtime_file: bool,
    network_scriptlet: bool,
    module_payloads: bool,
    omit_runtime_soname: bool,
    omit_loader_soname: bool,
    link_module_dependency: bool,
    executable_plugin: bool,
    omit_cpu_plugin: bool,
    omit_gpu_plugin: bool,
}

fn package_name(package: &Path) -> String {
    let output = Command::new("/usr/bin/rpm")
        .args(["--noplugins", "-qp", "--queryformat", "%{NAME}\n"])
        .arg(package)
        .env("LC_ALL", "C")
        .output()
        .expect("query fixture RPM name");
    assert!(output.status.success(), "query fixture RPM name");
    String::from_utf8(output.stdout)
        .expect("UTF-8 RPM name")
        .trim()
        .to_owned()
}

fn policy() -> OpenvinoPackagePolicy {
    OpenvinoPackagePolicy {
        openvino_nevr: "0:2026.2.0-2.intelnpu.fc44".to_owned(),
        driver_requirement: "intel-npu-driver(x86-64) = 1.38.0-1.intelnpu.fc44".to_owned(),
    }
}

fn validate_fixture(fixture: &FixtureRpms) -> Result<(), String> {
    validate_fedora_openvino_packages(
        &FedoraOpenvinoPackageSet {
            packages: fixture.packages.clone(),
            payload_root: fixture.payload_root.clone(),
        },
        &policy(),
    )
    .map_err(|error| error.code)
}

fn compile_shared(sources: &Path, output: &str, soname: &str, source: &str, links: &[&str]) {
    let source_path = sources.join(format!("{output}.c"));
    fs::write(&source_path, source).expect("write ELF fixture source");
    let mut command = Command::new("/usr/bin/gcc");
    command.args(["-shared", "-fPIC"]);
    if !soname.is_empty() {
        command.arg(format!("-Wl,-soname,{soname}"));
    }
    command
        .arg("-o")
        .arg(sources.join(output))
        .arg(&source_path)
        .arg(format!("-L{}", sources.display()))
        .args(links);
    let output = command.output().expect("compile ELF fixture");
    assert!(
        output.status.success(),
        "ELF fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_fixture_packages() -> FixtureRpms {
    build_fixture_packages_with(&FixtureOptions::default())
}

fn build_fixture_packages_with(options: &FixtureOptions) -> FixtureRpms {
    let root = TempDir::new().expect("create OpenVINO RPM fixture root");
    let topdir = root.path().join("rpmbuild");
    for directory in [
        "BUILD",
        "BUILDROOT",
        "RPMS",
        "SOURCES",
        "SPECS",
        "SRPMS",
        "TMP",
    ] {
        fs::create_dir_all(topdir.join(directory)).expect("create rpmbuild fixture directory");
    }
    let sources = topdir.join("SOURCES");
    fs::write(sources.join("LICENSE"), "fixture Apache-2.0 license\n")
        .expect("write fixture license");
    fs::write(sources.join("openvino.hpp"), "#pragma once\n").expect("write fixture header");

    compile_shared(
        &sources,
        "libopenvino.so.2026.2.0",
        if options.omit_runtime_soname {
            ""
        } else {
            "libopenvino.so.2620"
        },
        "int ov_runtime(void) { return 2620; }\n",
        &[],
    );
    compile_shared(
        &sources,
        "libopenvino_intel_npu_compiler.so",
        if options.module_payloads {
            ""
        } else {
            "libopenvino_intel_npu_compiler.so"
        },
        "int npu_compile(void) { return 7; }\n",
        &[],
    );
    let preserved_plugins = [
        ("cpu", options.omit_cpu_plugin),
        ("gpu", options.omit_gpu_plugin),
    ]
    .into_iter()
    .filter_map(|(device, omitted)| {
        (!omitted).then(|| format!("libopenvino_intel_{device}_plugin.so"))
    })
    .collect::<Vec<_>>();
    for library in &preserved_plugins {
        compile_shared(
            &sources,
            library,
            "",
            "extern int ov_runtime(void); int preserved_plugin(void) { return ov_runtime(); }\n",
            &["-Wl,--no-as-needed", "-l:libopenvino.so.2026.2.0"],
        );
    }
    compile_shared(
        &sources,
        "libopenvino_intel_npu_compiler_loader.so",
        if options.omit_loader_soname {
            ""
        } else {
            "libopenvino_intel_npu_compiler_loader.so"
        },
        if options.module_payloads && !options.link_module_dependency {
            "int npu_load(void) { return 7; }\n"
        } else {
            "extern int npu_compile(void); int npu_load(void) { return npu_compile(); }\n"
        },
        if options.module_payloads && !options.link_module_dependency {
            &[]
        } else {
            &["-Wl,--no-as-needed", "-l:libopenvino_intel_npu_compiler.so"]
        },
    );
    compile_shared(
        &sources,
        "libopenvino_intel_npu_plugin.so",
        if options.invalid_plugin_soname {
            "libwrong_npu_plugin.so"
        } else if options.module_payloads {
            ""
        } else {
            "libopenvino_intel_npu_plugin.so"
        },
        "extern int ov_runtime(void); extern int npu_load(void); int npu_plugin(void) { return ov_runtime() + npu_load(); }\n",
        &[
            "-Wl,--no-as-needed",
            "-l:libopenvino.so.2026.2.0",
            "-l:libopenvino_intel_npu_compiler_loader.so",
        ],
    );
    if options.executable_plugin {
        let source = sources.join("executable.c");
        fs::write(&source, "int main(void) { return 0; }\n").expect("write executable fixture");
        let output = Command::new("/usr/bin/gcc")
            .args(["-fPIE", "-pie", "-o"])
            .arg(sources.join("libopenvino_intel_npu_plugin.so"))
            .arg(source)
            .output()
            .expect("compile executable fixture");
        assert!(output.status.success(), "compile executable fixture");
    }
    if options.ubuntu_elf_marker {
        let marker = sources.join("ubuntu-comment.txt");
        fs::write(&marker, "GCC: (Ubuntu fixture) 13.2.0\n")
            .expect("write Ubuntu ELF marker fixture");
        let output = Command::new("/usr/bin/objcopy")
            .arg(format!("--update-section=.comment={}", marker.display()))
            .arg(sources.join("libopenvino_intel_npu_plugin.so"))
            .output()
            .expect("update fixture ELF comment");
        assert!(
            output.status.success(),
            "fixture objcopy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for frontend in [
        "ir",
        "onnx",
        "paddle",
        "pytorch",
        "tensorflow",
        "tensorflow_lite",
    ] {
        let output = format!("libopenvino_{frontend}_frontend.so.2026.2.0");
        let soname = format!("libopenvino_{frontend}_frontend.so.2620");
        compile_shared(
            &sources,
            &output,
            &soname,
            "int ov_frontend(void) { return 1; }\n",
            &[],
        );
    }

    let payload_root = root.path().join("payload");
    let library_root = payload_root.join("usr/lib64");
    let plugin_root = library_root.join("openvino-2026.2.0");
    fs::create_dir_all(&plugin_root).expect("create extracted fixture library roots");
    fs::create_dir_all(payload_root.join("usr/include/openvino"))
        .expect("create extracted fixture include root");
    for library in [
        "libopenvino.so.2026.2.0",
        "libopenvino_ir_frontend.so.2026.2.0",
        "libopenvino_onnx_frontend.so.2026.2.0",
        "libopenvino_paddle_frontend.so.2026.2.0",
        "libopenvino_pytorch_frontend.so.2026.2.0",
        "libopenvino_tensorflow_frontend.so.2026.2.0",
        "libopenvino_tensorflow_lite_frontend.so.2026.2.0",
    ] {
        fs::copy(sources.join(library), library_root.join(library))
            .expect("copy extracted fixture library");
    }
    symlink(
        "libopenvino.so.2026.2.0",
        library_root.join("libopenvino.so.2620"),
    )
    .expect("create runtime SONAME link");
    symlink("libopenvino.so.2620", library_root.join("libopenvino.so"))
        .expect("create runtime development link");
    for frontend in [
        "ir",
        "onnx",
        "paddle",
        "pytorch",
        "tensorflow",
        "tensorflow_lite",
    ] {
        symlink(
            format!("libopenvino_{frontend}_frontend.so.2026.2.0"),
            library_root.join(format!("libopenvino_{frontend}_frontend.so.2620")),
        )
        .expect("create frontend SONAME link");
    }
    for library in [
        "libopenvino_intel_npu_plugin.so",
        "libopenvino_intel_npu_compiler.so",
        "libopenvino_intel_npu_compiler_loader.so",
    ] {
        fs::copy(sources.join(library), plugin_root.join(library))
            .expect("copy extracted fixture plugin library");
    }
    fs::copy(
        sources.join("openvino.hpp"),
        payload_root.join("usr/include/openvino/openvino.hpp"),
    )
    .expect("copy extracted fixture header");
    for library in &preserved_plugins {
        fs::copy(sources.join(library), plugin_root.join(library))
            .expect("copy preserved acceleration plugin");
    }

    let spec = r#"
%global debug_package %{nil}
%global __strip /usr/bin/true
Name: openvino
Version: 2026.2.0
Release: 1.intelnpu.fc44
Summary: OpenVINO fixture
License: Apache-2.0
Source0: LICENSE
Source1: openvino.hpp
Source2: libopenvino.so.2026.2.0
Source3: libopenvino_intel_npu_plugin.so
Source4: libopenvino_intel_npu_compiler.so
Source5: libopenvino_intel_npu_compiler_loader.so
Source6: libopenvino_ir_frontend.so.2026.2.0
Source7: libopenvino_onnx_frontend.so.2026.2.0
Source8: libopenvino_paddle_frontend.so.2026.2.0
Source9: libopenvino_pytorch_frontend.so.2026.2.0
Source10: libopenvino_tensorflow_frontend.so.2026.2.0
Source11: libopenvino_tensorflow_lite_frontend.so.2026.2.0
Requires: libopenvino-ir-frontend%{?_isa} = %{version}-%{release}
Requires: libopenvino-onnx-frontend%{?_isa} = %{version}-%{release}
Requires: libopenvino-paddle-frontend%{?_isa} = %{version}-%{release}
Requires: libopenvino-pytorch-frontend%{?_isa} = %{version}-%{release}
Requires: libopenvino-tensorflow-frontend%{?_isa} = %{version}-%{release}
Requires: libopenvino-tensorflow-lite-frontend%{?_isa} = %{version}-%{release}

%description
Package-contract fixture.

%package devel
Summary: OpenVINO development fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description devel
Package-contract fixture.

%package plugins
Summary: OpenVINO plugin fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: intel-npu-compiler%{?_isa} = %{version}-%{release}
%description plugins
Package-contract fixture.

%package -n intel-npu-compiler
Summary: Intel NPU compiler fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
@DRIVER_REQUIREMENT@
%description -n intel-npu-compiler
Package-contract fixture.

%package -n libopenvino-ir-frontend
Summary: OpenVINO IR frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-ir-frontend
Package-contract fixture.

%package -n libopenvino-onnx-frontend
Summary: OpenVINO ONNX frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-onnx-frontend
Package-contract fixture.

%package -n libopenvino-paddle-frontend
Summary: OpenVINO Paddle frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-paddle-frontend
Package-contract fixture.

%package -n libopenvino-pytorch-frontend
Summary: OpenVINO PyTorch frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-pytorch-frontend
Package-contract fixture.

%package -n libopenvino-tensorflow-frontend
Summary: OpenVINO TensorFlow frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-tensorflow-frontend
Package-contract fixture.

%package -n libopenvino-tensorflow-lite-frontend
Summary: OpenVINO TensorFlow Lite frontend fixture
Requires: %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-tensorflow-lite-frontend
Package-contract fixture.

%prep
%build

%install
install -Dm0644 %{SOURCE0} %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dm0644 %{SOURCE1} %{buildroot}%{_includedir}/openvino/openvino.hpp
install -Dm0755 %{SOURCE2} %{buildroot}%{_libdir}/libopenvino.so.2026.2.0
ln -s libopenvino.so.2026.2.0 %{buildroot}%{_libdir}/libopenvino.so.2620
ln -s libopenvino.so.2620 %{buildroot}%{_libdir}/libopenvino.so
install -Dm0755 %{SOURCE3} %{buildroot}%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_plugin.so
install -Dm0755 %{SOURCE4} %{buildroot}%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_compiler.so
install -Dm0755 %{SOURCE5} %{buildroot}%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_compiler_loader.so
install -Dm0755 %{SOURCE6} %{buildroot}%{_libdir}/libopenvino_ir_frontend.so.2026.2.0
install -Dm0755 %{SOURCE7} %{buildroot}%{_libdir}/libopenvino_onnx_frontend.so.2026.2.0
install -Dm0755 %{SOURCE8} %{buildroot}%{_libdir}/libopenvino_paddle_frontend.so.2026.2.0
install -Dm0755 %{SOURCE9} %{buildroot}%{_libdir}/libopenvino_pytorch_frontend.so.2026.2.0
install -Dm0755 %{SOURCE10} %{buildroot}%{_libdir}/libopenvino_tensorflow_frontend.so.2026.2.0
install -Dm0755 %{SOURCE11} %{buildroot}%{_libdir}/libopenvino_tensorflow_lite_frontend.so.2026.2.0
@PRESERVED_PLUGIN_INSTALL@
@OPT_INSTALL@

%files
%license %{_licensedir}/%{name}/LICENSE
%{_libdir}/libopenvino.so.2026.2.0
%{_libdir}/libopenvino.so.2620

%files devel
%{_includedir}/openvino/openvino.hpp
%{_libdir}/libopenvino.so
@DUPLICATE_FILE@

%files plugins
%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_plugin.so
@PRESERVED_PLUGIN_FILES@
@OPT_FILE@

%files -n intel-npu-compiler
%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_compiler.so
%{_libdir}/openvino-2026.2.0/libopenvino_intel_npu_compiler_loader.so

%files -n libopenvino-ir-frontend
%{_libdir}/libopenvino_ir_frontend.so.2026.2.0
%{_libdir}/libopenvino_ir_frontend.so.2620
%files -n libopenvino-onnx-frontend
%{_libdir}/libopenvino_onnx_frontend.so.2026.2.0
%{_libdir}/libopenvino_onnx_frontend.so.2620
%files -n libopenvino-paddle-frontend
%{_libdir}/libopenvino_paddle_frontend.so.2026.2.0
%{_libdir}/libopenvino_paddle_frontend.so.2620
%files -n libopenvino-pytorch-frontend
%{_libdir}/libopenvino_pytorch_frontend.so.2026.2.0
%{_libdir}/libopenvino_pytorch_frontend.so.2620
%files -n libopenvino-tensorflow-frontend
%{_libdir}/libopenvino_tensorflow_frontend.so.2026.2.0
%{_libdir}/libopenvino_tensorflow_frontend.so.2620
%files -n libopenvino-tensorflow-lite-frontend
%{_libdir}/libopenvino_tensorflow_lite_frontend.so.2026.2.0
%{_libdir}/libopenvino_tensorflow_lite_frontend.so.2620
@SCRIPTLET@
"#
        .replace(
            "@PRESERVED_PLUGIN_INSTALL@",
            &preserved_plugins
                .iter()
                .map(|library| format!("install -Dm0755 %{{_sourcedir}}/{library} %{{buildroot}}%{{_libdir}}/openvino-2026.2.0/{library}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .replace(
            "@PRESERVED_PLUGIN_FILES@",
            &preserved_plugins
                .iter()
                .map(|library| format!("%{{_libdir}}/openvino-2026.2.0/{library}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .replace(
            "@DRIVER_REQUIREMENT@",
            if options.omit_driver_requirement {
                ""
            } else {
                "Requires: intel-npu-driver%{?_isa} = 1.38.0-1.intelnpu.fc44"
            },
        )
        .replace(
            "@OPT_INSTALL@",
            if options.install_opt_payload {
                "install -Dm0644 %{SOURCE0} %{buildroot}/opt/intel/openvino-fixture"
            } else {
                ""
            },
        )
        .replace(
            "@OPT_FILE@",
            if options.install_opt_payload {
                "/opt/intel/openvino-fixture"
            } else {
                ""
            },
        )
        .replace(
            "@DUPLICATE_FILE@",
            if options.duplicate_runtime_file {
                "%{_libdir}/libopenvino.so.2026.2.0"
            } else {
                ""
            },
        )
        .replace(
            "@SCRIPTLET@",
            if options.network_scriptlet {
                "%post -n openvino-plugins\n/usr/bin/curl https://example.invalid/payload"
            } else {
                ""
            },
        );
    let spec_path = topdir.join("SPECS/openvino.spec");
    fs::write(&spec_path, spec).expect("write OpenVINO fixture spec");
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
        .expect("run OpenVINO fixture rpmbuild");
    assert!(
        output.status.success(),
        "fixture rpmbuild failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut packages = Vec::new();
    for architecture in fs::read_dir(topdir.join("RPMS")).expect("read RPM architecture dirs") {
        let architecture = architecture.expect("read architecture entry").path();
        if architecture.is_dir() {
            for entry in fs::read_dir(architecture).expect("read built RPMs") {
                let path = entry.expect("read RPM entry").path();
                if path.extension().is_some_and(|extension| extension == "rpm") {
                    packages.push(path);
                }
            }
        }
    }
    packages.sort();
    FixtureRpms {
        _root: root,
        packages,
        payload_root,
    }
}

#[test]
fn fixture_rpm_and_elf_construction_succeeds_before_contract_work() {
    let fixture = build_fixture_packages();
    let mut names = fixture
        .packages
        .iter()
        .map(|package| package_name(package))
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, PACKAGE_NAMES);
    assert!(
        fixture
            .payload_root
            .join("usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so")
            .is_file()
    );
}

#[test]
fn accepts_exact_openvino_runtime_compiler_and_frontend_closure() {
    let fixture = build_fixture_packages();
    let plugin_package = fixture
        .packages
        .iter()
        .find(|package| package_name(package) == "openvino-plugins")
        .expect("fixture plugin RPM");
    let query = Command::new("/usr/bin/rpm")
        .args([
            "--noplugins",
            "-qp",
            "--queryformat",
            "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]",
        ])
        .arg(plugin_package)
        .env("LC_ALL", "C")
        .output()
        .expect("query fixture plugin digest");
    assert!(query.status.success());
    let packaged = String::from_utf8(query.stdout).expect("UTF-8 fixture digest query");
    let payload = fs::read(
        fixture
            .payload_root
            .join("usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so"),
    )
    .expect("read extracted fixture plugin");
    let payload_digest = format!("{:x}", Sha256::digest(payload));
    assert!(
        packaged.contains(&payload_digest),
        "fixture payload must match packaged ELF digest: {packaged} != {payload_digest}"
    );
    let result = validate_fedora_openvino_packages(
        &FedoraOpenvinoPackageSet {
            packages: fixture.packages.clone(),
            payload_root: fixture.payload_root.clone(),
        },
        &policy(),
    );
    assert!(result.is_ok(), "valid fixture rejected: {result:?}");
}

#[test]
fn rejects_an_incomplete_package_set() {
    let mut fixture = build_fixture_packages();
    fixture
        .packages
        .retain(|package| package_name(package) != "openvino-devel");
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_PACKAGE_SET_INVALID".to_owned())
    );
}

#[test]
fn rejects_shared_provider_upgrade_without_cpu_plugin() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        omit_cpu_plugin: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}

#[test]
fn rejects_shared_provider_upgrade_without_gpu_plugin() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        omit_gpu_plugin: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}

#[test]
fn rejects_a_missing_or_unbound_npu_plugin_payload() {
    let fixture = build_fixture_packages();
    fs::remove_file(
        fixture
            .payload_root
            .join("usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so"),
    )
    .expect("remove extracted NPU plugin fixture");
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}

#[test]
fn rejects_missing_exact_driver_dependency_or_opt_payload() {
    for (options, expected) in [
        (
            FixtureOptions {
                omit_driver_requirement: true,
                ..FixtureOptions::default()
            },
            "FEDORA_OPENVINO_DEPENDENCY_INVALID",
        ),
        (
            FixtureOptions {
                install_opt_payload: true,
                ..FixtureOptions::default()
            },
            "FEDORA_OPENVINO_FILE_INVALID",
        ),
    ] {
        let fixture = build_fixture_packages_with(&options);
        assert_eq!(
            validate_fixture(&fixture),
            Err(expected.to_owned()),
            "unsafe package mutation returned the wrong classification"
        );
    }
}

#[test]
fn rejects_invalid_soname_or_ubuntu_elf_marker() {
    for options in [
        FixtureOptions {
            invalid_plugin_soname: true,
            ..FixtureOptions::default()
        },
        FixtureOptions {
            ubuntu_elf_marker: true,
            ..FixtureOptions::default()
        },
    ] {
        let fixture = build_fixture_packages_with(&options);
        assert_eq!(
            validate_fixture(&fixture),
            Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_cross_package_overlap_or_network_scriptlet() {
    for (options, expected) in [
        (
            FixtureOptions {
                duplicate_runtime_file: true,
                ..FixtureOptions::default()
            },
            "FEDORA_OPENVINO_FILE_OVERLAP",
        ),
        (
            FixtureOptions {
                network_scriptlet: true,
                ..FixtureOptions::default()
            },
            "FEDORA_OPENVINO_SCRIPT_INVALID",
        ),
    ] {
        let fixture = build_fixture_packages_with(&options);
        assert_eq!(validate_fixture(&fixture), Err(expected.to_owned()));
    }
}

#[test]
fn production_spec_declares_the_source_built_openvino_npu_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let spec = fs::read_to_string(root.join("packaging/fedora/44/rpm/openvino/openvino.spec"))
        .expect("read production OpenVINO spec");

    for required in [
        "Name:           openvino",
        "Version:        2026.2.0",
        "Release:        1.intelnpu.fc44",
        "ExclusiveArch:  x86_64",
        "openvino.tar",
        "npu-compiler.tar",
        "npu-compiler-elf-openvino.tar",
        "intel-npu-compiler-llvm.tar",
        "intel-npu-nn-cost-model.tar",
        "level-zero-npu-extensions.tar",
        "openvino-flatbuffers.tar",
        "openvino-mlas.tar",
        "openvino-onnx.tar",
        "openvino-onednn-cpu.tar",
        "openvino-onednn-gpu.tar",
        "openvino-protobuf.tar",
        "npu-compiler-archive-build.patch",
        "BuildRequires:  gmock-devel = 1.17.0-2.fc44",
        "BuildRequires:  gtest-devel = 1.17.0-2.fc44",
        "%package devel",
        "%package plugins",
        "%package -n intel-npu-compiler",
        "-DENABLE_INTEL_NPU=ON",
        "-DENABLE_INTEL_NPU_COMPILER=OFF",
        "-DENABLE_JS=OFF",
        "-DCMAKE_DISABLE_FIND_PACKAGE_ONNX=ON",
        "-DONNX_BUILD_PYTHON=OFF",
        "-DENABLE_SYSTEM_PROTOBUF=OFF",
        "-Dprotobuf_BUILD_TESTS=OFF",
        "-DBUILD_COMPILER_FOR_DRIVER=ON",
        "-DNPU_COMPILER_SOURCE_COMMIT=6a7a7c531f54baed1dddfda1b80299413c4c6943",
        "-DNPU_LOADER_SOURCE_COMMIT=0c96256285114a596988bfa6e4face817165396c",
        "libopenvino_intel_npu_plugin.so",
        "libopenvino_intel_npu_compiler.so",
        "libopenvino_intel_npu_compiler_loader.so",
    ] {
        assert!(spec.contains(required), "missing spec contract: {required}");
    }

    let lowercase = spec.to_ascii_lowercase();
    for forbidden in [
        "npu_compiler_vcl_ubuntu",
        "storage.openvinotoolkit.org",
        "/opt/",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "forbidden prebuilt or non-Fedora path: {forbidden}"
        );
    }
}

#[test]
fn module_contract_accepts_filename_loaded_modules_without_soname() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        module_payloads: true,
        ..FixtureOptions::default()
    });
    assert_eq!(validate_fixture(&fixture), Ok(()));
}

#[test]
fn module_contract_requires_runtime_shared_library_soname() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        omit_runtime_soname: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}

#[test]
fn module_contract_requires_loader_shared_library_soname() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        omit_loader_soname: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}

#[test]
fn module_contract_does_not_invent_soname_providers_for_needed_closure() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        module_payloads: true,
        link_module_dependency: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_CLOSURE_INVALID".to_owned())
    );
}

#[test]
fn module_contract_rejects_pie_executable_as_plugin() {
    let fixture = build_fixture_packages_with(&FixtureOptions {
        executable_plugin: true,
        ..FixtureOptions::default()
    });
    assert_eq!(
        validate_fixture(&fixture),
        Err("FEDORA_OPENVINO_ELF_INVALID".to_owned())
    );
}
