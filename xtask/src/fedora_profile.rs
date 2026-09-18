// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, SystemProcessRunner, Termination};
use stack_schema::{
    ActivationRequirement, ComponentRequirement, InstalledFile, KernelRange, LicenseRecord,
    NativeProvider, PackageManager, PciId, PlatformSelector, Profile, ProfileStatus,
    RedistributionVerdict,
};
use thiserror::Error;

use crate::source_lock;

/// Failure to validate candidate inputs or publish a new profile.
#[derive(Debug, Error)]
#[error("FEDORA_PROFILE_INVALID: {0}")]
pub struct FedoraProfileError(String);

fn error(message: impl ToString) -> FedoraProfileError {
    FedoraProfileError(message.to_string())
}

fn require(condition: bool, message: &str) -> Result<(), FedoraProfileError> {
    if condition {
        Ok(())
    } else {
        Err(error(message))
    }
}

/// RPM-owned data retained in the generation evidence.
#[derive(Debug, Clone, Serialize)]
pub struct FileEvidence {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
    pub license: bool,
}

/// Exact RPM identity and all queried file bindings; scripts are always rejected.
#[derive(Debug, Clone, Serialize)]
pub struct PackageEvidence {
    pub filename: String,
    pub name: String,
    pub nevr: String,
    pub arch: String,
    pub sha256: String,
    pub license: String,
    pub source_rpm: String,
    pub files: Vec<FileEvidence>,
    pub requirements: BTreeSet<(String, String, String)>,
}

/// Deterministic evidence printed separately from the generated profile.
#[derive(Debug, Serialize)]
pub struct CandidateEvidence {
    pub status: &'static str,
    pub profile_sha256: String,
    pub source_lock_sha256: String,
    pub packages: Vec<PackageEvidence>,
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_file(path: &Path) -> Result<String, FedoraProfileError> {
    let mut file = File::open(path).map_err(error)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let length = file.read(&mut buffer).map_err(error)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn query(path: &Path, arguments: &[&str]) -> Result<String, FedoraProfileError> {
    let mut args = vec![OsString::from("--noplugins"), OsString::from("-qp")];
    args.extend(arguments.iter().map(|argument| OsString::from(*argument)));
    args.push(path.as_os_str().to_owned());
    let result = SystemProcessRunner
        .run(&ProcessRequest {
            executable: "/usr/bin/rpm".into(),
            args,
            timeout: Duration::from_secs(15),
            stdout_limit: 4_194_304,
            stderr_limit: 65_536,
            environment: vec![("PATH".into(), "/usr/bin:/bin".into())],
        })
        .map_err(error)?;
    require(
        result.termination == Termination::Exit(0)
            && !result.stdout_overflow
            && !result.stderr_overflow,
        "bounded RPM query failed",
    )?;
    String::from_utf8(result.stdout).map_err(error)
}

fn parse_json_string(value: &str) -> Result<String, FedoraProfileError> {
    serde_json::from_str(value).map_err(error)
}

fn expected_packages() -> BTreeMap<String, (String, String)> {
    let mut packages = BTreeMap::new();
    for name in [
        "openvino",
        "openvino-plugins",
        "intel-npu-compiler",
        "libopenvino-ir-frontend",
        "libopenvino-onnx-frontend",
        "libopenvino-paddle-frontend",
        "libopenvino-pytorch-frontend",
        "libopenvino-tensorflow-frontend",
        "libopenvino-tensorflow-lite-frontend",
    ] {
        packages.insert(
            name.to_owned(),
            ("0:2026.2.0-2.intelnpu.fc44".to_owned(), "x86_64".to_owned()),
        );
    }
    for (name, nevr, arch) in [
        ("intel-npu-driver", "0:1.38.0-1.intelnpu.fc44", "x86_64"),
        (
            "intel-npu-stack-firmware",
            "0:1.38.0-1.intelnpu.fc44",
            "noarch",
        ),
        ("oneapi-level-zero", "0:1.32.0-1.intelnpu.fc44", "x86_64"),
        ("intel-npu-stack", "0:0.1.0-2.intelnpu.fc44", "noarch"),
        ("intel-npu-stack-tools", "0:0.1.0-2.intelnpu.fc44", "x86_64"),
    ] {
        packages.insert(name.to_owned(), (nevr.to_owned(), arch.to_owned()));
    }
    packages
}

fn expected_license(name: &str) -> &'static str {
    match name {
        "intel-npu-stack" => "Apache-2.0",
        "intel-npu-stack-tools" => {
            "Apache-2.0 AND Artistic-2.0 AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0 AND Unicode-3.0 AND (Apache-2.0 WITH LLVM-exception)"
        }
        "intel-npu-compiler" => {
            "Apache-2.0 AND MIT AND BSL-1.0 AND HPND AND BSD-3-Clause AND (GPL-2.0-only OR BSD-3-Clause) AND (Apache-2.0 WITH LLVM-exception) AND NCSA AND BSD-2-Clause AND ISC AND Spencer-94 AND Unicode-DFS-2015 AND LicenseRef-LLVM-MD5"
        }
        "intel-npu-driver" => "MIT AND Apache-2.0 AND (GPL-2.0-only WITH Linux-syscall-note)",
        "intel-npu-stack-firmware" => "LicenseRef-Intel-firmware",
        "oneapi-level-zero" => "MIT",
        _ => {
            "Apache-2.0 AND MIT AND BSL-1.0 AND HPND AND BSD-3-Clause AND (GPL-2.0-only OR BSD-3-Clause)"
        }
    }
}

fn required_payload(name: &str) -> Vec<String> {
    let files: &[&str] = match name {
        "intel-npu-stack" => &[],
        "intel-npu-stack-tools" => &[
            "/usr/bin/intel-npu-stack",
            "/usr/libexec/intel-npu-stack/intel-npu-level-zero-probe",
            "/usr/libexec/intel-npu-stack/intel-npu-openvino-probe",
            "/usr/share/intel-npu-stack/installed-manifest.toml",
        ],
        "intel-npu-driver" => &["/usr/lib64/libze_intel_npu.so.1.38.0"],
        "intel-npu-stack-firmware" => &["/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin"],
        "oneapi-level-zero" => &[
            "/usr/lib64/libze_loader.so.1.32.0",
            "/usr/lib64/libze_tracing_layer.so.1.32.0",
            "/usr/lib64/libze_validation_layer.so.1.32.0",
        ],
        "openvino" => &[
            "/usr/lib64/libopenvino.so.2026.2.0",
            "/usr/lib64/libopenvino_c.so.2026.2.0",
        ],
        "intel-npu-compiler" => &[
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_compiler.so",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_compiler_loader.so",
        ],
        "openvino-plugins" => &[
            "/usr/lib64/openvino-2026.2.0/cache.json",
            "/usr/lib64/openvino-2026.2.0/libopenvino_auto_plugin.so",
            "/usr/lib64/openvino-2026.2.0/libopenvino_hetero_plugin.so",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_cpu_plugin.so",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_gpu_plugin.so",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so",
        ],
        _ => return vec![format!("/usr/lib64/{}.so.2026.2.0", name.replace('-', "_"))],
    };
    files.iter().map(|file| (*file).to_owned()).collect()
}

fn inspect(path: &Path) -> Result<PackageEvidence, FedoraProfileError> {
    let metadata = fs::symlink_metadata(path).map_err(error)?;
    require(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1_073_741_824,
        "RPM must be a regular file no larger than 1 GiB",
    )?;
    let sha256 = digest_file(path)?;
    let identity = query(
        path,
        &[
            "--queryformat",
            "%{NAME}\n%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{ARCH}\n%{LICENSE}\n%{FILEDIGESTALGO}\n",
        ],
    )?;
    let identity = identity.lines().collect::<Vec<_>>();
    require(
        identity.len() == 5 && identity[4] == "8",
        "RPM identity or digest algorithm",
    )?;
    let expected = expected_packages();
    let (nevr, arch) = expected
        .get(identity[0])
        .ok_or_else(|| error("unexpected RPM provider"))?;
    require(
        nevr == identity[1] && arch == identity[2],
        "wrong provider version/release/architecture",
    )?;
    require(
        identity[3] == expected_license(identity[0]),
        "package license differs from reviewed provider policy",
    )?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| error("invalid RPM filename"))?;
    require(
        filename
            == format!(
                "{}-{}.{}.rpm",
                identity[0],
                nevr.trim_start_matches("0:"),
                arch
            ),
        "RPM filename does not match identity",
    )?;
    for flag in ["--scripts", "--triggers", "--filetriggers"] {
        require(
            query(path, &[flag])?.trim().is_empty(),
            "script-bearing RPM rejected",
        )?;
    }
    let mut requirements = BTreeSet::new();
    for line in query(
        path,
        &[
            "--queryformat",
            "[%{REQUIRENAME:json}\t%{REQUIREFLAGS:depflags}\t%{REQUIREVERSION:json}\n]",
        ],
    )?
    .lines()
    {
        let parts = line.split('\t').collect::<Vec<_>>();
        require(parts.len() == 3, "invalid RPM requirement record")?;
        let name = parse_json_string(parts[0])?;
        require(
            name != "rpmlib(ShortCircuited)",
            "short-circuit RPM rejected",
        )?;
        let version = if parts[2] == "(none)" {
            String::new()
        } else {
            parse_json_string(parts[2])?
        };
        requirements.insert((name, parts[1].to_owned(), version));
    }
    let mut files = Vec::new();
    for line in query(
        path,
        &[
            "--queryformat",
            "[%{FILENAMES:json}\t%{FILEMODES:octal}\t%{FILEDIGESTS:json}\t%{FILEFLAGS:fflags}\n]",
        ],
    )?
    .lines()
    {
        let parts = line.split('\t').collect::<Vec<_>>();
        require(parts.len() == 4, "invalid RPM file record")?;
        let name = parse_json_string(parts[0])?;
        require(
            name.starts_with("/usr/")
                && !name.contains("//")
                && !name.contains("/./")
                && !name.ends_with('/')
                && !name.chars().any(char::is_control)
                && !Path::new(&name)
                    .components()
                    .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
            "unsafe RPM file path",
        )?;
        let mode = u32::from_str_radix(parts[1], 8).map_err(error)?;
        require(mode & 0o7000 == 0, "special permission bits rejected")?;
        let kind = mode & 0o170000;
        require(
            [0o040000, 0o100000, 0o120000].contains(&kind),
            "special RPM file type rejected",
        )?;
        let digest = parse_json_string(parts[2])?;
        if kind == 0o100000 {
            require(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "regular file digest required",
            )?;
        }
        if kind != 0o040000 {
            files.push(FileEvidence {
                path: name,
                sha256: digest,
                mode,
                license: parts[3].contains('l'),
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    require(
        identity[0] != "intel-npu-stack" || files.is_empty(),
        "metapackage must own no files",
    )?;
    let source_rpm = query(path, &["--queryformat", "%{SOURCERPM}"])?;
    require(
        source_rpm.ends_with(".src.rpm")
            && !source_rpm.contains('/')
            && !source_rpm.chars().any(char::is_whitespace),
        "source RPM identity required",
    )?;
    require(
        sha256 == digest_file(path)?,
        "RPM changed during inspection",
    )?;
    Ok(PackageEvidence {
        filename: filename.to_owned(),
        name: identity[0].to_owned(),
        nevr: nevr.clone(),
        arch: arch.clone(),
        sha256,
        license: identity[3].to_owned(),
        source_rpm,
        files,
        requirements,
    })
}

fn license_provider<'a>(
    package: &'a PackageEvidence,
    packages: &'a BTreeMap<String, PackageEvidence>,
) -> Result<&'a PackageEvidence, FedoraProfileError> {
    let owns_license = |p: &PackageEvidence| {
        p.files
            .iter()
            .any(|file| file.license && file.mode & 0o170000 == 0o100000)
    };
    if owns_license(package) {
        return Ok(package);
    }
    let owner = &packages["openvino"];
    let shared_family =
        package.name == "openvino-plugins" || package.name.starts_with("libopenvino-");
    let relationship = (
        "openvino(x86-64)".to_owned(),
        "=".to_owned(),
        "2026.2.0-2.intelnpu.fc44".to_owned(),
    );
    require(
        shared_family
            && owns_license(owner)
            && package.source_rpm == owner.source_rpm
            && package.license == owner.license
            && package.requirements.contains(&relationship),
        &format!(
            "{} has no bound package-owned license evidence",
            package.name
        ),
    )?;
    Ok(owner)
}

/// Generate only a candidate, atomically publishing a new profile without overwrite.
///
/// The input directory must contain exactly the fourteen runtime RPMs. Source
/// license records are validated locally; RPM scripts are queried but never run.
/// The returned evidence must be saved separately from the source archive.
///
/// # Errors
/// Returns an error for invalid inputs, unknown providers, changed RPMs, bounded
/// query failures, invalid profile data, or an existing/unwritable output path.
pub fn generate_candidate(
    rpms: &Path,
    repository: &Path,
    output: &Path,
) -> Result<CandidateEvidence, FedoraProfileError> {
    require(
        fs::symlink_metadata(output).is_err(),
        "output already exists",
    )?;
    let rpms = fs::canonicalize(rpms).map_err(error)?;
    let parent = fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .map_err(error)?;
    require(
        !parent.starts_with(&rpms),
        "output must be outside RPM inputs",
    )?;
    let lock_path = repository.join("packaging/fedora/44/provider-sources.toml");
    let lock = source_lock::validate(&lock_path, repository).map_err(error)?;
    require(
        lock.target.distribution_id == "fedora"
            && lock.target.version_id == "44"
            && lock.target.architecture == "x86_64"
            && lock.target.pci_vendor == "8086"
            && lock.target.pci_device == "643e",
        "source lock target mismatch",
    )?;
    let source_lock_sha256 = digest_file(&lock_path)?;
    let mut packages = BTreeMap::new();
    let entries = fs::read_dir(&rpms)
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    require(
        entries.len() == 14,
        "exactly fourteen runtime RPMs required",
    )?;
    let mut owned = BTreeSet::new();
    for entry in entries {
        let package = inspect(&entry.path())?;
        for file in &package.files {
            require(
                owned.insert(file.path.clone()),
                "cross-package file overlap",
            )?;
        }
        require(!packages.contains_key(&package.name), "duplicate provider")?;
        packages.insert(package.name.clone(), package);
    }
    require(
        packages.keys().eq(expected_packages().keys()),
        "incomplete runtime provider set",
    )?;
    for package in packages.values() {
        if package.name != "intel-npu-stack" {
            license_provider(package, &packages)?;
        }
        for required in required_payload(&package.name) {
            require(
                package
                    .files
                    .iter()
                    .any(|file| file.path == required && file.mode & 0o170000 == 0o100000),
                "required provider payload missing",
            )?;
        }
        for (name, operator, version) in &package.requirements {
            if let Some(provider) = packages.get(name.strip_suffix("(x86-64)").unwrap_or(name)) {
                require(
                    operator == "="
                        && version.trim_start_matches("0:")
                            == provider.nevr.trim_start_matches("0:"),
                    "contradictory or unpinned internal provider requirement",
                )?;
            }
        }
    }
    for (name, dependencies) in [
        (
            "intel-npu-stack",
            &[
                "intel-npu-stack-tools",
                "intel-npu-driver",
                "intel-npu-stack-firmware",
                "oneapi-level-zero",
                "openvino",
                "openvino-plugins",
                "intel-npu-compiler",
            ][..],
        ),
        (
            "intel-npu-stack-tools",
            &["oneapi-level-zero", "openvino"][..],
        ),
    ] {
        for dependency in dependencies {
            let p = &packages[*dependency];
            let dep_name = format!(
                "{}{}",
                p.name,
                if p.arch == "x86_64" { "(x86-64)" } else { "" }
            );
            let relation = (
                dep_name,
                "=".to_owned(),
                p.nevr.trim_start_matches("0:").to_owned(),
            );
            require(
                packages[name].requirements.contains(&relation),
                "exact provider requirement missing",
            )?;
        }
    }
    for executable in [
        "/usr/bin/intel-npu-stack",
        "/usr/libexec/intel-npu-stack/intel-npu-level-zero-probe",
        "/usr/libexec/intel-npu-stack/intel-npu-openvino-probe",
    ] {
        require(
            packages["intel-npu-stack-tools"]
                .files
                .iter()
                .any(|f| f.path == executable && f.mode == 0o100755),
            "tools executable path/mode mismatch",
        )?;
    }
    require(
        packages["intel-npu-stack-tools"].files.iter().any(|f| {
            f.path == "/usr/share/intel-npu-stack/installed-manifest.toml"
                && f.mode & 0o170000 == 0o100000
        }),
        "installed manifest missing",
    )?;
    let matrix = [
        (
            "npu_firmware",
            "intel-npu-stack-firmware",
            "linux-npu-driver",
            "/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin",
        ),
        (
            "level_zero_loader",
            "oneapi-level-zero",
            "level-zero",
            "/usr/lib64/libze_loader.so.1.32.0",
        ),
        (
            "npu_userspace_driver",
            "intel-npu-driver",
            "linux-npu-driver",
            "/usr/lib64/libze_intel_npu.so.1.38.0",
        ),
        (
            "npu_compiler",
            "intel-npu-compiler",
            "npu-compiler",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_compiler.so",
        ),
        (
            "openvino_runtime",
            "openvino",
            "openvino",
            "/usr/lib64/libopenvino.so.2026.2.0",
        ),
        (
            "openvino_npu_plugin",
            "openvino-plugins",
            "openvino",
            "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so",
        ),
    ];
    let mut components = BTreeMap::new();
    for (capability, name, source_name, mandatory) in matrix {
        let package = &packages[name];
        let source = lock
            .sources
            .iter()
            .find(|s| s.name == source_name)
            .ok_or_else(|| error("component source missing"))?;
        let files = package
            .files
            .iter()
            .filter(|f| {
                f.mode & 0o170000 == 0o100000
                    && (f.path.starts_with("/usr/lib64/")
                        || f.path.starts_with("/usr/lib/firmware/"))
            })
            .map(|f| InstalledFile {
                path: f.path.clone(),
                sha256: f.sha256.clone(),
            })
            .collect::<Vec<_>>();
        require(
            files.iter().any(|f| f.path == mandatory),
            "critical component file missing",
        )?;
        let license_owner = license_provider(package, &packages)?;
        let license_files = license_owner
            .files
            .iter()
            .filter(|f| f.license)
            .collect::<Vec<_>>();
        let license_record = serde_json::to_vec(&(
            &source_lock_sha256,
            &package.sha256,
            &package.license,
            &license_owner.name,
            &license_owner.sha256,
            &license_files,
        ))
        .map_err(error)?;
        components.insert(
            capability.to_owned(),
            ComponentRequirement {
                version: package
                    .nevr
                    .split(':')
                    .nth(1)
                    .unwrap_or("")
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                source: source.url.clone(),
                sha256: package.sha256.clone(),
                provider: NativeProvider {
                    package: name.to_owned(),
                    version: package.nevr.clone(),
                    activation: if capability == "npu_firmware" {
                        ActivationRequirement::Reboot
                    } else {
                        ActivationRequirement::Immediate
                    },
                    files,
                },
                license: LicenseRecord {
                    expression: package.license.clone(),
                    redistribution: RedistributionVerdict::Allowed,
                    evidence_sha256: digest_bytes(&license_record),
                },
            },
        );
    }
    let profile = Profile {
        schema_version: 1,
        id: "fedora-44-lunar-lake-x86_64".to_owned(),
        stack_release: "0.1.0".to_owned(),
        status: ProfileStatus::Candidate,
        package_manager: PackageManager::Rpm,
        conflicts: Vec::new(),
        platform: PlatformSelector {
            id: "fedora".to_owned(),
            version_id: "44".to_owned(),
            arch: "x86_64".to_owned(),
        },
        hardware: vec![PciId {
            vendor: "8086".to_owned(),
            device: "643e".to_owned(),
        }],
        // Initial unqualified test target, observed on the Fedora laptop. This
        // narrow bound is not evidence that any kernel is supported.
        kernel: KernelRange {
            min: "7.1.13".to_owned(),
            max_exclusive: "7.1.14".to_owned(),
            module: "intel_vpu".to_owned(),
        },
        components,
        qualification: None,
    };
    let body = format!(
        "# SPDX-License-Identifier: Apache-2.0\n# Generated candidate; no channel may select it.\n# source_lock_sha256 = {source_lock_sha256}\n{}",
        toml::to_string_pretty(&profile).map_err(error)?
    );
    Profile::parse_toml(&body).map_err(error)?;
    let evidence = CandidateEvidence {
        status: "candidate",
        profile_sha256: digest_bytes(body.as_bytes()),
        source_lock_sha256,
        packages: packages.into_values().collect(),
    };
    let mut draft = tempfile::NamedTempFile::new_in(&parent).map_err(error)?;
    draft.write_all(body.as_bytes()).map_err(error)?;
    draft.as_file().sync_all().map_err(error)?;
    draft.persist_noclobber(output).map_err(error)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(error)?;
    Ok(evidence)
}
