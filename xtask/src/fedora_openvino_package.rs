// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, SystemProcessRunner, Termination};
use thiserror::Error;

const RPM: &str = "/usr/bin/rpm";
const READELF: &str = "/usr/bin/readelf";
const OUTPUT_LIMIT: usize = 8_388_608;
const STDERR_LIMIT: usize = 65_536;
const MAX_RPM_BYTES: u64 = 4_294_967_296;
const MAX_ELF_BYTES: u64 = 2_147_483_648;

const REQUIRED_PACKAGES: [&str; 10] = [
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

const FRONTENDS: [&str; 6] = [
    "libopenvino-ir-frontend",
    "libopenvino-onnx-frontend",
    "libopenvino-paddle-frontend",
    "libopenvino-pytorch-frontend",
    "libopenvino-tensorflow-frontend",
    "libopenvino-tensorflow-lite-frontend",
];

// Plugins/compiler are dlopen modules; runtime and loader are linked libraries.
// Shared-provider upgrades must preserve CPU and GPU acceleration alongside NPU.
const REQUIRED_ELFS: [(&str, &str, &str, bool); 6] = [
    (
        "openvino",
        "/usr/lib64/libopenvino.so.2026.2.0",
        "libopenvino.so.2620",
        true,
    ),
    (
        "openvino-plugins",
        "/usr/lib64/openvino-2026.2.0/libopenvino_intel_cpu_plugin.so",
        "libopenvino_intel_cpu_plugin.so",
        false,
    ),
    (
        "openvino-plugins",
        "/usr/lib64/openvino-2026.2.0/libopenvino_intel_gpu_plugin.so",
        "libopenvino_intel_gpu_plugin.so",
        false,
    ),
    (
        "openvino-plugins",
        "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_plugin.so",
        "libopenvino_intel_npu_plugin.so",
        false,
    ),
    (
        "intel-npu-compiler",
        "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_compiler.so",
        "libopenvino_intel_npu_compiler.so",
        false,
    ),
    (
        "intel-npu-compiler",
        "/usr/lib64/openvino-2026.2.0/libopenvino_intel_npu_compiler_loader.so",
        "libopenvino_intel_npu_compiler_loader.so",
        true,
    ),
];

/// Explicit candidate RPMs and their already extracted, unprivileged payload root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedoraOpenvinoPackageSet {
    pub packages: Vec<PathBuf>,
    pub payload_root: PathBuf,
}

/// Exact version bindings expected for one Fedora OpenVINO/NPU compiler build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenvinoPackagePolicy {
    pub openvino_nevr: String,
    pub driver_requirement: String,
}

/// Stable failure returned by Fedora OpenVINO package inspection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct FedoraOpenvinoPackageError {
    pub code: String,
    pub message: String,
}

impl FedoraOpenvinoPackageError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct Package {
    name: String,
    nevr: String,
    architecture: String,
    requires: Vec<Relation>,
    files: Vec<RpmFile>,
}

#[derive(Debug)]
struct Relation {
    name: String,
    operator: String,
    version: Option<String>,
}

#[derive(Debug)]
struct RpmFile {
    path: String,
    mode: u32,
    digest: String,
    flags: String,
}

#[derive(Debug)]
struct ElfMetadata {
    soname: Option<String>,
    needed: Vec<String>,
}

/// Validates an extracted Fedora OpenVINO/NPU compiler RPM closure without installing it.
///
/// RPM and ELF metadata are queried through fixed absolute executables, cleared
/// environments, bounded output, and deadlines. The extracted payload must be
/// supplied by an isolated caller and every inspected ELF is rebound to its RPM
/// SHA-256 before `readelf` is invoked.
///
/// # Errors
///
/// Returns a stable error for an unsafe input, incomplete or mismatched package
/// closure, script-bearing or overlapping RPM, unapproved path, payload digest
/// mismatch, malformed ELF, invalid SONAME/RPATH, or unresolved OpenVINO library.
pub fn validate_fedora_openvino_packages(
    candidate: &FedoraOpenvinoPackageSet,
    policy: &OpenvinoPackagePolicy,
) -> Result<(), FedoraOpenvinoPackageError> {
    validate_policy(policy)?;
    let payload_root = require_payload_root(&candidate.payload_root)?;
    if candidate.packages.len() != REQUIRED_PACKAGES.len() {
        return Err(package_set_invalid());
    }

    let mut packages = BTreeMap::new();
    let mut canonical_rpms = BTreeSet::new();
    for path in &candidate.packages {
        let path = require_rpm(path)?;
        if !canonical_rpms.insert(path.clone()) {
            return Err(package_set_invalid());
        }
        let package = query_package(&path)?;
        if packages.insert(package.name.clone(), package).is_some() {
            return Err(package_set_invalid());
        }
        reject_scripts(&path)?;
    }
    if packages.keys().map(String::as_str).collect::<Vec<_>>() != REQUIRED_PACKAGES {
        return Err(package_set_invalid());
    }

    for package in packages.values() {
        if package.nevr != policy.openvino_nevr || package.architecture != "x86_64" {
            return Err(FedoraOpenvinoPackageError::new(
                "FEDORA_OPENVINO_IDENTITY_INVALID",
                "OpenVINO RPM identity, NEVR, or architecture is invalid",
            ));
        }
    }
    validate_relations(&packages, policy)?;
    validate_ownership(&packages)?;
    validate_elf_payloads(&packages, &payload_root)
}

fn validate_policy(policy: &OpenvinoPackagePolicy) -> Result<(), FedoraOpenvinoPackageError> {
    if !safe_scalar(&policy.openvino_nevr)
        || !policy.openvino_nevr.starts_with("0:")
        || !safe_scalar(&policy.driver_requirement)
    {
        return Err(FedoraOpenvinoPackageError::new(
            "FEDORA_OPENVINO_POLICY_INVALID",
            "OpenVINO package policy contains an invalid identity",
        ));
    }
    Ok(())
}

fn validate_relations(
    packages: &BTreeMap<String, Package>,
    policy: &OpenvinoPackagePolicy,
) -> Result<(), FedoraOpenvinoPackageError> {
    let version_release = policy.openvino_nevr.strip_prefix("0:").ok_or_else(|| {
        FedoraOpenvinoPackageError::new(
            "FEDORA_OPENVINO_POLICY_INVALID",
            "OpenVINO NEVR must use an explicit zero epoch",
        )
    })?;
    let openvino = format!("openvino(x86-64) = {version_release}");
    for dependent in REQUIRED_PACKAGES
        .iter()
        .copied()
        .filter(|name| *name != "openvino")
    {
        require_relation(&packages[dependent].requires, &openvino)?;
    }
    for frontend in FRONTENDS {
        require_relation(
            &packages["openvino"].requires,
            &format!("{frontend}(x86-64) = {version_release}"),
        )?;
    }
    require_relation(
        &packages["openvino-plugins"].requires,
        &format!("intel-npu-compiler(x86-64) = {version_release}"),
    )?;
    require_relation(
        &packages["intel-npu-compiler"].requires,
        &policy.driver_requirement,
    )
}

fn validate_ownership(
    packages: &BTreeMap<String, Package>,
) -> Result<(), FedoraOpenvinoPackageError> {
    let mut owners = BTreeMap::new();
    for package in packages.values() {
        for file in &package.files {
            let path = Path::new(&file.path);
            if !file.path.starts_with("/usr/")
                || file.path.starts_with("/opt/")
                || file.path.contains("//")
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(FedoraOpenvinoPackageError::new(
                    "FEDORA_OPENVINO_FILE_INVALID",
                    "OpenVINO RPM owns a path outside the Fedora prefix",
                ));
            }
            if file.mode & 0o170000 == 0o040000 {
                continue;
            }
            if owners.insert(&file.path, &package.name).is_some() {
                return Err(FedoraOpenvinoPackageError::new(
                    "FEDORA_OPENVINO_FILE_OVERLAP",
                    "OpenVINO subpackages own a duplicate non-directory path",
                ));
            }
        }
    }
    if !packages["openvino"]
        .files
        .iter()
        .any(|file| file.path == "/usr/share/licenses/openvino/LICENSE" && file.flags.contains('l'))
    {
        return Err(FedoraOpenvinoPackageError::new(
            "FEDORA_OPENVINO_LICENSE_INVALID",
            "OpenVINO runtime RPM lacks its packaged license",
        ));
    }
    Ok(())
}

fn validate_elf_payloads(
    packages: &BTreeMap<String, Package>,
    payload_root: &Path,
) -> Result<(), FedoraOpenvinoPackageError> {
    let mut candidate_sonames = BTreeSet::new();
    let mut metadata = Vec::new();
    for (owner, path, expected_soname, soname_required) in REQUIRED_ELFS {
        let rpm_file = packages[owner]
            .files
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(elf_invalid)?;
        if rpm_file.digest.is_empty() {
            return Err(elf_invalid());
        }
        let payload = require_payload_file(payload_root, path)?;
        if sha256_file(&payload)? != rpm_file.digest {
            return Err(elf_invalid());
        }
        let elf = query_elf(&payload)?;
        match &elf.soname {
            Some(soname) if soname == expected_soname => {
                candidate_sonames.insert(soname.clone());
            }
            None if !soname_required => {}
            _ => return Err(elf_invalid()),
        }
        metadata.push(elf);
    }
    for elf in metadata {
        for needed in elf.needed {
            if needed.starts_with("libopenvino") && !candidate_sonames.contains(&needed) {
                return Err(FedoraOpenvinoPackageError::new(
                    "FEDORA_OPENVINO_ELF_CLOSURE_INVALID",
                    "OpenVINO ELF has an unresolved candidate-library dependency",
                ));
            }
        }
    }
    Ok(())
}

fn query_package(path: &Path) -> Result<Package, FedoraOpenvinoPackageError> {
    let identity = rpm_query(
        path,
        &[
            "--queryformat",
            "%{NAME:json}\n%{EPOCHNUM}\n%{VERSION:json}\n%{RELEASE:json}\n%{ARCH:json}\n%{FILEDIGESTALGO:hashalgo}\n",
        ],
    )?;
    let lines = text_lines(&identity, 6)?;
    let name = json_string(lines[0])?;
    let epoch = lines[1];
    let version = json_string(lines[2])?;
    let release = json_string(lines[3])?;
    let architecture = json_string(lines[4])?;
    if !epoch.bytes().all(|byte| byte.is_ascii_digit()) || lines[5] != "SHA256" {
        return Err(query_malformed());
    }
    Ok(Package {
        name,
        nevr: format!("{epoch}:{version}-{release}"),
        architecture,
        requires: query_relations(path)?,
        files: query_files(path)?,
    })
}

fn query_relations(path: &Path) -> Result<Vec<Relation>, FedoraOpenvinoPackageError> {
    let output = rpm_query(
        path,
        &[
            "--queryformat",
            "[%{REQUIRENAME:json}\t%{REQUIREFLAGS:depflags}\t%{REQUIREVERSION:json}\n]",
        ],
    )?;
    let text = std::str::from_utf8(&output).map_err(|_| query_malformed())?;
    let mut relations = Vec::new();
    for line in text.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(query_malformed());
        }
        relations.push(Relation {
            name: json_string(fields[0])?,
            operator: fields[1].to_owned(),
            version: json_optional_string(fields[2])?,
        });
    }
    Ok(relations)
}

fn query_files(path: &Path) -> Result<Vec<RpmFile>, FedoraOpenvinoPackageError> {
    let output = rpm_query(
        path,
        &[
            "--queryformat",
            "[%{FILENAMES:json}\t%{FILEMODES:octal}\t%{FILEDIGESTS:json}\t%{FILEFLAGS:fflags}\n]",
        ],
    )?;
    let text = std::str::from_utf8(&output).map_err(|_| query_malformed())?;
    let mut files = Vec::new();
    for line in text.lines() {
        let fields = line.splitn(4, '\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(query_malformed());
        }
        let path = json_string(fields[0])?;
        let digits = fields[1].trim_start_matches('0');
        let mode = u32::from_str_radix(if digits.is_empty() { "0" } else { digits }, 8)
            .map_err(|_| query_malformed())?;
        let digest = json_string(fields[2])?;
        if !path.starts_with('/')
            || path.chars().any(char::is_control)
            || (!digest.is_empty() && !is_lower_hex(&digest, 64))
        {
            return Err(query_malformed());
        }
        files.push(RpmFile {
            path,
            mode,
            digest,
            flags: fields[3].to_owned(),
        });
    }
    Ok(files)
}

fn require_relation(
    relations: &[Relation],
    expected: &str,
) -> Result<(), FedoraOpenvinoPackageError> {
    if relations.iter().any(|relation| {
        relation.version.as_deref().is_some_and(|version| {
            format!("{} {} {}", relation.name, relation.operator, version) == expected
        })
    }) {
        Ok(())
    } else {
        Err(FedoraOpenvinoPackageError::new(
            "FEDORA_OPENVINO_DEPENDENCY_INVALID",
            "OpenVINO package closure lacks an exact required dependency",
        ))
    }
}

fn reject_scripts(path: &Path) -> Result<(), FedoraOpenvinoPackageError> {
    for option in ["--scripts", "--triggers", "--filetriggers"] {
        if !rpm_query(path, &[option])?.is_empty() {
            return Err(FedoraOpenvinoPackageError::new(
                "FEDORA_OPENVINO_SCRIPT_INVALID",
                "OpenVINO provider RPMs must not contain scripts or triggers",
            ));
        }
    }
    Ok(())
}

fn query_elf(path: &Path) -> Result<ElfMetadata, FedoraOpenvinoPackageError> {
    let header = run_readelf(path, &["--file-header"])?;
    let header = std::str::from_utf8(&header).map_err(|_| elf_invalid())?;
    if !header.contains("Class:                             ELF64")
        || !header.contains("Machine:                           Advanced Micro Devices X86-64")
    {
        return Err(elf_invalid());
    }
    if !header.lines().any(|line| {
        line.trim_start()
            .strip_prefix("Type:")
            .is_some_and(|value| value.split_whitespace().next() == Some("DYN"))
    }) {
        return Err(elf_invalid());
    }
    let dynamic = run_readelf(path, &["--dynamic"])?;
    let dynamic = std::str::from_utf8(&dynamic).map_err(|_| elf_invalid())?;
    if dynamic.contains("(RPATH)")
        || dynamic.contains("(RUNPATH)")
        || dynamic.lines().any(|line| {
            line.contains("(FLAGS_1)") && line.split_whitespace().any(|word| word == "PIE")
        })
    {
        return Err(elf_invalid());
    }
    let sections = run_readelf(path, &["--section-headers"])?;
    let sections = std::str::from_utf8(&sections).map_err(|_| elf_invalid())?;
    if sections.contains(".comment") {
        let comment = run_readelf(path, &["--string-dump=.comment"])?;
        let comment = std::str::from_utf8(&comment).map_err(|_| elf_invalid())?;
        if comment.to_ascii_lowercase().contains("ubuntu") {
            return Err(elf_invalid());
        }
    }
    let sonames = dynamic_values(dynamic, "(SONAME)")?;
    if sonames.len() > 1 {
        return Err(elf_invalid());
    }
    Ok(ElfMetadata {
        soname: sonames.into_iter().next(),
        needed: dynamic_values(dynamic, "(NEEDED)")?,
    })
}

fn dynamic_values(dynamic: &str, marker: &str) -> Result<Vec<String>, FedoraOpenvinoPackageError> {
    let mut values = Vec::new();
    for line in dynamic.lines().filter(|line| line.contains(marker)) {
        let start = line.find('[').ok_or_else(elf_invalid)? + 1;
        let end = line[start..].find(']').ok_or_else(elf_invalid)? + start;
        let value = &line[start..end];
        if !safe_scalar(value) || value.contains('/') {
            return Err(elf_invalid());
        }
        values.push(value.to_owned());
    }
    Ok(values)
}

fn require_rpm(path: &Path) -> Result<PathBuf, FedoraOpenvinoPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| package_set_invalid())?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RPM_BYTES
    {
        return Err(package_set_invalid());
    }
    path.canonicalize().map_err(|_| package_set_invalid())
}

fn require_payload_root(path: &Path) -> Result<PathBuf, FedoraOpenvinoPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| elf_invalid())?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(elf_invalid());
    }
    path.canonicalize().map_err(|_| elf_invalid())
}

fn require_payload_file(
    root: &Path,
    rpm_path: &str,
) -> Result<PathBuf, FedoraOpenvinoPackageError> {
    let relative = Path::new(rpm_path)
        .strip_prefix("/")
        .map_err(|_| elf_invalid())?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| elf_invalid())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_ELF_BYTES
    {
        return Err(elf_invalid());
    }
    let canonical = path.canonicalize().map_err(|_| elf_invalid())?;
    if !canonical.starts_with(root) {
        return Err(elf_invalid());
    }
    Ok(canonical)
}

fn sha256_file(path: &Path) -> Result<String, FedoraOpenvinoPackageError> {
    let mut reader = BufReader::new(File::open(path).map_err(|_| elf_invalid())?);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| elf_invalid())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn rpm_query(path: &Path, options: &[&str]) -> Result<Vec<u8>, FedoraOpenvinoPackageError> {
    let mut args = vec![OsString::from("--noplugins"), OsString::from("-qp")];
    args.extend(options.iter().map(OsString::from));
    args.push(path.as_os_str().to_owned());
    run_process(RPM, args, Duration::from_secs(10)).map_err(|_| {
        FedoraOpenvinoPackageError::new("FEDORA_OPENVINO_QUERY_FAILED", "bounded RPM query failed")
    })
}

fn run_readelf(path: &Path, options: &[&str]) -> Result<Vec<u8>, FedoraOpenvinoPackageError> {
    let mut args = options.iter().map(OsString::from).collect::<Vec<_>>();
    args.push(path.as_os_str().to_owned());
    run_process(READELF, args, Duration::from_secs(15)).map_err(|_| elf_invalid())
}

fn run_process(executable: &str, args: Vec<OsString>, timeout: Duration) -> Result<Vec<u8>, ()> {
    let output = SystemProcessRunner
        .run(&ProcessRequest {
            executable: PathBuf::from(executable),
            args,
            timeout,
            stdout_limit: OUTPUT_LIMIT,
            stderr_limit: STDERR_LIMIT,
            environment: Vec::new(),
        })
        .map_err(|_| ())?;
    if output.termination != Termination::Exit(0)
        || output.stdout_overflow
        || output.stderr_overflow
    {
        return Err(());
    }
    Ok(output.stdout)
}

fn text_lines(bytes: &[u8], expected: usize) -> Result<Vec<&str>, FedoraOpenvinoPackageError> {
    let text = std::str::from_utf8(bytes).map_err(|_| query_malformed())?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != expected {
        return Err(query_malformed());
    }
    Ok(lines)
}

fn json_string(value: &str) -> Result<String, FedoraOpenvinoPackageError> {
    serde_json::from_str::<String>(value).map_err(|_| query_malformed())
}

fn json_optional_string(value: &str) -> Result<Option<String>, FedoraOpenvinoPackageError> {
    if value == "(none)" {
        Ok(None)
    } else {
        serde_json::from_str::<Option<String>>(value)
            .map(|value| value.filter(|text| !text.is_empty()))
            .map_err(|_| query_malformed())
    }
}

fn package_set_invalid() -> FedoraOpenvinoPackageError {
    FedoraOpenvinoPackageError::new(
        "FEDORA_OPENVINO_PACKAGE_SET_INVALID",
        "candidate must contain each exact OpenVINO RPM once",
    )
}

fn query_malformed() -> FedoraOpenvinoPackageError {
    FedoraOpenvinoPackageError::new(
        "FEDORA_OPENVINO_QUERY_MALFORMED",
        "RPM query returned malformed metadata",
    )
}

fn elf_invalid() -> FedoraOpenvinoPackageError {
    FedoraOpenvinoPackageError::new(
        "FEDORA_OPENVINO_ELF_INVALID",
        "OpenVINO ELF payload, digest, architecture, or dynamic metadata is invalid",
    )
}

fn safe_scalar(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
