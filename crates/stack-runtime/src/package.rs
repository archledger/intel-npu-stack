// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stack_core::{CheckStatus, DiagnosticCheck, Requirement};
use stack_schema::{PackageManager, Profile};

use crate::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};

const PACKAGE_FORMAT: &str = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n";
const OWNER_FORMAT: &str = "%{NAME}\n";
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const STDOUT_LIMIT: usize = 65_536;
const STDERR_LIMIT: usize = 16_384;
const MAX_CRITICAL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub install_time: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackageInspection {
    pub checks: Vec<DiagnosticCheck>,
    pub packages: BTreeMap<String, InstalledPackage>,
}

pub trait PackageInspector: Send + Sync {
    fn inspect(&self, profile: &Profile) -> PackageInspection;
}

pub struct RpmPackageInspector<'a> {
    rpm_executable: PathBuf,
    root: PathBuf,
    runner: &'a dyn ProcessRunner,
}

impl<'a> RpmPackageInspector<'a> {
    #[must_use]
    pub fn new(
        rpm_executable: impl Into<PathBuf>,
        root: impl Into<PathBuf>,
        runner: &'a dyn ProcessRunner,
    ) -> Self {
        Self {
            rpm_executable: rpm_executable.into(),
            root: root.into(),
            runner,
        }
    }

    fn request(&self, args: Vec<OsString>) -> Result<ProcessOutput, ProcessError> {
        self.runner.run(&ProcessRequest {
            executable: self.rpm_executable.clone(),
            args,
            timeout: QUERY_TIMEOUT,
            stdout_limit: STDOUT_LIMIT,
            stderr_limit: STDERR_LIMIT,
        })
    }

    fn query_package(&self, package: &str) -> PackageQuery {
        let result = self.request(vec![
            OsString::from("-q"),
            OsString::from("--qf"),
            OsString::from(PACKAGE_FORMAT),
            OsString::from("--"),
            OsString::from(package),
        ]);
        let output = match result {
            Ok(output) => output,
            Err(ProcessError::Timeout) => return PackageQuery::Failed("RPM_QUERY_TIMEOUT"),
            Err(_) => return PackageQuery::Failed("RPM_QUERY_FAILED"),
        };
        if output.stdout_overflow || output.stderr_overflow {
            return PackageQuery::Failed("RPM_OUTPUT_LIMIT");
        }
        match output.termination {
            Termination::Exit(1) if output.stdout.is_empty() => PackageQuery::Missing,
            Termination::Exit(0) => parse_package_output(&output.stdout, package)
                .map(PackageQuery::Present)
                .unwrap_or(PackageQuery::Failed("RPM_OUTPUT_INVALID")),
            Termination::Exit(_) | Termination::Signal => PackageQuery::Failed("RPM_QUERY_FAILED"),
        }
    }

    fn query_owner(&self, path: &str) -> Result<String, &'static str> {
        let result = self.request(vec![
            OsString::from("-qf"),
            OsString::from("--qf"),
            OsString::from(OWNER_FORMAT),
            OsString::from("--"),
            OsString::from(path),
        ]);
        let output = match result {
            Ok(output) => output,
            Err(ProcessError::Timeout) => return Err("RPM_QUERY_TIMEOUT"),
            Err(_) => return Err("RPM_QUERY_FAILED"),
        };
        if output.stdout_overflow || output.stderr_overflow {
            return Err("RPM_OUTPUT_LIMIT");
        }
        if output.termination != Termination::Exit(0) {
            return Err("FILE_OWNERSHIP_QUERY_FAILED");
        }
        parse_owner_output(&output.stdout).ok_or("RPM_OUTPUT_INVALID")
    }

    fn inspect_file(&self, path: &str) -> FileObservation {
        let relative = match Path::new(path).strip_prefix("/") {
            Ok(relative) => relative,
            Err(_) => return FileObservation::Failed("FILE_PATH_INVALID"),
        };
        hash_regular_file(&self.root.join(relative))
    }
}

impl PackageInspector for RpmPackageInspector<'_> {
    fn inspect(&self, profile: &Profile) -> PackageInspection {
        if profile.package_manager != PackageManager::Rpm {
            return PackageInspection {
                checks: vec![check(
                    "provider.package_manager",
                    CheckStatus::Blocked,
                    "native package manager is unsupported",
                    details([
                        ("code", json!("PACKAGE_MANAGER_UNSUPPORTED")),
                        (
                            "package_manager",
                            json!(package_manager_name(profile.package_manager)),
                        ),
                    ]),
                )],
                packages: BTreeMap::new(),
            };
        }

        let package_names = profile
            .components
            .values()
            .map(|component| component.provider.package.as_str())
            .chain(
                profile
                    .conflicts
                    .iter()
                    .map(|conflict| conflict.package.as_str()),
            )
            .collect::<BTreeSet<_>>();
        let queries = package_names
            .into_iter()
            .map(|package| (package.to_owned(), self.query_package(package)))
            .collect::<BTreeMap<_, _>>();
        let packages = queries
            .iter()
            .filter_map(|(name, result)| match result {
                PackageQuery::Present(package) => Some((name.clone(), package.clone())),
                PackageQuery::Missing | PackageQuery::Failed(_) => None,
            })
            .collect::<BTreeMap<_, _>>();

        let mut files = BTreeMap::<String, FileObservation>::new();
        let mut owners = BTreeMap::<String, Result<String, &'static str>>::new();
        let mut checks = Vec::with_capacity(profile.components.len() + profile.conflicts.len());
        for (capability, component) in &profile.components {
            let provider = &component.provider;
            let package = queries
                .get(&provider.package)
                .expect("all validated providers were queried");
            checks.push(match package {
                PackageQuery::Missing => provider_failure(
                    capability,
                    "PACKAGE_MISSING",
                    &provider.package,
                    BTreeMap::new(),
                ),
                PackageQuery::Failed(code) => {
                    provider_failure(capability, code, &provider.package, BTreeMap::new())
                }
                PackageQuery::Present(installed) if installed.version != provider.version => {
                    provider_failure(
                        capability,
                        "PACKAGE_VERSION_MISMATCH",
                        &provider.package,
                        details([
                            ("expected_version", json!(&provider.version)),
                            ("actual_version", json!(&installed.version)),
                        ]),
                    )
                }
                PackageQuery::Present(installed) => inspect_provider_files(
                    self,
                    capability,
                    provider,
                    installed,
                    &mut files,
                    &mut owners,
                ),
            });
        }

        for conflict in &profile.conflicts {
            let id = format!("conflict.{}", conflict.package);
            let query = queries
                .get(&conflict.package)
                .expect("all validated conflicts were queried");
            checks.push(match query {
                PackageQuery::Missing => check(
                    &id,
                    CheckStatus::Pass,
                    "conflicting package is absent",
                    details([
                        ("code", json!("PACKAGE_CONFLICT_ABSENT")),
                        ("package", json!(&conflict.package)),
                    ]),
                ),
                PackageQuery::Present(installed) => check(
                    &id,
                    CheckStatus::Fail,
                    "conflicting package is installed",
                    details([
                        ("code", json!("PACKAGE_CONFLICT_PRESENT")),
                        ("package", json!(&installed.name)),
                        ("actual_version", json!(&installed.version)),
                    ]),
                ),
                PackageQuery::Failed(code) => check(
                    &id,
                    CheckStatus::Fail,
                    "conflicting package state could not be verified",
                    details([("code", json!(code)), ("package", json!(&conflict.package))]),
                ),
            });
        }
        checks.sort_by(|left, right| left.id.cmp(&right.id));

        PackageInspection { checks, packages }
    }
}

#[derive(Debug, Clone)]
enum PackageQuery {
    Present(InstalledPackage),
    Missing,
    Failed(&'static str),
}

#[derive(Debug, Clone)]
enum FileObservation {
    Digest(String),
    Failed(&'static str),
}

fn inspect_provider_files(
    inspector: &RpmPackageInspector<'_>,
    capability: &str,
    provider: &stack_schema::NativeProvider,
    installed: &InstalledPackage,
    files: &mut BTreeMap<String, FileObservation>,
    owners: &mut BTreeMap<String, Result<String, &'static str>>,
) -> DiagnosticCheck {
    for expected_file in &provider.files {
        let observed = files
            .entry(expected_file.path.clone())
            .or_insert_with(|| inspector.inspect_file(&expected_file.path));
        match observed {
            FileObservation::Failed(code) => {
                return provider_failure(
                    capability,
                    code,
                    &provider.package,
                    details([("path", json!(&expected_file.path))]),
                );
            }
            FileObservation::Digest(actual) if actual != &expected_file.sha256 => {
                return provider_failure(
                    capability,
                    "FILE_DIGEST_MISMATCH",
                    &provider.package,
                    details([
                        ("path", json!(&expected_file.path)),
                        ("expected_sha256", json!(&expected_file.sha256)),
                        ("actual_sha256", json!(actual)),
                    ]),
                );
            }
            FileObservation::Digest(_) => {}
        }

        let owner = owners
            .entry(expected_file.path.clone())
            .or_insert_with(|| inspector.query_owner(&expected_file.path));
        match owner {
            Err(code) => {
                return provider_failure(
                    capability,
                    code,
                    &provider.package,
                    details([("path", json!(&expected_file.path))]),
                );
            }
            Ok(actual) if actual != &provider.package => {
                return provider_failure(
                    capability,
                    "FILE_OWNERSHIP_MISMATCH",
                    &provider.package,
                    details([
                        ("path", json!(&expected_file.path)),
                        ("actual_package", json!(actual)),
                    ]),
                );
            }
            Ok(_) => {}
        }
    }

    check(
        &format!("provider.{capability}"),
        CheckStatus::Pass,
        "native provider is verified",
        details([
            ("code", json!("PROVIDER_VERIFIED")),
            ("package", json!(&installed.name)),
            ("version", json!(&installed.version)),
        ]),
    )
}

fn provider_failure(
    capability: &str,
    code: &'static str,
    package: &str,
    extra: BTreeMap<String, Value>,
) -> DiagnosticCheck {
    let mut values = details([("code", json!(code)), ("package", json!(package))]);
    values.extend(extra);
    check(
        &format!("provider.{capability}"),
        CheckStatus::Fail,
        "native provider verification failed",
        values,
    )
}

fn check(
    id: &str,
    status: CheckStatus,
    summary: &str,
    details: BTreeMap<String, Value>,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.to_owned(),
        status,
        summary: summary.to_owned(),
        details,
        requirement: Requirement::Required,
    }
}

fn details<const N: usize>(values: [(&str, Value); N]) -> BTreeMap<String, Value> {
    values
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn parse_package_output(bytes: &[u8], expected_name: &str) -> Option<InstalledPackage> {
    let line = parse_one_line(bytes)?;
    let mut fields = line.split('\t');
    let name = fields.next()?;
    let version = fields.next()?;
    let install_time = fields.next()?;
    if fields.next().is_some()
        || name != expected_name
        || !is_package_name(name)
        || !is_package_version(version)
        || install_time.is_empty()
        || !install_time.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(InstalledPackage {
        name: name.to_owned(),
        version: version.to_owned(),
        install_time: install_time.parse().ok()?,
    })
}

fn parse_owner_output(bytes: &[u8]) -> Option<String> {
    let owner = parse_one_line(bytes)?;
    is_package_name(owner).then(|| owner.to_owned())
}

fn parse_one_line(bytes: &[u8]) -> Option<&str> {
    let line = bytes.strip_suffix(b"\n")?;
    if line.is_empty() || line.contains(&b'\n') || line.contains(&b'\r') {
        return None;
    }
    std::str::from_utf8(line).ok()
}

fn is_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
}

fn is_package_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'+' | b'-' | b'_' | b':' | b'~' | b'^')
        })
}

fn hash_regular_file(path: &Path) -> FileObservation {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return FileObservation::Failed("FILE_UNAVAILABLE"),
    };
    if !before.file_type().is_file() {
        return FileObservation::Failed("FILE_TYPE_INVALID");
    }
    if before.len() > MAX_CRITICAL_FILE_BYTES {
        return FileObservation::Failed("FILE_TOO_LARGE");
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return FileObservation::Failed("FILE_UNAVAILABLE"),
    };
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return FileObservation::Failed("FILE_UNAVAILABLE"),
    };
    let after = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return FileObservation::Failed("FILE_REPLACED"),
    };
    if !after.file_type().is_file()
        || opened.len() > MAX_CRITICAL_FILE_BYTES
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return FileObservation::Failed("FILE_REPLACED");
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(_) => return FileObservation::Failed("FILE_READ_FAILED"),
        }
    }
    FileObservation::Digest(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_: &Metadata, _: &Metadata) -> bool {
    true
}

const fn package_manager_name(manager: PackageManager) -> &'static str {
    match manager {
        PackageManager::Rpm => "rpm",
        PackageManager::Dpkg => "dpkg",
        PackageManager::Pacman => "pacman",
    }
}
