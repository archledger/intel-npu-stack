// SPDX-License-Identifier: Apache-2.0

use crate::{InstallError, ReleasePackage, manifest::validate_package};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Inputs to the download-only native solver. The caller must authenticate the
/// configuration, repository metadata and release package list independently.
/// Its output is untrusted until NativePlan and the RPM verifiers accept it.
#[derive(Debug)]
pub struct DnfPlanningRequest<'a> {
    pub configuration: &'a Path,
    pub transaction: &'a Path,
    pub packages: &'a [&'a ReleasePackage],
}

/// Successful native planning diagnostics. The private directory is removed
/// on drop; keep it explicitly when a subsequent verification fails.
#[derive(Debug)]
pub struct DnfPlanningOutput {
    directory: PlanningDirectory,
}

/// Private workspace ownership: a native runner's temporary directory, or a
/// library-test adopted directory with equivalent cleanup semantics.
#[derive(Debug)]
enum PlanningDirectory {
    Native(tempfile::TempDir),
    Adopted(AdoptedDirectory),
}

/// Removes an adopted workspace when dropped, unless it was kept.
#[derive(Debug)]
struct AdoptedDirectory {
    path: Option<PathBuf>,
}

impl AdoptedDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
}

impl Drop for AdoptedDirectory {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl PlanningDirectory {
    fn path(&self) -> &Path {
        match self {
            PlanningDirectory::Native(directory) => directory.path(),
            PlanningDirectory::Adopted(adopted) => adopted.path.as_deref().unwrap(),
        }
    }

    fn keep(self) -> PathBuf {
        match self {
            PlanningDirectory::Native(directory) => directory.keep(),
            PlanningDirectory::Adopted(mut adopted) => adopted.path.take().unwrap(),
        }
    }
}

impl DnfPlanningOutput {
    pub fn diagnostics(&self) -> &Path {
        self.directory.path()
    }

    pub fn preserve(self) -> PathBuf {
        self.directory.keep()
    }

    /// Adopts an existing private workspace as a planning result. This is the
    /// library test injection boundary for a fabricated native result;
    /// production only ever uses `plan_downloads`.
    pub fn adopt(path: PathBuf) -> Self {
        Self {
            directory: PlanningDirectory::Adopted(AdoptedDirectory::new(path)),
        }
    }
}

/// Native failure with retained local diagnostic files. These files may contain
/// repository/package details; they are private and must not be uploaded by
/// default. None means workspace creation failed before a command was started.
#[derive(Debug, thiserror::Error)]
#[error("{error}; native exit: {status:?}; diagnostics: {diagnostics:?}")]
pub struct DnfPlanningFailure {
    pub error: InstallError,
    pub status: Option<i32>,
    pub diagnostics: Option<PathBuf>,
}

/// Runs only the fixed native download-only planning command. No sudo, replay,
/// installed-state mutation or approval receipt is created here. This runner
/// must never be reused to enforce a deadline on a mutating RPM transaction.
pub fn plan_downloads(
    request: &DnfPlanningRequest<'_>,
) -> Result<DnfPlanningOutput, DnfPlanningFailure> {
    let directory = workspace()?;
    let args =
        planning_arguments(request, directory.path()).map_err(|error| DnfPlanningFailure {
            error,
            status: None,
            diagnostics: None,
        })?;
    run_in(
        Path::new("/usr/bin/dnf5"),
        &args,
        directory,
        Duration::from_secs(1_800),
        64 * 1_048_576,
    )
}

fn planning_arguments(
    request: &DnfPlanningRequest<'_>,
    workspace: &Path,
) -> Result<Vec<OsString>, InstallError> {
    let invalid = |detail: &'static str| InstallError::integrity(detail);
    for path in [request.configuration, request.transaction] {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(invalid("planning paths must be absolute and normalized"));
        }
    }
    let metadata = fs::symlink_metadata(request.configuration)
        .map_err(|_| invalid("planning configuration is missing"))?;
    if !metadata.is_file() || metadata.len() > 1_048_576 {
        return Err(invalid(
            "planning configuration is not one bounded regular file",
        ));
    }
    if fs::canonicalize(request.configuration)
        .map_err(|_| invalid("planning configuration is missing"))?
        != request.configuration
    {
        return Err(invalid("planning configuration path is not canonical"));
    }
    if !matches!(fs::symlink_metadata(request.transaction), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(invalid("planning transaction output already exists"));
    }
    let parent = request
        .transaction
        .parent()
        .ok_or_else(|| invalid("planning transaction path has no parent"))?;
    if fs::canonicalize(parent).map_err(|_| invalid("planning transaction parent is missing"))?
        != parent
    {
        return Err(invalid("planning transaction parent is not canonical"));
    }
    if request.packages.is_empty() || request.packages.len() > 128 {
        return Err(invalid("planning package list is empty or oversized"));
    }
    let mut names = BTreeSet::new();
    for package in request.packages {
        validate_package(package)?;
        if !names.insert(&package.name) {
            return Err(invalid("planning package list contains duplicates"));
        }
    }
    let option_path = |prefix: &str, path: &Path| {
        let mut result = OsString::from(prefix);
        result.push(path);
        result
    };
    let mut args = vec![
        "--no-plugins".into(),
        option_path("--config=", request.configuration),
        option_path("--setopt=cachedir=", &workspace.join("cache")),
        option_path("--setopt=reposdir=", &workspace.join("repos")),
        "--setopt=gpgcheck=True".into(),
        "--setopt=localpkg_gpgcheck=True".into(),
        "--setopt=install_weak_deps=False".into(),
        "--assumeyes".into(),
        "install".into(),
        "--downloadonly".into(),
        option_path("--store=", request.transaction),
        "--no-allow-downgrade".into(),
    ];
    args.extend(request.packages.iter().map(|package| {
        format!(
            "{}-{}.{}",
            package.name,
            package.nevr.strip_prefix("0:").unwrap_or(&package.nevr),
            package.arch
        )
        .into()
    }));
    Ok(args)
}

fn workspace() -> Result<tempfile::TempDir, DnfPlanningFailure> {
    tempfile::Builder::new()
        .prefix("intel-npu-dnf-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| failure("INSTALL_NATIVE_IO_FAILED", None, None))
}

fn failure(
    code: &'static str,
    status: Option<i32>,
    directory: Option<tempfile::TempDir>,
) -> DnfPlanningFailure {
    DnfPlanningFailure {
        error: InstallError {
            exit_code: 30,
            code,
            message: "native planning failed; inspect the retained diagnostics",
        },
        status,
        diagnostics: directory.map(tempfile::TempDir::keep),
    }
}

fn run_in(
    executable: &Path,
    args: &[OsString],
    directory: tempfile::TempDir,
    timeout: Duration,
    output_limit: u64,
) -> Result<DnfPlanningOutput, DnfPlanningFailure> {
    // Direct files avoid pipe deadlocks and retain native stderr, including on
    // timeout or a reader's failure. Output limits are observed between polls;
    // they are a refusal threshold, not a hard filesystem allocation quota.
    let prepare = || -> std::io::Result<(File, File)> {
        for child in ["home", "repos", "cache", "config"] {
            fs::create_dir(directory.path().join(child))?;
        }
        let open = |name| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join(name))
        };
        Ok((open("stdout.log")?, open("stderr.log")?))
    };
    let (stdout, stderr) = match prepare() {
        Ok(files) => files,
        Err(_) => return Err(failure("INSTALL_NATIVE_IO_FAILED", None, Some(directory))),
    };
    let child = Command::new(executable)
        .args(args)
        .current_dir(directory.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", directory.path().join("home"))
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(_) => {
            return Err(failure(
                "INSTALL_NATIVE_SPAWN_FAILED",
                None,
                Some(directory),
            ));
        }
    };
    let started = Instant::now();
    loop {
        let status = child.try_wait();
        let sizes = ["stdout.log", "stderr.log"]
            .map(|name| fs::metadata(directory.path().join(name)).map(|m| m.len()));
        let error = if sizes.iter().any(Result::is_err) || status.is_err() {
            Some("INSTALL_NATIVE_IO_FAILED")
        } else if sizes
            .iter()
            .any(|size| matches!(size, Ok(n) if *n > output_limit))
        {
            Some("INSTALL_NATIVE_OUTPUT_LIMIT")
        } else if matches!(status, Ok(Some(s)) if !s.success()) {
            Some("INSTALL_NATIVE_FAILED")
        } else if matches!(status, Ok(None)) && started.elapsed() >= timeout {
            Some("INSTALL_NATIVE_TIMEOUT")
        } else {
            None
        };
        if let Some(code) = error {
            let exit = match status {
                Ok(Some(status)) => status.code(),
                _ => {
                    let _ = child.kill();
                    child.wait().ok().and_then(|s| s.code())
                }
            };
            return Err(failure(code, exit, Some(directory)));
        }
        if matches!(status, Ok(Some(_))) {
            return Ok(DnfPlanningOutput {
                directory: PlanningDirectory::Native(directory),
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
fn run_logged(
    executable: &Path,
    args: &[OsString],
    timeout: Duration,
    limit: u64,
) -> Result<DnfPlanningOutput, DnfPlanningFailure> {
    run_in(executable, args, workspace()?, timeout, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    fn fixture(script: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native-fixture");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (dir, path)
    }

    #[test]
    fn native_failure_retains_both_streams_and_exit_after_result_drop() {
        let (_fixture, executable) =
            fixture("printf 'planned output'; printf 'native failure' >&2; exit 42");
        let failure = run_logged(&executable, &[], Duration::from_secs(3), 1024).unwrap_err();
        assert_eq!(failure.error.code, "INSTALL_NATIVE_FAILED");
        assert_eq!(failure.status, Some(42));
        let path = failure.diagnostics.clone().unwrap();
        drop(failure);
        assert_eq!(
            fs::read(path.join("stdout.log")).unwrap(),
            b"planned output"
        );
        assert_eq!(
            fs::read(path.join("stderr.log")).unwrap(),
            b"native failure"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path.join("stderr.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn planning_deadline_preserves_diagnostics() {
        let (_fixture, executable) = fixture("printf 'before timeout' >&2; exec /usr/bin/sleep 5");
        let start = std::time::Instant::now();
        let failure = run_logged(&executable, &[], Duration::from_millis(100), 1024).unwrap_err();
        assert_eq!(failure.error.code, "INSTALL_NATIVE_TIMEOUT");
        assert!(start.elapsed() < Duration::from_secs(3));
        let path = failure.diagnostics.unwrap();
        assert_eq!(
            fs::read(path.join("stderr.log")).unwrap(),
            b"before timeout"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn spawn_failure_retains_a_diagnostic_directory() {
        let failure = run_logged(
            std::path::Path::new("/missing/native-tool"),
            &[],
            Duration::from_secs(3),
            1024,
        )
        .unwrap_err();
        assert_eq!(failure.error.code, "INSTALL_NATIVE_SPAWN_FAILED");
        let path = failure.diagnostics.unwrap();
        assert!(path.join("stderr.log").is_file());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn native_success_keeps_logs_until_the_owner_is_dropped() {
        let (_fixture, executable) = fixture("printf 'native output'; printf 'native warning' >&2");
        let result = run_logged(&executable, &[], Duration::from_secs(3), 1024).unwrap();
        let path = result.diagnostics().to_owned();
        assert_eq!(fs::read(path.join("stdout.log")).unwrap(), b"native output");
        assert_eq!(
            fs::read(path.join("stderr.log")).unwrap(),
            b"native warning"
        );
        drop(result);
        assert!(!path.exists());
    }

    #[test]
    fn excessive_planning_output_is_a_failure_even_if_native_exit_is_success() {
        let (_fixture, executable) = fixture("printf '123456789' >&2");
        let failure = run_logged(&executable, &[], Duration::from_secs(3), 8).unwrap_err();
        assert_eq!(failure.error.code, "INSTALL_NATIVE_OUTPUT_LIMIT");
        let path = failure.diagnostics.unwrap();
        assert_eq!(fs::read(path.join("stderr.log")).unwrap(), b"123456789");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn planning_passes_exact_package_arguments_and_cannot_select_a_mutating_command() {
        let root = tempfile::tempdir().unwrap();
        let manifest =
            crate::ReleaseManifest::parse_json(include_bytes!("../tests/fixtures/release.json"))
                .unwrap();
        let packages = manifest.selected_packages(false, false).unwrap();
        let config = root.path().join("repo config.ini");
        fs::write(&config, b"[main]\n").unwrap();
        let request = DnfPlanningRequest {
            configuration: &config,
            transaction: &root.path().join("transaction"),
            packages: &packages,
        };
        let args = planning_arguments(&request, root.path()).unwrap();
        assert!(args.iter().any(|a| a == "--downloadonly"));
        assert!(args.iter().any(|a| a == "--no-allow-downgrade"));
        assert!(args.iter().any(|a| a == "--no-plugins"));
        assert!(args.iter().any(|a| a == "--setopt=localpkg_gpgcheck=True"));
        assert!(args.iter().any(|a| a == "--setopt=gpgcheck=True"));
        assert!(args.iter().any(|a| a == "install"));
        assert!(
            args.iter()
                .any(|a| a == "intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch")
        );
        assert!(!args.iter().any(|a| a == "replay" || a == "--nogpgcheck"));
        let config_arg = std::ffi::OsString::from(format!("--config={}", config.display()));
        assert!(args.contains(&config_arg));
    }

    #[test]
    fn malformed_package_or_existing_store_is_refused_before_native_execution() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("repo.ini");
        fs::write(&config, b"[main]\n").unwrap();
        let manifest =
            crate::ReleaseManifest::parse_json(include_bytes!("../tests/fixtures/release.json"))
                .unwrap();
        let mut package = manifest.selected_packages(false, false).unwrap()[0].clone();
        package.name = "--nogpgcheck".into();
        let transaction = root.path().join("transaction");
        let request = DnfPlanningRequest {
            configuration: &config,
            transaction: &transaction,
            packages: &[&package],
        };
        assert!(planning_arguments(&request, root.path()).is_err());
        fs::create_dir(&transaction).unwrap();
        let packages = manifest.selected_packages(false, false).unwrap();
        let request = DnfPlanningRequest {
            configuration: &config,
            transaction: &transaction,
            packages: &packages,
        };
        assert!(planning_arguments(&request, root.path()).is_err());
    }
}
