// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};

use crate::{
    ApprovedPlan, DnfPlanningFailure, DnfPlanningOutput, DnfPlanningRequest, FedoraRpm,
    InstallError, NativeInventory, NativePlan, ProjectRpmTrust, ReleaseManifest, ReleasePackage,
};

const MAX_REPOSITORY_BYTES: u64 = 1_048_576;
const MAX_BOUND_BYTES: u64 = 8 * MAX_REPOSITORY_BYTES;
// Fedora's compressed primary metadata exceeds the configuration-file bound.
// Hash it as a stream, retaining an explicit per-file bound through replay.
const MAX_REPODATA_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRANSACTION_BYTES: usize = 8_388_608;
const FEDORA_KEY_TEMPLATE: &str =
    "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch";

/// One verified native replay invocation boundary. Production inherits the
/// controlling terminal so native password prompts and diagnostics reach the
/// user; no output capture or deadline may kill a mutating transaction.
pub trait ReplayExecutor: Send + Sync {
    fn run(&self, argv: &[OsString]) -> std::io::Result<ReplayStatus>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStatus {
    Exit(i32),
    Signal,
}

/// Executes the fixed privileged replay with inherited standard streams.
pub struct SystemReplayExecutor;

impl ReplayExecutor for SystemReplayExecutor {
    fn run(&self, argv: &[OsString]) -> std::io::Result<ReplayStatus> {
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        match command.status()? {
            status if status.success() => Ok(ReplayStatus::Exit(0)),
            status => Ok(status
                .code()
                .map_or(ReplayStatus::Signal, ReplayStatus::Exit)),
        }
    }
}

/// One native download-only planning boundary. Production always uses the
/// fixed `plan_downloads` runner; injection exists for library tests only.
pub trait NativePlanner: Send + Sync {
    fn plan(
        &self,
        request: &DnfPlanningRequest<'_>,
    ) -> Result<DnfPlanningOutput, DnfPlanningFailure>;
}

/// The production planner: the fixed native download-only runner.
pub struct SystemNativePlanner;

impl NativePlanner for SystemNativePlanner {
    fn plan(
        &self,
        request: &DnfPlanningRequest<'_>,
    ) -> Result<DnfPlanningOutput, DnfPlanningFailure> {
        crate::dnf::plan_downloads(request)
    }
}

/// A failed replay with its native exit, when one exists. Callers must call
/// `PreparedTransaction::preserve` to retain the private tree diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("{error}; native exit: {status:?}")]
pub struct ReplayFailure {
    pub error: InstallError,
    pub status: Option<i32>,
}

/// A failed composition with retained private diagnostics, when a tree exists.
#[derive(Debug, thiserror::Error)]
#[error("{error}; diagnostics: {diagnostics:?}")]
pub struct PrepareFailure {
    pub error: InstallError,
    pub diagnostics: Option<PathBuf>,
}

/// Independently verified Fedora system repository configuration.
///
/// Both repository files and the distribution public key must be native
/// package owned and unmodified, and their content must match Fedora 44's
/// captured metalink and GPG semantics. Their digests stay bound until replay.
#[derive(Debug)]
pub struct FedoraSources {
    releasever: String,
    gpgkey: String,
    repositories: BTreeMap<String, FedoraRepository>,
    digests: Vec<(PathBuf, String)>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

#[derive(Debug)]
struct FedoraRepository {
    name: String,
    metalink: String,
}

impl FedoraSources {
    /// Verifies the distribution repository sources under a configuration
    /// root; production uses `/etc`. Fixture roots serve library tests only.
    pub fn verify_at(
        etc: &Path,
        releasever: &str,
        basearch: &str,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, InstallError> {
        let unverified = || {
            InstallError::metadata("Fedora repository configuration is not a verified system file")
        };
        if !releasever.bytes().all(|b| b.is_ascii_digit())
            || releasever.is_empty()
            || releasever.len() > 4
            || basearch != "x86_64"
            || !etc.is_absolute()
        {
            return Err(unverified());
        }
        let files = [
            etc.join("yum.repos.d/fedora.repo"),
            etc.join("yum.repos.d/fedora-updates.repo"),
            etc.join(format!(
                "pki/rpm-gpg/RPM-GPG-KEY-fedora-{releasever}-{basearch}"
            )),
        ];
        let mut digests = Vec::new();
        let mut symlinks = Vec::new();
        for file in &files {
            // Fedora ships the arch key as a same-directory symlink to the
            // primary key owned by fedora-gpg-keys; the link must stay inside
            // its own directory and resolve to one bounded regular file.
            let resolved = if fs::symlink_metadata(file)
                .map_err(|_| unverified())?
                .file_type()
                .is_symlink()
            {
                let parent = file.parent().ok_or_else(unverified)?;
                let target = fs::read_link(file).map_err(|_| unverified())?;
                if target.is_absolute() {
                    return Err(unverified());
                }
                let joined = parent.join(&target);
                let canonical = joined.canonicalize().map_err(|_| unverified())?;
                if canonical.parent() != parent.canonicalize().ok().as_deref() {
                    return Err(unverified());
                }
                symlinks.push((file.clone(), target));
                canonical
            } else {
                file.clone()
            };
            let metadata = fs::symlink_metadata(&resolved).map_err(|_| unverified())?;
            if !metadata.is_file() || metadata.len() > MAX_REPOSITORY_BYTES {
                return Err(unverified());
            }
            digests.push((resolved.clone(), digest_file(&resolved)?));
        }
        // One ownership and one verification query cover every input file, in
        // the same argv shape as the captured native probes.
        for (probe, expect_empty) in [("-qf", false), ("-Vf", true)] {
            let mut args = macro_arguments();
            args.push(probe.into());
            args.extend(files.iter().map(|file| file.as_os_str().into()));
            let output = runner
                .run(&ProcessRequest {
                    executable: "/usr/bin/rpm".into(),
                    args,
                    timeout: Duration::from_secs(10),
                    stdout_limit: 4096,
                    stderr_limit: 4096,
                    environment: Vec::new(),
                })
                .map_err(|_| unverified())?;
            if output.termination != Termination::Exit(0)
                || output.stdout_overflow
                || output.stderr_overflow
                || output.stdout.is_empty() != expect_empty
            {
                return Err(unverified());
            }
        }
        let mut sources = Self {
            releasever: releasever.to_owned(),
            gpgkey: FEDORA_KEY_TEMPLATE
                .replace("$releasever", releasever)
                .replace("$basearch", basearch),
            repositories: BTreeMap::new(),
            digests,
            symlinks,
        };
        let base = sources.parse_repository(&files[0].clone(), "fedora")?;
        let updates = sources.parse_repository(&files[1].clone(), "updates")?;
        if !base || !updates {
            return Err(unverified());
        }
        Ok(sources)
    }

    fn repository_ids(&self) -> Vec<String> {
        self.repositories.keys().cloned().collect()
    }

    /// Parses one repository file, storing its enabled base repository.
    fn parse_repository(&mut self, file: &Path, expected_id: &str) -> Result<bool, InstallError> {
        let invalid =
            || InstallError::metadata("unexpected Fedora repository configuration content");
        let text = fs::read_to_string(file).map_err(|_| invalid())?;
        let mut stanzas: Vec<(String, Vec<(String, String)>)> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut found_base = false;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(id) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                if !seen.insert(id.to_owned())
                    || !["fedora", "updates"].contains(&id)
                        && !id.starts_with("fedora-")
                        && !id.starts_with("updates-")
                {
                    return Err(invalid());
                }
                stanzas.push((id.to_owned(), Vec::new()));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(invalid());
            };
            let Some(stanza) = stanzas.last_mut() else {
                return Err(invalid());
            };
            if !stanza.1.iter().all(|(existing, _)| existing != key)
                || ![
                    "name",
                    "metalink",
                    "enabled",
                    "countme",
                    "metadata_expire",
                    "repo_gpgcheck",
                    "type",
                    "gpgcheck",
                    "gpgkey",
                    "skip_if_unavailable",
                ]
                .contains(&key)
                || value.is_empty()
                || value.contains(['\n', '\r', '[', ']'])
                || value.bytes().any(|b| b.is_ascii_control())
            {
                return Err(invalid());
            }
            stanza.1.push((key.to_owned(), value.to_owned()));
        }
        for (id, directives) in stanzas {
            let value = |key: &str| {
                directives
                    .iter()
                    .find(|(existing, _)| existing == key)
                    .map(|(_, v)| v.as_str())
            };
            if !["fedora", "updates"].contains(&id.as_str()) {
                if value("enabled").is_none_or(|v| v != "0") {
                    return Err(invalid());
                }
                continue;
            }
            if value("enabled").is_none_or(|v| v != "1")
                || value("gpgcheck").is_none_or(|v| v != "1")
                || value("repo_gpgcheck").is_none_or(|v| v != "0")
                || value("skip_if_unavailable").is_none_or(|v| v != "False")
                || value("gpgkey").is_none_or(|v| v != FEDORA_KEY_TEMPLATE)
            {
                return Err(invalid());
            }
            let substitute = |text: &str| {
                let substituted = text
                    .replace("$releasever", &self.releasever)
                    .replace("$basearch", "x86_64");
                if substituted.contains('$') {
                    Err(invalid())
                } else {
                    Ok(substituted)
                }
            };
            let metalink = substitute(value("metalink").ok_or_else(invalid)?)?;
            let pinned = format!(
                "https://mirrors.fedoraproject.org/metalink?repo={}&arch=x86_64",
                if id == "fedora" {
                    format!("fedora-{}", self.releasever)
                } else {
                    format!("updates-released-f{}", self.releasever)
                }
            );
            if metalink != pinned || id != expected_id || found_base {
                return Err(invalid());
            }
            self.repositories.insert(
                id.clone(),
                FedoraRepository {
                    name: substitute(value("name").ok_or_else(invalid)?)?,
                    metalink,
                },
            );
            found_base = true;
        }
        Ok(found_base)
    }
}

/// Everything one preparation needs. The manifest is already authenticated by
/// the verified release transport; the key and fingerprint come from that same
/// independent trust, never from downloaded metadata.
pub struct PrepareInput<'a> {
    pub manifest: &'a ReleaseManifest,
    pub project_key: &'a [u8],
    pub primary_fingerprint: &'a str,
    pub packages: &'a [&'a ReleasePackage],
    pub fedora: Option<&'a FedoraSources>,
}

/// One private owner of an exact, fully verified installation transaction.
///
/// It joins the authenticated release identity, the project RPM trust, the
/// reviewed Fedora repository configuration, the native plan/download result
/// and the replay assets under one mode-0700 tree. Replay consumes the review
/// receipt for this exact plan after every recorded byte is rechecked.
#[derive(Debug)]
pub struct PreparedTransaction {
    directory: tempfile::TempDir,
    trust: ProjectRpmTrust,
    planning: DnfPlanningOutput,
    primary_fingerprint: String,
    plan: NativePlan,
    bound: Vec<(PathBuf, String, u64)>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

impl PreparedTransaction {
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    pub fn plan(&self) -> &NativePlan {
        &self.plan
    }

    /// Retained native planning logs and the private solver workspace.
    pub fn planning_diagnostics(&self) -> &Path {
        self.planning.diagnostics()
    }

    /// Rechecks every recorded configuration, key and metadata digest, the
    /// exact stored transaction bytes and RPM contents, every signature and
    /// the observed installed state. Native DNF still owns locking; this is a
    /// read-only precondition, not an atomic guarantee.
    pub fn verify_bound(&self, runner: &dyn ProcessRunner) -> Result<(), InstallError> {
        verify_symlinks(&self.symlinks)?;
        for (path, expected, limit) in &self.bound {
            let metadata = fs::symlink_metadata(path).map_err(|_| integrity())?;
            if !metadata.is_file() || metadata.len() > *limit {
                return Err(integrity());
            }
            if digest_file_with_limit(path, *limit)? != *expected {
                return Err(integrity());
            }
        }
        let store = self.directory.path().join("store");
        self.plan.verify_stored(&store, runner)?;
        self.plan.verify_signatures(&store, &self.trust, runner)?;
        Ok(())
    }

    /// The exact privileged argv sequence `execute_replay` dispatches, for
    /// display and audit. The release key import precedes replay because
    /// native replay verifies stored package signatures only against the
    /// system RPM database; the repository `gpgkey` does not reach it.
    pub fn replay_steps(&self) -> Vec<Vec<OsString>> {
        vec![self.key_import_argv(), self.replay_argv()]
    }

    /// Fixed privileged release-key import of the bound public key.
    fn key_import_argv(&self) -> Vec<OsString> {
        [
            "/usr/bin/sudo".to_owned(),
            "--set-home".to_owned(),
            "--".to_owned(),
            "/usr/bin/rpmkeys".to_owned(),
            "--import".to_owned(),
            format!("{}/public.asc", self.directory.path().display()),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    /// The exact privileged argv of the native replay itself.
    pub fn replay_argv(&self) -> Vec<OsString> {
        let tree = self.directory.path();
        [
            "/usr/bin/sudo".to_owned(),
            "--set-home".to_owned(),
            "--".to_owned(),
            "/usr/bin/dnf5".to_owned(),
            "--no-plugins".to_owned(),
            format!("--config={}/replay.ini", tree.display()),
            format!("--setopt=reposdir={}/repos", tree.display()),
            "--setopt=localpkg_gpgcheck=True".to_owned(),
            "--setopt=install_weak_deps=False".to_owned(),
            "--assumeyes".to_owned(),
            "replay".to_owned(),
            format!("{}/store", tree.display()),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    /// Replays the reviewed exact transaction. The receipt must reference this
    /// prepared plan; every bound byte, signature and the installed state are
    /// rechecked first. The executor keeps the controlling terminal and no
    /// deadline may interrupt a mutating native transaction.
    pub fn execute_replay(
        &self,
        approval: &ApprovedPlan<'_>,
        runner: &dyn ProcessRunner,
        executor: &dyn ReplayExecutor,
    ) -> Result<(), ReplayFailure> {
        let refused = |error: InstallError| ReplayFailure {
            error,
            status: None,
        };
        if !std::ptr::eq(approval.plan(), &self.plan) {
            return Err(refused(InstallError {
                exit_code: 30,
                code: "INSTALL_PLAN_RECEIPT_MISMATCH",
                message: "the approval receipt belongs to a different prepared transaction",
            }));
        }
        if self.plan.is_empty() {
            return Err(refused(InstallError {
                exit_code: 30,
                code: "INSTALL_NOTHING_TO_REPLAY",
                message: "an exact no-op has no native transaction to replay",
            }));
        }
        self.verify_bound(runner).map_err(refused)?;
        let import_failed = |status: Option<i32>| ReplayFailure {
            error: InstallError {
                exit_code: 30,
                code: "INSTALL_KEY_IMPORT_FAILED",
                message: "the release public key could not be installed into the native database",
            },
            status,
        };
        match executor.run(&self.key_import_argv()) {
            Ok(ReplayStatus::Exit(0)) => {}
            Ok(ReplayStatus::Exit(code)) => return Err(import_failed(Some(code))),
            Ok(ReplayStatus::Signal) => return Err(import_failed(None)),
            Err(_) => return Err(import_failed(None)),
        }
        self.verify_imported_key(runner)
            .map_err(|_| import_failed(None))?;
        let failed = || InstallError {
            exit_code: 30,
            code: "INSTALL_REPLAY_FAILED",
            message: "the native replay did not complete; native output was preserved",
        };
        match executor.run(&self.replay_argv()) {
            Ok(ReplayStatus::Exit(0)) => Ok(()),
            Ok(ReplayStatus::Exit(code)) => Err(ReplayFailure {
                error: failed(),
                status: Some(code),
            }),
            Ok(ReplayStatus::Signal) => Err(ReplayFailure {
                error: failed(),
                status: None,
            }),
            Err(_) => Err(refused(InstallError {
                exit_code: 30,
                code: "INSTALL_REPLAY_SPAWN_FAILED",
                message: "the privileged native replay could not be started",
            })),
        }
    }

    /// Keeps the private tree for diagnostics; the planning workspace and the
    /// temporary project trust database are cleaned up by this move.
    pub fn preserve(self) -> PathBuf {
        self.directory.keep()
    }

    /// Confirms the bound release key is present in the observed system RPM
    /// database after the fixed import. Read-only; native RPM owns the state.
    fn verify_imported_key(&self, runner: &dyn ProcessRunner) -> Result<(), InstallError> {
        let mut args = macro_arguments();
        for argument in ["-qa", "gpg-pubkey", "--qf", "%{VERSION}\n"] {
            args.push(argument.into());
        }
        let output = runner
            .run(&ProcessRequest {
                executable: "/usr/bin/rpm".into(),
                args,
                timeout: Duration::from_secs(10),
                stdout_limit: 65_536,
                stderr_limit: 65_536,
                environment: Vec::new(),
            })
            .map_err(|_| integrity())?;
        if output.termination != Termination::Exit(0)
            || output.stdout_overflow
            || output.stderr_overflow
        {
            return Err(integrity());
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|_| integrity())?;
        if !text.lines().any(|line| line == self.primary_fingerprint) {
            return Err(integrity());
        }
        Ok(())
    }
}

/// Prepared parts before the tree ownership is attached.
struct Prepared {
    trust: ProjectRpmTrust,
    planning: DnfPlanningOutput,
    primary_fingerprint: String,
    plan: NativePlan,
    bound: Vec<(PathBuf, String, u64)>,
    symlinks: Vec<(PathBuf, PathBuf)>,
}

/// Prepares the transaction with the production native planner.
pub fn prepare(
    input: &PrepareInput<'_>,
    runner: &dyn ProcessRunner,
) -> Result<PreparedTransaction, PrepareFailure> {
    prepare_with(input, &SystemNativePlanner, runner)
}

/// Prepares the transaction with an injected planning boundary.
pub fn prepare_with(
    input: &PrepareInput<'_>,
    planner: &dyn NativePlanner,
    runner: &dyn ProcessRunner,
) -> Result<PreparedTransaction, PrepareFailure> {
    let directory = tempfile::Builder::new()
        .prefix("intel-npu-prepare-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| PrepareFailure {
            error: InstallError::integrity("cannot create the private preparation tree"),
            diagnostics: None,
        })?;
    match compose(input, planner, runner, directory.path()) {
        Ok(prepared) => Ok(PreparedTransaction {
            directory,
            trust: prepared.trust,
            planning: prepared.planning,
            primary_fingerprint: prepared.primary_fingerprint,
            plan: prepared.plan,
            bound: prepared.bound,
            symlinks: prepared.symlinks,
        }),
        Err(error) => Err(PrepareFailure {
            error,
            diagnostics: Some(directory.keep()),
        }),
    }
}

fn compose(
    input: &PrepareInput<'_>,
    planner: &dyn NativePlanner,
    runner: &dyn ProcessRunner,
    tree: &Path,
) -> Result<Prepared, InstallError> {
    let io = || InstallError::integrity("the private preparation tree could not be written");
    if input.packages.is_empty() || input.packages.len() > 128 {
        return Err(InstallError::metadata("invalid release selection"));
    }
    let repository = input.manifest.repository();
    let repository_id = repository.id.clone();
    let mut expected_repositories = vec![repository_id.clone()];
    if let Some(fedora) = input.fedora {
        verify_symlinks(&fedora.symlinks)?;
        for (path, expected) in &fedora.digests {
            if digest_file(path)? != *expected {
                return Err(InstallError::metadata(
                    "Fedora repository configuration changed after verification",
                ));
            }
        }
        let ids = fedora.repository_ids();
        if ids.iter().any(|id| *id == repository_id) {
            return Err(InstallError::metadata(
                "the release repository identity collides with a Fedora repository",
            ));
        }
        expected_repositories.extend(ids);
    }
    let trust =
        ProjectRpmTrust::from_armored_key(input.project_key, input.primary_fingerprint, runner)?;
    for child in ["repos", "replay-repos"] {
        fs::create_dir(tree.join(child)).map_err(|_| io())?;
    }
    let public = tree.join("public.asc");
    let planning_config = tree.join("planning.ini");
    let replay_config = tree.join("replay.ini");
    let store = tree.join("store");
    fs::write(&public, input.project_key).map_err(|_| io())?;
    set_private(&public).map_err(|_| io())?;
    fs::write(&planning_config, render_config(input, tree, true)?).map_err(|_| io())?;
    set_private(&planning_config).map_err(|_| io())?;
    let inventory = NativeInventory::query(runner)?;
    let planning = planner
        .plan(&DnfPlanningRequest {
            configuration: &planning_config,
            transaction: &store,
            packages: input.packages,
        })
        .map_err(|dnf| dnf.error)?;
    let mut bound = vec![
        (public.clone(), digest_file(&public)?, MAX_BOUND_BYTES),
        (
            planning_config.clone(),
            digest_file(&planning_config)?,
            MAX_BOUND_BYTES,
        ),
    ];
    if let Some(fedora) = input.fedora {
        bound.extend(
            fedora
                .digests
                .iter()
                .map(|(path, digest)| (path.clone(), digest.clone(), MAX_REPOSITORY_BYTES)),
        );
    }
    let bytes = match fs::read(store.join("transaction.json")) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(InstallError::integrity(
                "the stored native transaction is unreadable",
            ));
        }
    };
    let dependencies = match &bytes {
        Some(bytes) => discover_dependencies(bytes, input, &store, runner)?,
        None => Vec::new(),
    };
    let plan = NativePlan::parse_with_dependencies(
        bytes.as_deref(),
        input.packages,
        &dependencies,
        &inventory,
        &repository_id,
        runner,
    )?;
    plan.verify_signatures(&store, &trust, runner)?;
    bind_cache_and_snapshot(
        &planning,
        &expected_repositories,
        &repository_id,
        &repository.repomd_sha256,
        tree,
    )
    .map(|snapshot_digests| bound.extend(snapshot_digests))?;
    fs::write(&replay_config, render_config(input, tree, false)?).map_err(|_| io())?;
    set_private(&replay_config).map_err(|_| io())?;
    bound.push((
        replay_config.clone(),
        digest_file(&replay_config)?,
        MAX_BOUND_BYTES,
    ));
    Ok(Prepared {
        trust,
        planning,
        primary_fingerprint: input.primary_fingerprint.to_ascii_lowercase(),
        plan,
        bound,
        symlinks: input
            .fedora
            .map_or_else(Vec::new, |fedora| fedora.symlinks.clone()),
    })
}

/// Binds the private native cache to the configured repositories and freezes
/// the used metadata into private replay repositories, signed bytes intact.
fn bind_cache_and_snapshot(
    planning: &DnfPlanningOutput,
    expected_repositories: &[String],
    repository_id: &str,
    release_repomd: &str,
    tree: &Path,
) -> Result<Vec<(PathBuf, String, u64)>, InstallError> {
    let invalid = || InstallError::integrity("the native planning cache is unusable");
    let cache = planning.diagnostics().join("cache");
    if !fs::symlink_metadata(&cache)
        .map_err(|_| invalid())?
        .is_dir()
    {
        return Err(invalid());
    }
    let mut cache_ids: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in fs::read_dir(&cache).map_err(|_| invalid())? {
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name().into_string().map_err(|_| invalid())?;
        let Some((_, suffix)) = name.rsplit_once('-') else {
            return Err(invalid());
        };
        let Some(matched) = expected_repositories
            .iter()
            .find(|id| name.starts_with(&format!("{}-", id)))
        else {
            return Err(InstallError::integrity(
                "the native planning cache holds an unexpected repository",
            ));
        };
        if suffix.len() != 16
            || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
            || !entry.file_type().map_err(|_| invalid())?.is_dir()
            || cache_ids.insert(matched.clone(), entry.path()).is_some()
        {
            return Err(InstallError::integrity(
                "the native planning cache holds an unexpected repository",
            ));
        }
    }
    let mut bound = Vec::new();
    for id in expected_repositories {
        let repodata = cache_ids
            .get(id)
            .ok_or_else(|| {
                InstallError::integrity("the native planning cache is missing a repository")
            })?
            .join("repodata");
        let repomd = repodata.join("repomd.xml");
        if !fs::symlink_metadata(&repomd)
            .map_err(|_| invalid())?
            .is_file()
        {
            return Err(InstallError::integrity(
                "cached repository metadata is missing",
            ));
        }
        let digest = digest_file(&repomd)?;
        if *id == repository_id {
            if digest != release_repomd {
                return Err(InstallError::integrity(
                    "cached project repository metadata does not match the release",
                ));
            }
            if !fs::symlink_metadata(repodata.join("repomd.xml.asc"))
                .map_err(|_| invalid())?
                .is_file()
            {
                return Err(InstallError::integrity(
                    "the signed project repository metadata signature is missing",
                ));
            }
        }
        let snapshot = tree.join("replay-repos").join(id).join("repodata");
        fs::create_dir_all(&snapshot).map_err(|_| invalid())?;
        for entry in fs::read_dir(&repodata).map_err(|_| invalid())? {
            let entry = entry.map_err(|_| invalid())?;
            if !entry.file_type().map_err(|_| invalid())?.is_file() {
                return Err(InstallError::integrity(
                    "cached repository metadata holds an unsafe entry",
                ));
            }
            let target = snapshot.join(entry.file_name());
            if entry.metadata().map_err(|_| invalid())?.len() > MAX_REPODATA_BYTES {
                return Err(invalid());
            }
            fs::copy(entry.path(), &target).map_err(|_| invalid())?;
            set_private(&target).map_err(|_| invalid())?;
            bound.push((
                target.clone(),
                digest_file_with_limit(&target, MAX_REPODATA_BYTES)?,
                MAX_REPODATA_BYTES,
            ));
        }
    }
    Ok(bound)
}

/// Renders the exact planning or replay configuration. Planning uses the
/// authenticated release URL and Fedora metalinks; replay uses only private
/// file:// snapshots of the metadata planning actually consumed.
fn render_config(
    input: &PrepareInput<'_>,
    tree: &Path,
    planning: bool,
) -> Result<String, InstallError> {
    let invalid = || InstallError::metadata("release repository identity cannot be rendered");
    let repository = input.manifest.repository();
    let scalar = |value: &str| {
        if value.is_empty()
            || value
                .bytes()
                .any(|b| b.is_ascii_control() || matches!(b, b'[' | b']' | b'$'))
        {
            Err(invalid())
        } else {
            Ok(())
        }
    };
    scalar(&repository.id)?;
    scalar(&repository.base_url)?;
    let project_url = if planning {
        repository.base_url.clone()
    } else {
        format!("file://{}/replay-repos/{}/", tree.display(), repository.id)
    };
    let mut config = String::from("[main]\n");
    config.push_str(&format!(
        "[{}]\nname=Intel NPU Stack {} repository\nbaseurl={project_url}\n\
         gpgkey=file://{}/public.asc\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ncost=100\n",
        repository.id,
        input.manifest.stack_release(),
        tree.display()
    ));
    if let Some(fedora) = input.fedora {
        for (id, repo) in &fedora.repositories {
            let location = if planning {
                format!("metalink={}", repo.metalink)
            } else {
                format!("baseurl=file://{}/replay-repos/{}/", tree.display(), id)
            };
            config.push_str(&format!(
                "[{id}]\nname={}\n{location}\ngpgkey={}\n\
                 enabled=1\ngpgcheck=1\nrepo_gpgcheck=0\nskip_if_unavailable=False\n",
                repo.name, fedora.gpgkey
            ));
        }
    }
    Ok(config)
}

/// Binds every stored solver row that is not a project input to a verified
/// Fedora dependency. A successful authenticated native download plus its
/// captured digest establishes repository-checked bytes; signature and
/// identity are then verified independently through the pinned Fedora key.
fn discover_dependencies(
    bytes: &[u8],
    input: &PrepareInput<'_>,
    store: &Path,
    runner: &dyn ProcessRunner,
) -> Result<Vec<FedoraRpm>, InstallError> {
    let invalid = || InstallError::integrity("the stored native transaction holds an unusable row");
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(invalid());
    }
    let document: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let rows = document["rpms"].as_array().ok_or_else(invalid)?;
    let mut allowed = BTreeSet::from(["fedora", "updates"]);
    allowed.insert(input.manifest.repository().id.as_str());
    let mut dependencies = Vec::new();
    for row in rows {
        if row["action"].as_str() == Some("Replaced") {
            continue;
        }
        let repository = row["repo_id"]
            .as_str()
            .and_then(|id| id.strip_prefix("@stored_transaction("))
            .and_then(|id| id.strip_suffix(')'))
            .ok_or_else(invalid)?;
        let nevra = row["nevra"].as_str().ok_or_else(invalid)?;
        let project = input.packages.iter().any(|package| {
            *nevra
                == format!(
                    "{}-{}.{}",
                    package.name,
                    package.nevr.strip_prefix("0:").unwrap_or(&package.nevr),
                    package.arch
                )
        });
        let known = allowed.contains(repository);
        if project {
            if repository != "@commandline" && !known {
                return Err(invalid());
            }
            continue;
        }
        if !known || repository == "@commandline" {
            return Err(invalid());
        }
        let filename = row["package_path"]
            .as_str()
            .and_then(|path| path.strip_prefix("./packages/"))
            .ok_or_else(invalid)?;
        if filename.contains('/')
            || !filename.ends_with(".rpm")
            || filename.len() > 512
            || !filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+~^".contains(&b))
        {
            return Err(invalid());
        }
        let package = store.join("packages").join(filename);
        let digest = digest_file(&package)?;
        dependencies.push(FedoraRpm::verify(&package, &digest, runner)?);
    }
    Ok(dependencies)
}

fn macro_arguments() -> Vec<OsString> {
    vec![
        "--macros".into(),
        "/usr/lib/rpm/macros".into(),
        "--noplugins".into(),
        "--dbpath".into(),
        "/usr/lib/sysimage/rpm".into(),
    ]
}

fn set_private(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn digest_file(path: &Path) -> Result<String, InstallError> {
    digest_file_with_limit(path, MAX_BOUND_BYTES)
}

// Preserve the distribution's verified link layout independently from the
// bounded regular target bytes. Retargeting even to identical bytes refuses.
fn verify_symlinks(symlinks: &[(PathBuf, PathBuf)]) -> Result<(), InstallError> {
    for (path, target) in symlinks {
        if fs::read_link(path).map_err(|_| integrity())? != *target {
            return Err(integrity());
        }
    }
    Ok(())
}

fn digest_file_with_limit(path: &Path, limit: u64) -> Result<String, InstallError> {
    let file = fs::File::open(path).map_err(|_| integrity())?;
    let mut input = file.take(limit + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut size = 0_u64;
    loop {
        let count = input.read(&mut buffer).map_err(|_| integrity())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hash.update(&buffer[..count]);
    }
    if size > limit {
        return Err(integrity());
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn integrity() -> InstallError {
    InstallError::integrity("bound installer inputs no longer match their recorded content")
}
