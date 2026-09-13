// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use stack_install::{
    ApprovedPlan, DnfPlanningFailure, DnfPlanningOutput, DnfPlanningRequest, FedoraSources,
    InstallOptions, NativePlanner, PlanReview, PrepareInput, PreparedTransaction, ReleaseManifest,
    ReplayExecutor, ReplayStatus, prepare_with, review_plan,
};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, Termination};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

const FINGERPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FEDORA_FINGERPRINT: &str = "36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6";
const INVENTORY_FORMAT: &str = "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n";
const STATE: &[u8] = b"basesystem|0:16.2.0-1.fc44|noarch|0\n";
const STATE_COMPLETE: &[u8] = b"basesystem|0:16.2.0-1.fc44|noarch|0\n\
intel-npu-stack|0:0.1.0-1.intelnpu.fc44|noarch|10\n\
intel-npu-stack-firmware|0:1.35.0-1.intelnpu.fc44|noarch|10\n\
intel-npu-stack-tools|0:0.1.0-1.intelnpu.fc44|x86_64|10\n";

fn prepare_runner() -> PrepareRunner {
    PrepareRunner {
        inventory: STATE,
        refuse_fedora_signature: false,
        rpmdb_project_key: true,
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prepare")
}

fn identity_for(filename: &str) -> String {
    match filename {
        "intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm" => {
            "intel-npu-stack|0:0.1.0-1.intelnpu.fc44|noarch|0\n"
        }
        "intel-npu-stack-firmware-1.35.0-1.intelnpu.fc44.noarch.rpm" => {
            "intel-npu-stack-firmware|0:1.35.0-1.intelnpu.fc44|noarch|0\n"
        }
        "intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm" => {
            "intel-npu-stack-tools|0:0.1.0-1.intelnpu.fc44|x86_64|0\n"
        }
        "createrepo_c-libs-1.2.0-1.fc44.x86_64.rpm" => {
            "createrepo_c-libs|0:1.2.0-1.fc44|x86_64|0\n"
        }
        "drpm-0.5.3-2.fc44.x86_64.rpm" => "drpm|0:0.5.3-2.fc44|x86_64|0\n",
        other => panic!("unexpected rpm identity query for {other}"),
    }
    .to_owned()
}

fn signature_body(fingerprint: &str) -> String {
    format!(
        "    Header OpenPGP V4 RSA/SHA256 signature, key fingerprint: {fingerprint}: OK\n    \
         Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n"
    )
}

/// Answers every native call the composition makes, in captured output format.
struct PrepareRunner {
    inventory: &'static [u8],
    refuse_fedora_signature: bool,
    rpmdb_project_key: bool,
}

impl ProcessRunner for PrepareRunner {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        assert!(request.environment.is_empty());
        assert!(
            request
                .args
                .windows(2)
                .any(|a| a == ["--macros", "/usr/lib/rpm/macros"])
                || request.executable.to_str() == Some("/usr/bin/rpmkeys")
        );
        let last = request.args.last().unwrap().to_str().unwrap().to_owned();
        let has = |flag: &str| request.args.iter().any(|a| a == flag);
        let query = || {
            request
                .args
                .windows(2)
                .find(|a| a[0] == "--qf")
                .map(|a| a[1].to_str().unwrap().to_owned())
        };
        let stdout = if request.executable.to_str() == Some("/usr/bin/rpmkeys") {
            if has("--import") {
                Vec::new()
            } else if has("--checksig") {
                let project = request.args.iter().any(|a| a == "--dbpath");
                if project {
                    format!("{}:\n{}", last, signature_body(&FINGERPRINT.to_lowercase()))
                } else if self.refuse_fedora_signature {
                    return Ok(ProcessOutput {
                        termination: Termination::Exit(1),
                        stdout: Vec::new(),
                        stdout_overflow: false,
                        stderr_overflow: false,
                    });
                } else {
                    format!("{}:\n{}", last, signature_body(FEDORA_FINGERPRINT))
                }
                .into_bytes()
            } else {
                panic!("unexpected rpmkeys invocation");
            }
        } else {
            assert_eq!(request.executable.to_str(), Some("/usr/bin/rpm"));
            assert!(request.args.iter().any(|a| a == "--noplugins"));
            if has("-qf") {
                b"fedora-repos-44-1.noarch\nfedora-repos-44-1.noarch\n".to_vec()
            } else if has("-Vf") || has("--initdb") {
                Vec::new()
            } else if query().as_deref() == Some("%{VERSION}\n") {
                if has("gpg-pubkey") {
                    if self.rpmdb_project_key {
                        format!("{}\n", FINGERPRINT.to_lowercase()).into_bytes()
                    } else {
                        format!("{}\n", FEDORA_FINGERPRINT).into_bytes()
                    }
                } else {
                    format!("{}\n", FINGERPRINT.to_lowercase()).into_bytes()
                }
            } else if query().as_deref() == Some(INVENTORY_FORMAT) {
                self.inventory.to_vec()
            } else if has("-qp") {
                let filename = Path::new(&last)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                identity_for(&filename).into_bytes()
            } else {
                panic!("unexpected rpm invocation");
            }
        };
        Ok(ProcessOutput {
            termination: Termination::Exit(0),
            stdout,
            stdout_overflow: false,
            stderr_overflow: false,
        })
    }
}

/// Builds the exact native workspace the system planner would have produced.
struct FakePlanner {
    empty: bool,
    corrupt_repomd: bool,
    extra_cache: bool,
    omit_fedora_cache: bool,
    metadata_bytes: Option<u64>,
    configuration: Mutex<Option<String>>,
}

impl FakePlanner {
    fn observing() -> Self {
        Self {
            empty: false,
            corrupt_repomd: false,
            extra_cache: false,
            omit_fedora_cache: false,
            metadata_bytes: None,
            configuration: Mutex::new(None),
        }
    }
}

impl NativePlanner for FakePlanner {
    fn plan(
        &self,
        request: &DnfPlanningRequest<'_>,
    ) -> Result<DnfPlanningOutput, DnfPlanningFailure> {
        let configuration = fs::read_to_string(request.configuration).unwrap();
        *self.configuration.lock().unwrap() = Some(configuration);
        assert!(request.transaction.to_str().unwrap().ends_with("/store"));
        // The production planner refuses an existing transaction output, so
        // preparation must hand it a path that does not exist yet.
        assert!(
            !request.transaction.exists(),
            "prepare must not pre-create the native transaction store"
        );
        fs::create_dir_all(request.transaction.join("packages")).unwrap();
        if !self.empty {
            fs::copy(
                fixtures().join("transaction.json"),
                request.transaction.join("transaction.json"),
            )
            .unwrap();
            for entry in fs::read_dir(fixtures().join("packages")).unwrap() {
                let entry = entry.unwrap();
                fs::copy(
                    entry.path(),
                    request.transaction.join("packages").join(entry.file_name()),
                )
                .unwrap();
            }
        }
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.keep();
        let cache = path.join("cache");
        let repo = |id: &str, suffix: &str| {
            let dir = cache.join(format!("{id}-{suffix}")).join("repodata");
            fs::create_dir_all(&dir).unwrap();
            dir
        };
        let project = repo("intel-npu-stack-0.1.0", "0123456789abcdef");
        fs::copy(
            fixtures().join(if self.corrupt_repomd {
                "updates-repomd.xml"
            } else {
                "repomd.xml"
            }),
            project.join("repomd.xml"),
        )
        .unwrap();
        fs::copy(
            fixtures().join("repomd.xml.asc"),
            project.join("repomd.xml.asc"),
        )
        .unwrap();
        fs::copy(
            fixtures().join("primary.xml.zst"),
            project.join("primary.xml.zst"),
        )
        .unwrap();
        if !self.omit_fedora_cache {
            fs::copy(
                fixtures().join("fedora-repomd.xml"),
                repo("fedora", "fed0fed0fed0fed0").join("repomd.xml"),
            )
            .unwrap();
            fs::copy(
                fixtures().join("updates-repomd.xml"),
                repo("updates", "0dad0dad0dad0dad").join("repomd.xml"),
            )
            .unwrap();
        }
        if self.extra_cache {
            fs::create_dir_all(cache.join("thirdparty-abc123").join("repodata")).unwrap();
        }
        if let Some(bytes) = self.metadata_bytes {
            let file = repo("fedora", "fed0fed0fed0fed0").join("primary.xml.zck");
            fs::File::create(file).unwrap().set_len(bytes).unwrap();
        }
        Ok(DnfPlanningOutput::adopt(path))
    }
}

fn sources(runner: &dyn ProcessRunner) -> FedoraSources {
    FedoraSources::verify_at(&fixtures().join("etc"), "44", "x86_64", runner).unwrap()
}

fn input<'a>(
    manifest: &'a ReleaseManifest,
    packages: &'a [&'a stack_install::ReleasePackage],
    fedora: Option<&'a FedoraSources>,
) -> PrepareInput<'a> {
    PrepareInput {
        manifest,
        project_key: include_bytes!("fixtures/prepare/public.asc"),
        primary_fingerprint: FINGERPRINT,
        packages,
        fedora,
    }
}

fn prepare_with_fixtures<'a>(
    manifest: &'a ReleaseManifest,
    packages: &'a [&'a stack_install::ReleasePackage],
    planner: &FakePlanner,
    runner: &PrepareRunner,
) -> Result<PreparedTransaction, stack_install::PrepareFailure> {
    let fedora = sources(runner);
    prepare_with(&input(manifest, packages, Some(&fedora)), planner, runner)
}

fn options(yes: bool) -> InstallOptions {
    InstallOptions {
        yes,
        ..InstallOptions::default()
    }
}

struct RecordedReplay {
    argv: Mutex<Vec<Vec<OsString>>>,
    statuses: Mutex<Vec<ReplayStatus>>,
}
impl ReplayExecutor for RecordedReplay {
    fn run(&self, argv: &[OsString]) -> std::io::Result<ReplayStatus> {
        self.argv.lock().unwrap().push(argv.to_vec());
        let mut statuses = self.statuses.lock().unwrap();
        if statuses.len() > 1 {
            Ok(statuses.remove(0))
        } else {
            Ok(statuses[0])
        }
    }
}
struct MustNotReplay;
impl ReplayExecutor for MustNotReplay {
    fn run(&self, _: &[OsString]) -> std::io::Result<ReplayStatus> {
        panic!("privileged execution must not run after a failed recheck");
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn verified_sources_construct_the_exact_planning_configuration() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let configuration = planner.configuration.lock().unwrap().clone().unwrap();
    assert!(configuration.contains("[intel-npu-stack-0.1.0]\n"));
    assert!(configuration.contains(
        "baseurl=https://downloads.example.invalid/intel-npu-stack/0.1.0/fedora/44/x86_64/\n"
    ));
    assert!(configuration.contains("repo_gpgcheck=1\n"));
    let tree = prepared.directory();
    let key = format!("gpgkey=file://{}/public.asc\n", tree.display());
    assert!(configuration.contains(&key));
    assert!(configuration.contains("[fedora]\n"));
    assert!(configuration.contains(
        "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64\n"
    ));
    assert!(configuration.contains("[updates]\n"));
    assert!(configuration.contains(
        "metalink=https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64\n"
    ));
    assert!(!configuration.contains('$'));
    assert_eq!(mode(tree), 0o700);
    assert_eq!(mode(&tree.join("public.asc")), 0o600);
    assert_eq!(mode(&tree.join("planning.ini")), 0o600);
}

#[test]
fn unowned_or_modified_fedora_repository_files_are_refused() {
    struct Failing(&'static str);
    impl ProcessRunner for Failing {
        fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
            assert!(
                request
                    .args
                    .windows(2)
                    .any(|a| a == ["--macros", "/usr/lib/rpm/macros"])
            );
            if request.args.iter().any(|a| a == self.0) {
                return Ok(ProcessOutput {
                    termination: Termination::Exit(1),
                    stdout: Vec::new(),
                    stdout_overflow: false,
                    stderr_overflow: false,
                });
            }
            Ok(ProcessOutput {
                termination: Termination::Exit(0),
                stdout: if request.args.iter().any(|a| a == "-qf") {
                    b"fedora-repos-44-1.noarch\n".to_vec()
                } else {
                    Vec::new()
                },
                stdout_overflow: false,
                stderr_overflow: false,
            })
        }
    }
    for flag in ["-qf", "-Vf"] {
        let error =
            FedoraSources::verify_at(&fixtures().join("etc"), "44", "x86_64", &Failing(flag))
                .unwrap_err();
        assert_eq!(error.exit_code, 20);
    }
}

#[test]
fn unexpected_fedora_repository_content_is_refused() {
    type Mutation = (&'static str, fn(&str) -> String);
    let mutations: [Mutation; 6] = [
        ("http metalink", |c| {
            c.replace("https://mirrors", "http://mirrors")
        }),
        ("disabled base repo", |c| {
            c.replacen("enabled=1", "enabled=0", 1)
        }),
        ("unsigned repo", |c| {
            c.replacen("gpgcheck=1", "gpgcheck=0", 1)
        }),
        ("unknown directive", |c| {
            c.replacen("[fedora]\n", "[fedora]\nevil=1\n", 1)
        }),
        ("foreign repository", |c| {
            format!("[thirdparty]\nname=x\nbaseurl=https://evil.invalid/\nenabled=1\n{c}")
        }),
        ("repo metadata signing", |c| {
            c.replacen("repo_gpgcheck=0", "repo_gpgcheck=1", 1)
        }),
    ];
    let runner = prepare_runner();
    for (name, mutate) in mutations {
        let root = tempfile::tempdir().unwrap();
        let etc = root.path().join("etc");
        for dir in ["yum.repos.d", "pki/rpm-gpg"] {
            fs::create_dir_all(etc.join(dir)).unwrap();
        }
        let fedora = fs::read_to_string(fixtures().join("etc/yum.repos.d/fedora.repo")).unwrap();
        // The pristine copy must verify so each mutation is refused by content.
        let pristine = fedora.clone();
        fs::write(etc.join("yum.repos.d/fedora.repo"), &pristine).unwrap();
        fs::copy(
            fixtures().join("etc/yum.repos.d/fedora-updates.repo"),
            etc.join("yum.repos.d/fedora-updates.repo"),
        )
        .unwrap();
        fs::copy(
            fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
            etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
        )
        .unwrap();
        FedoraSources::verify_at(&etc, "44", "x86_64", &runner).unwrap();
        fs::write(etc.join("yum.repos.d/fedora.repo"), mutate(&fedora)).unwrap();
        assert!(
            FedoraSources::verify_at(&etc, "44", "x86_64", &runner).is_err(),
            "{name} was accepted"
        );
    }
}

#[test]
fn distribution_key_symlink_layout_is_accepted_and_escapes_refused() {
    let runner = prepare_runner();
    let make = |layout: &str| {
        let root = tempfile::tempdir().unwrap();
        let etc = root.path().join("etc");
        for directory in ["yum.repos.d", "pki/rpm-gpg"] {
            fs::create_dir_all(etc.join(directory)).unwrap();
        }
        fs::copy(
            fixtures().join("etc/yum.repos.d/fedora.repo"),
            etc.join("yum.repos.d/fedora.repo"),
        )
        .unwrap();
        fs::copy(
            fixtures().join("etc/yum.repos.d/fedora-updates.repo"),
            etc.join("yum.repos.d/fedora-updates.repo"),
        )
        .unwrap();
        let key = etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64");
        match layout {
            // Every real Fedora 44 system ships the arch key as a same-dir
            // symlink to the primary key owned by fedora-gpg-keys.
            "symlink" => {
                fs::copy(
                    fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
                    etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary"),
                )
                .unwrap();
                std::os::unix::fs::symlink("RPM-GPG-KEY-fedora-44-primary", &key).unwrap();
            }
            "dangling" => {
                std::os::unix::fs::symlink("absent-key", &key).unwrap();
            }
            "escape" => {
                let outside = root.path().join("outside-key");
                fs::copy(
                    fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
                    &outside,
                )
                .unwrap();
                std::os::unix::fs::symlink("../../outside-key", &key).unwrap();
            }
            _ => {
                fs::copy(
                    fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
                    &key,
                )
                .unwrap();
            }
        }
        (root, etc)
    };
    let (regular_root, regular) = make("regular");
    FedoraSources::verify_at(&regular, "44", "x86_64", &runner).unwrap();
    let (symlink_root, symlink) = make("symlink");
    let fedora = FedoraSources::verify_at(&symlink, "44", "x86_64", &runner).unwrap();
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let prepared = prepare_with(
        &input(&manifest, &packages, Some(&fedora)),
        &FakePlanner::observing(),
        &runner,
    )
    .unwrap();
    prepared.verify_bound(&runner).unwrap();
    let key = symlink.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64");
    fs::copy(
        symlink.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary"),
        symlink.join("pki/rpm-gpg/other-key"),
    )
    .unwrap();
    fs::remove_file(&key).unwrap();
    std::os::unix::fs::symlink("other-key", &key).unwrap();
    let receipt = approved(&prepared);
    assert!(
        prepared
            .execute_replay(&receipt, &runner, &MustNotReplay)
            .is_err()
    );
    let (dangling_root, dangling) = make("dangling");
    assert!(FedoraSources::verify_at(&dangling, "44", "x86_64", &runner).is_err());
    let (escape_root, escape) = make("escape");
    assert!(FedoraSources::verify_at(&escape, "44", "x86_64", &runner).is_err());
    drop((regular_root, symlink_root, dangling_root, escape_root));
}

#[test]
fn prepare_binds_project_and_fedora_inputs_into_one_native_plan() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let preview = prepared.plan().preview();
    for identity in [
        "intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch",
        "intel-npu-stack-firmware-1.35.0-1.intelnpu.fc44.noarch",
        "intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64",
        "createrepo_c-libs-1.2.0-1.fc44.x86_64",
        "drpm-0.5.3-2.fc44.x86_64",
    ] {
        assert!(
            preview.contains(identity),
            "{identity} missing from preview"
        );
    }
    assert_eq!(
        prepared.plan().transaction_sha256().unwrap(),
        &format!(
            "{:x}",
            Sha256::digest(fs::read(fixtures().join("transaction.json")).unwrap())
        )
    );
    prepared.verify_bound(&runner).unwrap();
}

#[test]
fn bound_inputs_survive_the_distribution_key_symlink_layout() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let root = tempfile::tempdir().unwrap();
    let etc = root.path().join("etc");
    for directory in ["yum.repos.d", "pki/rpm-gpg"] {
        fs::create_dir_all(etc.join(directory)).unwrap();
    }
    for name in ["fedora.repo", "fedora-updates.repo"] {
        fs::copy(
            fixtures().join(format!("etc/yum.repos.d/{name}")),
            etc.join(format!("yum.repos.d/{name}")),
        )
        .unwrap();
    }
    fs::copy(
        fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
        etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "RPM-GPG-KEY-fedora-44-primary",
        etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
    )
    .unwrap();
    let fedora = FedoraSources::verify_at(&etc, "44", "x86_64", &runner).unwrap();
    let request = input(&manifest, &packages, Some(&fedora));
    let prepared = prepare_with(&request, &planner, &runner).unwrap();
    prepared.verify_bound(&runner).unwrap();
}

#[test]
fn cached_project_repomd_must_match_authenticated_release_metadata() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner {
        corrupt_repomd: true,
        ..FakePlanner::observing()
    };
    let runner = prepare_runner();
    let failure = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap_err();
    assert_eq!(failure.error.exit_code, 20);
    let diagnostics = failure.diagnostics.unwrap();
    assert!(diagnostics.join("planning.ini").is_file());
    assert_eq!(mode(&diagnostics), 0o700);
    fs::remove_dir_all(diagnostics).unwrap();
}

#[test]
fn unexpected_or_missing_cache_repositories_are_refused() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let runner = prepare_runner();
    for corrupt in [false, true] {
        let planner = FakePlanner {
            empty: false,
            corrupt_repomd: false,
            extra_cache: corrupt,
            omit_fedora_cache: !corrupt,
            metadata_bytes: None,
            configuration: Mutex::new(None),
        };
        let failure = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap_err();
        assert_eq!(failure.error.exit_code, 20);
        fs::remove_dir_all(failure.diagnostics.unwrap()).unwrap();
    }
}

#[test]
fn unsigned_fedora_dependency_is_refused() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = PrepareRunner {
        inventory: STATE,
        refuse_fedora_signature: true,
        rpmdb_project_key: true,
    };
    let failure = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap_err();
    assert_eq!(failure.error.code, "INSTALL_INTEGRITY_FAILED");
    fs::remove_dir_all(failure.diagnostics.unwrap()).unwrap();
}

#[test]
fn replay_configuration_snapshots_preserve_repository_bytes() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let tree = prepared.directory();
    let configuration = fs::read_to_string(tree.join("replay.ini")).unwrap();
    assert_eq!(mode(&tree.join("replay.ini")), 0o600);
    for (repository, repomd) in [
        ("intel-npu-stack-0.1.0", "repomd.xml"),
        ("fedora", "fedora-repomd.xml"),
        ("updates", "updates-repomd.xml"),
    ] {
        let snapshot = tree.join("replay-repos").join(repository).join("repodata");
        assert!(configuration.contains(&format!(
            "baseurl=file://{}/replay-repos/{}/\n",
            tree.display(),
            repository
        )));
        assert_eq!(
            fs::read(snapshot.join("repomd.xml")).unwrap(),
            fs::read(fixtures().join(repomd)).unwrap()
        );
        for entry in fs::read_dir(&snapshot).unwrap() {
            assert_eq!(mode(&entry.unwrap().path()), 0o600);
        }
    }
    let project = tree.join("replay-repos/intel-npu-stack-0.1.0/repodata");
    assert_eq!(
        fs::read(project.join("repomd.xml.asc")).unwrap(),
        fs::read(fixtures().join("repomd.xml.asc")).unwrap()
    );
    assert_eq!(
        fs::read(project.join("primary.xml.zst")).unwrap(),
        fs::read(fixtures().join("primary.xml.zst")).unwrap()
    );
}

#[test]
fn real_sized_fedora_metadata_is_bound_and_later_corruption_refused() {
    use std::io::{Seek, SeekFrom, Write};
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner {
        metadata_bytes: Some(36_915_318),
        ..FakePlanner::observing()
    };
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    prepared.verify_bound(&runner).unwrap();
    let file = prepared
        .directory()
        .join("replay-repos/fedora/repodata/primary.xml.zck");
    let mut file = fs::OpenOptions::new().write(true).open(file).unwrap();
    file.seek(SeekFrom::Start(36_000_000)).unwrap();
    file.write_all(b"corruption beyond the old 8 MiB limit")
        .unwrap();
    let receipt = approved(&prepared);
    assert!(
        prepared
            .execute_replay(&receipt, &runner, &MustNotReplay)
            .is_err()
    );
}

#[test]
fn oversized_repository_metadata_is_refused_before_replay() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner {
        metadata_bytes: Some(256 * 1024 * 1024 + 1),
        ..FakePlanner::observing()
    };
    let failure =
        prepare_with_fixtures(&manifest, &packages, &planner, &prepare_runner()).unwrap_err();
    assert_eq!(failure.error.code, "INSTALL_INTEGRITY_FAILED");
    fs::remove_dir_all(failure.diagnostics.unwrap()).unwrap();
}

fn approved(prepared: &PreparedTransaction) -> ApprovedPlan<'_> {
    let mut output = Vec::new();
    match review_plan(prepared.plan(), &options(true), &mut output, &mut NoPrompt).unwrap() {
        PlanReview::Approved(approval) => approval,
        other => panic!("expected approval, got {other:?}"),
    }
}
struct NoPrompt;
impl stack_install::ConfirmationPrompt for NoPrompt {
    fn read_response(&mut self) -> std::io::Result<String> {
        panic!("--yes must not read a terminal response");
    }
}

#[test]
fn replay_executes_only_the_reviewed_plan_with_fixed_privileged_steps() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let receipt = approved(&prepared);
    let executor = RecordedReplay {
        argv: Mutex::new(Vec::new()),
        statuses: Mutex::new(vec![ReplayStatus::Exit(0)]),
    };
    prepared
        .execute_replay(&receipt, &runner, &executor)
        .unwrap();
    let tree = prepared.directory();
    let steps = executor.argv.lock().unwrap().clone();
    let step = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned().into())
            .collect::<Vec<OsString>>()
    };
    // The key import precedes replay: native replay verifies stored package
    // signatures only against the system RPM database.
    assert_eq!(
        steps,
        vec![
            step(&[
                "/usr/bin/sudo",
                "--set-home",
                "--",
                "/usr/bin/rpmkeys",
                "--import",
            ])
            .into_iter()
            .chain([OsString::from(format!("{}/public.asc", tree.display()))])
            .collect::<Vec<_>>(),
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
            .collect::<Vec<_>>(),
        ]
    );
}

#[test]
fn altered_inputs_prevent_replay_before_any_privileged_execution() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    for altered in ["snapshot", "store", "replay.ini", "public.asc"] {
        let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
        let tree = prepared.directory().to_path_buf();
        match altered {
            "snapshot" => {
                let file = tree.join("replay-repos/fedora/repodata/repomd.xml");
                fs::write(&file, b"altered").unwrap();
            }
            "store" => {
                let file = tree
                    .join("store/packages/intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm");
                fs::write(&file, b"altered").unwrap();
            }
            "replay.ini" => {
                let mut text = fs::read_to_string(tree.join("replay.ini")).unwrap();
                text.push('\n');
                fs::write(tree.join("replay.ini"), text).unwrap();
            }
            _ => {
                fs::write(tree.join("public.asc"), b"altered").unwrap();
            }
        }
        let receipt = approved(&prepared);
        let error = prepared
            .execute_replay(&receipt, &runner, &MustNotReplay)
            .unwrap_err();
        assert_eq!(error.error.exit_code, 20, "{altered} did not fail rechecks");
    }
}

#[test]
fn a_receipt_for_a_different_plan_is_refused() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let other = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let foreign = approved(&other);
    let error = prepared
        .execute_replay(&foreign, &runner, &MustNotReplay)
        .unwrap_err();
    assert_eq!(error.error.code, "INSTALL_PLAN_RECEIPT_MISMATCH");
}

#[test]
fn a_complete_noop_plan_produces_no_replayable_transaction() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner {
        empty: true,
        ..FakePlanner::observing()
    };
    let runner = PrepareRunner {
        inventory: STATE_COMPLETE,
        refuse_fedora_signature: false,
        rpmdb_project_key: true,
    };
    let fedora = sources(&runner);
    let prepared = prepare_with(
        &input(&manifest, &packages, Some(&fedora)),
        &planner,
        &runner,
    )
    .unwrap();
    assert!(prepared.plan().is_empty());
    let mut output = Vec::new();
    assert!(matches!(
        review_plan(prepared.plan(), &options(true), &mut output, &mut NoPrompt).unwrap(),
        PlanReview::NoChanges
    ));
    let transaction = prepared.directory().join("store/transaction.json");
    assert!(!transaction.exists());
}

#[test]
fn fedora_source_drift_between_verification_and_preparation_is_refused() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let root = tempfile::tempdir().unwrap();
    let etc = root.path().join("etc");
    fs::create_dir_all(etc.join("yum.repos.d")).unwrap();
    fs::create_dir_all(etc.join("pki/rpm-gpg")).unwrap();
    for file in ["yum.repos.d/fedora.repo", "yum.repos.d/fedora-updates.repo"] {
        fs::copy(fixtures().join("etc").join(file), etc.join(file)).unwrap();
    }
    fs::copy(
        fixtures().join("etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
        etc.join("pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64"),
    )
    .unwrap();
    let runner = prepare_runner();
    let fedora = FedoraSources::verify_at(&etc, "44", "x86_64", &runner).unwrap();
    let repo = etc.join("yum.repos.d/fedora.repo");
    let mut content = fs::read_to_string(&repo).unwrap();
    content.push_str("# drifted\n");
    fs::write(&repo, content).unwrap();
    let planner = FakePlanner::observing();
    let failure = prepare_with(
        &input(&manifest, &packages, Some(&fedora)),
        &planner,
        &runner,
    )
    .unwrap_err();
    assert_eq!(failure.error.exit_code, 20);
    fs::remove_dir_all(failure.diagnostics.unwrap()).unwrap();
}

#[test]
fn replay_failure_reports_the_native_exit_and_retains_a_preserved_tree() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let receipt = approved(&prepared);
    let executor = RecordedReplay {
        argv: Mutex::new(Vec::new()),
        statuses: Mutex::new(vec![ReplayStatus::Exit(0), ReplayStatus::Exit(42)]),
    };
    let failure = prepared
        .execute_replay(&receipt, &runner, &executor)
        .unwrap_err();
    assert_eq!(failure.error.code, "INSTALL_REPLAY_FAILED");
    assert_eq!(failure.status, Some(42));
    assert_eq!(executor.argv.lock().unwrap().len(), 2);
    let preserved = prepared.preserve();
    assert!(preserved.join("store/transaction.json").is_file());
    fs::remove_dir_all(preserved).unwrap();
}

#[test]
fn a_failed_release_key_import_prevents_the_native_replay() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = prepare_runner();
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let receipt = approved(&prepared);
    let executor = RecordedReplay {
        argv: Mutex::new(Vec::new()),
        statuses: Mutex::new(vec![ReplayStatus::Exit(1)]),
    };
    let failure = prepared
        .execute_replay(&receipt, &runner, &executor)
        .unwrap_err();
    assert_eq!(failure.error.code, "INSTALL_KEY_IMPORT_FAILED");
    assert_eq!(failure.status, Some(1));
    assert_eq!(executor.argv.lock().unwrap().len(), 1);
}

#[test]
fn an_unconfirmed_release_key_import_prevents_the_native_replay() {
    let manifest =
        ReleaseManifest::parse_json(include_bytes!("fixtures/prepare/release.json")).unwrap();
    let packages = manifest.selected_packages(false, false).unwrap();
    let planner = FakePlanner::observing();
    let runner = PrepareRunner {
        inventory: STATE,
        refuse_fedora_signature: false,
        rpmdb_project_key: false,
    };
    let prepared = prepare_with_fixtures(&manifest, &packages, &planner, &runner).unwrap();
    let receipt = approved(&prepared);
    let executor = RecordedReplay {
        argv: Mutex::new(Vec::new()),
        statuses: Mutex::new(vec![ReplayStatus::Exit(0)]),
    };
    let failure = prepared
        .execute_replay(&receipt, &runner, &executor)
        .unwrap_err();
    assert_eq!(failure.error.code, "INSTALL_KEY_IMPORT_FAILED");
    assert_eq!(failure.status, None);
    assert_eq!(executor.argv.lock().unwrap().len(), 1);
}
