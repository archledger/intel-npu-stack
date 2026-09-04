// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use xtask::source_bundle::{bundle_sources, hash_cached_source, materialize_lfs_archive};

const LICENSE_SHA256: &str = "a7c6bf8df7d8fb707af606599f275e0eb192cd28492c95593b0608ca966c8df1";

struct Fixture {
    root: TempDir,
    cache: PathBuf,
    lock: PathBuf,
    leaf_commit: String,
    root_commit: String,
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .expect("run fixture git command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("fixture git output is UTF-8")
        .trim()
        .to_owned()
}

fn init_repo(path: &Path, origin: &str, filename: &str, contents: &str) -> String {
    fs::create_dir_all(path).expect("create fixture repository");
    git(path, &["init", "--quiet"]);
    git(path, &["config", "user.name", "Fixture Author"]);
    git(path, &["config", "user.email", "fixture@example.invalid"]);
    git(path, &["remote", "add", "origin", origin]);
    fs::write(path.join(filename), contents).expect("write tracked fixture");
    git(path, &["add", "--", filename]);
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("commit fixture repository");
    assert!(output.status.success(), "commit fixture repository");
    git(path, &["-c", "tag.gpgSign=false", "tag", "v1"]);
    git(path, &["rev-parse", "HEAD"])
}

fn archive_digest(repo: &Path, name: &str, commit: &str) -> String {
    let prefix = format!("{name}/");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["archive", "--format=tar", "--prefix", &prefix, commit])
        .output()
        .expect("archive fixture repository");
    assert!(output.status.success(), "archive fixture repository");
    format!("{:x}", Sha256::digest(output.stdout))
}

fn source_record(name: &str, role: &str, url: &str, commit: &str, digest: &str) -> String {
    format!(
        r#"[[sources]]
name = "{name}"
role = "{role}"
kind = "git_tag"
url = "{url}"
tag = "v1"
commit = "{commit}"
archive_sha256 = "{digest}"
license_expression = "MIT"
license_files = ["evidence/LICENSE.fixture"]
license_evidence_sha256 = "{LICENSE_SHA256}"
redistribution = "allowed"
"#
    )
}

fn write_lock(fixture: &Fixture, root_gitlinks: &str) {
    let leaf_repo = fixture.cache.join("leaf");
    let root_repo = fixture.cache.join("root");
    let leaf_digest = archive_digest(&leaf_repo, "leaf", &fixture.leaf_commit);
    let root_digest = archive_digest(&root_repo, "root", &fixture.root_commit);
    let text = format!(
        r#"schema_version = 1
status = "sealed"
profile_id = "fedora-44-x86_64-8086-643e-candidate"

[target]
distribution_id = "fedora"
version_id = "44"
architecture = "x86_64"
pci_vendor = "8086"
pci_device = "643e"

{}
{}
{}
"#,
        source_record(
            "leaf",
            "build_dependency",
            "https://example.invalid/leaf.git",
            &fixture.leaf_commit,
            &leaf_digest
        ),
        source_record(
            "root",
            "npu_userspace_driver",
            "https://example.invalid/root.git",
            &fixture.root_commit,
            &root_digest
        ),
        root_gitlinks
    );
    fs::write(&fixture.lock, text).expect("write source lock");
}

fn setup() -> Fixture {
    let root = TempDir::new().expect("create source-bundle fixture");
    let cache = root.path().join("cache");
    let evidence = root.path().join("evidence");
    fs::create_dir_all(&cache).expect("create source cache");
    fs::create_dir_all(&evidence).expect("create evidence directory");
    fs::write(evidence.join("LICENSE.fixture"), "fixture license\n").expect("write evidence");

    let leaf_commit = init_repo(
        &cache.join("leaf"),
        "https://example.invalid/leaf.git",
        "leaf.txt",
        "leaf source\n",
    );
    init_repo(
        &cache.join("root"),
        "https://example.invalid/root.git",
        "root.txt",
        "root source\n",
    );
    git(
        &cache.join("root"),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{leaf_commit},deps/leaf"),
        ],
    );
    fs::write(
        cache.join("root/.gitmodules"),
        "[submodule \"deps/leaf\"]\n\tpath = deps/leaf\n\turl = https://example.invalid/leaf.git\n",
    )
    .expect("write gitmodules");
    fs::write(
        cache.join("root/.gitattributes"),
        "root.txt filter=hostile\n",
    )
    .expect("write fixture attributes");
    git(
        &cache.join("root"),
        &["add", ".gitmodules", ".gitattributes"],
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(cache.join("root"))
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "add declared gitlink",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-02T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-02T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("commit fixture gitlink");
    assert!(output.status.success(), "commit fixture gitlink");
    git(
        &cache.join("root"),
        &["-c", "tag.gpgSign=false", "tag", "-f", "v1"],
    );
    let root_commit = git(&cache.join("root"), &["rev-parse", "HEAD"]);

    let fixture = Fixture {
        lock: root.path().join("provider-sources.toml"),
        root,
        cache,
        leaf_commit,
        root_commit,
    };
    let gitlink = format!(
        r#"[[sources.gitlinks]]
path = "deps/leaf"
disposition = "bundled"
source = "leaf"
commit = "{}"
"#,
        fixture.leaf_commit
    );
    write_lock(&fixture, &gitlink);
    fixture
}

fn bundle(fixture: &Fixture, output: &Path) -> Result<(), String> {
    bundle_sources(&fixture.lock, fixture.root.path(), &fixture.cache, output)
        .map(|_| ())
        .map_err(|error| error.code)
}

#[test]
fn creates_identical_archives_and_sorted_checksums_from_real_git_repositories() {
    let fixture = setup();
    let first = fixture.root.path().join("first");
    let second = fixture.root.path().join("second");
    fs::create_dir(&first).expect("create first output");
    fs::create_dir(&second).expect("create second output");

    bundle(&fixture, &first).expect("first bundle");
    bundle(&fixture, &second).expect("second bundle");

    for filename in ["leaf.tar", "root.tar", "SHA256SUMS"] {
        assert_eq!(
            fs::read(first.join(filename)).expect("read first artifact"),
            fs::read(second.join(filename)).expect("read second artifact"),
            "artifact {filename}"
        );
    }
    let checksums = fs::read_to_string(first.join("SHA256SUMS")).expect("read checksums");
    assert!(
        checksums
            .lines()
            .next()
            .expect("first checksum")
            .ends_with("  leaf.tar")
    );
    assert!(
        checksums
            .lines()
            .nth(1)
            .expect("second checksum")
            .ends_with("  root.tar")
    );
}

#[test]
fn rejects_wrong_root_commit_and_a_moved_tag() {
    let fixture = setup();
    let output = fixture.root.path().join("wrong-root");
    fs::create_dir(&output).expect("create output");
    let original = fs::read_to_string(&fixture.lock).expect("read source lock");
    fs::write(
        &fixture.lock,
        original.replace(
            &fixture.root_commit,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    )
    .expect("write wrong root commit");
    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_TAG_MOVED".to_owned())
    );

    write_lock(
        &fixture,
        &format!(
            "[[sources.gitlinks]]\npath = \"deps/leaf\"\ndisposition = \"bundled\"\nsource = \"leaf\"\ncommit = \"{}\"\n",
            fixture.leaf_commit
        ),
    );
    fs::write(fixture.cache.join("root/new.txt"), "new commit\n").expect("write moved tag file");
    git(&fixture.cache.join("root"), &["add", "new.txt"]);
    let commit = Command::new("git")
        .arg("-C")
        .arg(fixture.cache.join("root"))
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "move tag",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-03T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-03T00:00:00Z")
        .output()
        .expect("commit moved tag");
    assert!(commit.status.success(), "commit moved tag");
    git(
        &fixture.cache.join("root"),
        &["-c", "tag.gpgSign=false", "tag", "-f", "v1"],
    );
    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_TAG_MOVED".to_owned())
    );
}

#[test]
fn rejects_wrong_or_undeclared_gitlinks() {
    let fixture = setup();
    let output = fixture.root.path().join("gitlink-output");
    fs::create_dir(&output).expect("create output");
    write_lock(
        &fixture,
        "[[sources.gitlinks]]\npath = \"deps/leaf\"\ndisposition = \"bundled\"\nsource = \"leaf\"\ncommit = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
    );
    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_GITLINK_MISMATCH".to_owned())
    );

    write_lock(&fixture, "");
    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_GITLINK_UNDECLARED".to_owned())
    );
}

#[test]
fn rejects_nonempty_or_symlinked_output_before_archiving() {
    let fixture = setup();
    let nonempty = fixture.root.path().join("nonempty");
    fs::create_dir(&nonempty).expect("create nonempty output");
    fs::write(nonempty.join("keep"), "user data\n").expect("write user data");
    assert_eq!(
        bundle(&fixture, &nonempty),
        Err("SOURCE_BUNDLE_OUTPUT_INVALID".to_owned())
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real = fixture.root.path().join("real-output");
        let linked = fixture.root.path().join("linked-output");
        fs::create_dir(&real).expect("create real output");
        symlink(&real, &linked).expect("create output symlink");
        assert_eq!(
            bundle(&fixture, &linked),
            Err("SOURCE_BUNDLE_OUTPUT_INVALID".to_owned())
        );
    }
}

#[test]
fn rejects_a_cache_origin_that_does_not_match_the_lock() {
    let fixture = setup();
    let output = fixture.root.path().join("origin-output");
    fs::create_dir(&output).expect("create output");
    git(
        &fixture.cache.join("leaf"),
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/other.git",
        ],
    );
    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_ORIGIN_MISMATCH".to_owned())
    );
}

#[test]
fn does_not_publish_external_only_sources() {
    let fixture = setup();
    let output = fixture.root.path().join("external-only-output");
    fs::create_dir(&output).expect("create output");
    let lock = fs::read_to_string(&fixture.lock)
        .expect("read source lock")
        .replace(
            "redistribution = \"allowed\"",
            "redistribution = \"external_only\"",
        );
    fs::write(&fixture.lock, lock).expect("write external-only lock");

    bundle(&fixture, &output).expect("verify external-only sources");
    assert_eq!(
        fs::read_to_string(output.join("SHA256SUMS")).expect("read checksums"),
        ""
    );
    assert_eq!(
        fs::read_dir(&output).expect("read output").count(),
        1,
        "only the checksum manifest is published"
    );
}

#[test]
fn rejects_repository_compressor_configuration() {
    let fixture = setup();
    let output = fixture.root.path().join("safe-archive-output");
    fs::create_dir(&output).expect("create output");
    git(
        &fixture.cache.join("root"),
        &["config", "tar.tar.gz.command", "false"],
    );

    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_CACHE_CONFIG_INVALID".to_owned())
    );
    assert!(!output.join("root.tar").exists());
}

#[test]
fn rejects_local_archive_filters_before_they_execute() {
    let fixture = setup();
    let output = fixture.root.path().join("filter-output");
    let marker = fixture.root.path().join("filter-executed");
    fs::create_dir(&output).expect("create output");
    git(
        &fixture.cache.join("root"),
        &[
            "config",
            "filter.hostile.smudge",
            &format!("/usr/bin/touch {}", marker.display()),
        ],
    );

    assert_eq!(
        bundle(&fixture, &output),
        Err("SOURCE_BUNDLE_CACHE_CONFIG_INVALID".to_owned())
    );
    assert!(!marker.exists(), "configured content filter executed");
}

#[test]
fn neutralizes_external_attributes_and_replacement_refs() {
    let fixture = setup();
    let repository = fixture.cache.join("leaf");
    let expected = archive_digest(&repository, "leaf", &fixture.leaf_commit);
    let attributes = fixture.root.path().join("external-attributes");
    fs::write(&attributes, "leaf.txt export-ignore\n").expect("write external attributes");
    git(
        &repository,
        &[
            "config",
            "core.attributesFile",
            attributes.to_str().expect("UTF-8 fixture path"),
        ],
    );

    fs::write(repository.join("leaf.txt"), "replacement source\n")
        .expect("write replacement source");
    git(&repository, &["add", "leaf.txt"]);
    let replacement = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "replacement fixture",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-05T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-05T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("commit replacement fixture");
    assert!(replacement.status.success(), "commit replacement fixture");
    let replacement_commit = git(&repository, &["rev-parse", "HEAD"]);
    git(
        &repository,
        &["replace", &fixture.leaf_commit, &replacement_commit],
    );

    let output = fixture.root.path().join("neutralized.tar");
    assert_eq!(
        hash_cached_source(&repository, "leaf", &fixture.leaf_commit, &output)
            .expect("mutable Git metadata is neutralized"),
        expected
    );
}

#[test]
fn rejects_info_attributes_and_alternate_object_stores() {
    let attributes_fixture = setup();
    let attributes_repository = attributes_fixture.cache.join("leaf");
    fs::write(
        attributes_repository.join(".git/info/attributes"),
        "leaf.txt export-ignore\n",
    )
    .expect("write info attributes");
    assert_eq!(
        hash_cached_source(
            &attributes_repository,
            "leaf",
            &attributes_fixture.leaf_commit,
            &attributes_fixture.root.path().join("attributes.tar"),
        )
        .expect_err("mutable info attributes must fail")
        .code,
        "SOURCE_BUNDLE_CACHE_CONFIG_INVALID"
    );

    let alternates_fixture = setup();
    let alternates_repository = alternates_fixture.cache.join("leaf");
    let external_objects = alternates_fixture.root.path().join("external-objects");
    fs::create_dir(&external_objects).expect("create external object directory");
    fs::write(
        alternates_repository.join(".git/objects/info/alternates"),
        format!("{}\n", external_objects.display()),
    )
    .expect("write alternate object store");
    assert_eq!(
        hash_cached_source(
            &alternates_repository,
            "leaf",
            &alternates_fixture.leaf_commit,
            &alternates_fixture.root.path().join("alternates.tar"),
        )
        .expect_err("alternate object store must fail")
        .code,
        "SOURCE_BUNDLE_CACHE_CONFIG_INVALID"
    );
}

#[test]
fn materializes_verified_lfs_objects_without_filters_or_network() {
    let fixture = TempDir::new().expect("create LFS fixture");
    let repo = fixture.path().join("lfs-repo");
    let output = fixture.path().join("materialized.tar");
    fs::create_dir(&repo).expect("create LFS repository");
    git(&repo, &["init", "--quiet"]);
    git(&repo, &["config", "user.name", "Fixture Author"]);
    git(&repo, &["config", "user.email", "fixture@example.invalid"]);

    let payload = b"verified LFS payload\n";
    let oid = format!("{:x}", Sha256::digest(payload));
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {}\n",
        payload.len()
    );
    fs::write(repo.join(".gitattributes"), "asset.bin filter=lfs -text\n")
        .expect("write LFS attributes");
    fs::write(repo.join("asset.bin"), pointer).expect("write LFS pointer");
    git(&repo, &["add", ".gitattributes", "asset.bin"]);
    let commit = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args([
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "LFS fixture",
        ])
        .env("GIT_AUTHOR_DATE", "2026-01-04T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-04T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("commit LFS fixture");
    assert!(commit.status.success(), "commit LFS fixture");

    let object = repo
        .join(".git/lfs/objects")
        .join(&oid[..2])
        .join(&oid[2..4])
        .join(&oid);
    fs::create_dir_all(object.parent().expect("LFS object parent"))
        .expect("create LFS object directory");
    fs::write(&object, payload).expect("write LFS object");
    let raw = fixture.path().join("raw.tar");
    let archive = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args([
            "-c",
            "filter.lfs.process=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            "archive",
            "--format=tar",
            "--prefix=lfs/",
            "--output",
        ])
        .arg(&raw)
        .arg(git(&repo, &["rev-parse", "HEAD"]))
        .output()
        .expect("create raw pointer archive");
    assert!(archive.status.success(), "create raw pointer archive");

    materialize_lfs_archive(&repo, &raw, &output).expect("materialize LFS archive");
    let extracted = Command::new("/usr/bin/tar")
        .args(["-xOf"])
        .arg(&output)
        .arg("lfs/asset.bin")
        .output()
        .expect("read materialized archive");
    assert!(extracted.status.success(), "read materialized archive");
    assert_eq!(extracted.stdout, payload);

    fs::write(&object, vec![b'x'; payload.len()]).expect("write wrong-digest LFS object");
    assert_eq!(
        materialize_lfs_archive(&repo, &raw, &fixture.path().join("wrong-digest.tar"))
            .expect_err("wrong-digest LFS object must fail")
            .code,
        "SOURCE_BUNDLE_LFS_OBJECT_INVALID"
    );
    fs::write(&object, b"x").expect("write wrong-size LFS object");
    assert_eq!(
        materialize_lfs_archive(&repo, &raw, &fixture.path().join("wrong-size.tar"))
            .expect_err("wrong-size LFS object must fail")
            .code,
        "SOURCE_BUNDLE_LFS_OBJECT_INVALID"
    );

    fs::remove_file(object).expect("remove LFS object");
    assert_eq!(
        materialize_lfs_archive(&repo, &raw, &fixture.path().join("missing.tar"))
            .expect_err("missing LFS object must fail")
            .code,
        "SOURCE_BUNDLE_LFS_OBJECT_MISSING"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let first = repo.join(".git/lfs/objects").join(&oid[..2]);
        fs::remove_dir_all(&first).expect("remove LFS prefix directory");
        let outside = fixture.path().join("outside-lfs");
        let escaped = outside.join(&oid[2..4]).join(&oid);
        fs::create_dir_all(escaped.parent().expect("escaped LFS object parent"))
            .expect("create escaped LFS object directory");
        fs::write(&escaped, payload).expect("write escaped LFS object");
        symlink(&outside, &first).expect("create LFS parent symlink");
        assert_eq!(
            materialize_lfs_archive(&repo, &raw, &fixture.path().join("escaped.tar"))
                .expect_err("LFS parent symlink must fail")
                .code,
            "SOURCE_BUNDLE_LFS_OBJECT_INVALID"
        );
    }
}

#[test]
fn hashes_one_explicit_cached_commit_without_network() {
    let fixture = setup();
    let output = fixture.root.path().join("leaf-explicit.tar");
    let expected = archive_digest(&fixture.cache.join("leaf"), "leaf", &fixture.leaf_commit);
    let actual = hash_cached_source(
        &fixture.cache.join("leaf"),
        "leaf",
        &fixture.leaf_commit,
        &output,
    )
    .expect("hash explicit cached source");
    assert_eq!(actual, expected);
    assert!(output.is_file());

    assert_eq!(
        hash_cached_source(
            &fixture.cache.join("leaf"),
            "../escape",
            &fixture.leaf_commit,
            &fixture.root.path().join("escape.tar"),
        )
        .expect_err("unsafe source name must fail")
        .code,
        "SOURCE_BUNDLE_IDENTITY_INVALID"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let guarded_output = fixture.root.path().join("guarded.tar");
        let raw_neighbor = guarded_output.with_extension("raw.tar");
        let victim = fixture.root.path().join("victim");
        fs::write(&victim, "keep\n").expect("write victim");
        symlink(&victim, &raw_neighbor).expect("create raw archive symlink");
        assert_eq!(
            hash_cached_source(
                &fixture.cache.join("leaf"),
                "leaf",
                &fixture.leaf_commit,
                &guarded_output,
            )
            .expect_err("raw archive symlink must fail")
            .code,
            "SOURCE_BUNDLE_OUTPUT_INVALID"
        );
        assert_eq!(fs::read_to_string(&victim).expect("read victim"), "keep\n");

        fs::remove_file(&raw_neighbor).expect("remove raw archive symlink");
        let draft_neighbor = guarded_output.with_extension("materializing.tar");
        symlink(&victim, &draft_neighbor).expect("create materializing archive symlink");
        assert_eq!(
            hash_cached_source(
                &fixture.cache.join("leaf"),
                "leaf",
                &fixture.leaf_commit,
                &guarded_output,
            )
            .expect_err("materializing archive symlink must fail")
            .code,
            "SOURCE_BUNDLE_OUTPUT_INVALID"
        );
        assert_eq!(fs::read_to_string(victim).expect("read victim"), "keep\n");
    }
}
