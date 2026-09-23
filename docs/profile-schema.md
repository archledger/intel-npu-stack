# Capability profile schema version 1

An `intel-npu-stack` profile is one independently reviewed compatibility matrix. It binds an exact operating-system release, architecture, PCI hardware allowlist, kernel range, and six userspace/firmware capabilities. Parsing validates structure and immutable identities; qualification remains a separate evidence-backed release decision.

## Top-level fields

| Field | Type | Requirement |
|---|---|---|
| `schema_version` | integer | Must equal `1`. |
| `id` | string | Nonempty stable profile identifier. |
| `stack_release` | string | Nonempty stack release that consumes the profile. |
| `status` | enum | `candidate`, `experimental`, `qualified`, `unsupported`, or `deprecated`. |
| `package_manager` | enum | `rpm`, `dpkg`, or `pacman`; Phase 2 implements inspection for `rpm`. |
| `conflicts` | array of tables | Sorted, unique native package names with resolution `remove`; maximum 32. |
| `platform` | table | Exact OS and architecture selector. |
| `hardware` | array of tables | At least one lowercase four-digit PCI vendor/device pair. |
| `kernel` | table | Numeric inclusive minimum, exclusive maximum, and exact module. |
| `components` | table | Exactly the six required logical capabilities. |
| `qualification` | optional table | Required when status is `qualified`. |

Unknown fields are rejected at every serialized table boundary.

## Platform and hardware

`platform.id`, `platform.version_id`, and `platform.arch` are nonempty strings compared exactly with detected OS `ID`, `VERSION_ID`, and architecture. `ID_LIKE` never authorizes a match.

Every `hardware` entry has lowercase four-digit hexadecimal `vendor` and `device` fields. A platform matches when at least one detected normalized PCI pair equals an allowlisted pair. PCI bus addresses are neither stored in profiles nor emitted in diagnostics.

`kernel.min` is inclusive and `kernel.max_exclusive` is exclusive. Each is a numeric `major.minor.patch`; a distribution suffix introduced by `-` may follow the patch. The minimum must be lower than the maximum. `kernel.module` must be exactly `intel_vpu`, and selection also requires that exact module to be loaded.

## Required component capabilities

`components` contains exactly these keys:

- `npu_firmware`
- `level_zero_loader`
- `npu_userspace_driver`
- `npu_compiler`
- `openvino_runtime`
- `openvino_npu_plugin`

Each component contains a nonempty `version`, a nonempty `https://` `source` with no whitespace, and a 64-character lowercase hexadecimal `sha256`. It also contains:

- `provider.package`: exact native package name;
- `provider.version`: exact native version including distribution release;
- `provider.activation`: `immediate`, `reboot`, or `relogin`;
- `provider.files`: one through 16 critical installed files, each with an approved absolute path and lowercase SHA-256;
- `license.expression`: nonempty SPDX expression recorded by qualification;
- `license.redistribution`: `allowed`, `external_only`, or `forbidden`;
- `license.evidence_sha256`: digest of the reviewed license/provenance record.

Package names allow only ASCII letters, digits, `.`, `+`, `-`, and `_`. Package versions additionally allow `:`, `~`, and `^`. These fields are inert data and are never shell fragments. Critical paths must be normalized beneath `/usr/bin/`, `/usr/lib/`, `/usr/lib64/`, `/usr/libexec/`, `/usr/share/`, or `/usr/lib/firmware/`; control characters, repeated separators, dot components, parent components, and trailing separators are rejected.

These six components form one compatibility matrix; independently newer versions are never combined automatically.

### Generated Fedora candidate evidence

The Fedora generator accepts exactly fourteen runtime RPMs: the twelve provider
packages, the tools package and the empty metapackage. Development, debug and
source RPMs belong to separate build evidence. It validates exact NEVRs and
architectures, required payload paths, executable modes, reviewed license
expressions, package-owned license notices, internal version pins, absence of
scripts and cross-package file overlap. RPM queries use fixed argument arrays,
cleared environments, output bounds and deadlines; they do not execute scripts.

For this generated profile, each component's `source` identifies its upstream
provenance repository, while `sha256` identifies the supplied provider RPM.
It is not a checksum for a download from that repository URL. The JSON generation
report records exact RPM filenames and SHA-256 values for all fourteen packages,
their queried file metadata, the source-lock digest and the profile-file digest.
Store this report outside source archives. The tools RPM's digest cannot be
embedded in its own installed manifest or source inputs.

Each component's license evidence digest is SHA-256 of compact JSON serialized
as `[source_lock_sha256, rpm_sha256, license_expression, license_owner_package,
license_owner_rpm_sha256, license_files]`. OpenVINO subpackages may use the main
OpenVINO RPM's notices only with an exact dependency, the same source-RPM identity
and the same reviewed license expression. The owner must contain regular files
marked as licenses. The generation report retains each source-RPM identity.
`license_files` is the owner's path-sorted list of files marked as RPM licenses;
each record has fields `path`, `sha256`, `mode` and `license`, in that order.
The generation report preserves the inputs needed to reconstruct this record.
Matching a reviewed expression and binding its notices does not replace the
release review of actual redistribution and complete source availability.

The Level Zero loader is the project's own source-locked
`oneapi-level-zero-1.32.0-1.intelnpu.fc44` build matching the driver's matrix
and is recorded as `allowed`. The earlier distro-owned `external_only`
recording applied only to the retired Fedora 1.28.6 deviation. The source lock
identifies the source matrix; the profile identifier matches the tools'
installed manifest. Candidate kernel bounds identify a narrow test target, not
a qualified support range.

A qualified profile may admit a kernel series, for example `[7.2.5, 7.3.0)`,
chosen in its promotion change. Its qualification evidence names the kernels
it was collected on, and each of them lies inside the window. Newer kernels in
the window are admitted by policy, observed by the kernel watcher and need a
recorded per-kernel probe; a new series needs a new qualification. See
[Kernel window and per-kernel probes](kernel-probes.md).

## Status and channel policy

| Status | Stable channel | Experimental channel |
|---|---:|---:|
| `qualified` | eligible | eligible with risk acceptance |
| `experimental` | rejected | eligible with risk acceptance |
| `candidate` | rejected | rejected |
| `unsupported` | rejected | rejected |
| `deprecated` | rejected | rejected |

The experimental channel requires `--accept-experimental-risk`. Supplying that flag with the stable channel is an error. The approved release workflow currently authorizes only the evidence-backed `candidate` to `qualified` promotion; it occurs through a separately reviewed promotion change and never through parsing, validation, upstream discovery, or hardware-test automation. Any other status transition requires an explicit future design decision and cannot inherit qualification from a similar profile.

A `qualified` profile has a `qualification` table with nonempty `evidence_id`, `qualified_at`, `hardware_class`, and `test_suite_version` values plus lowercase `evidence_sha256`. It may not contain a component whose redistribution verdict is `forbidden`. Schema validation checks shape and completeness, not the truth of the evidence; protected release automation must independently bind and verify the evidence and exact artifact digests.

## Resource limits

Readers reject profile input larger than 1,048,576 bytes, any scalar string larger than 4096 UTF-8 bytes, more than 64 hardware identifiers, more than 32 conflicts, or a component with fewer than one or more than 16 critical files. These limits apply before runtime inspection.

## Selection rules

Selection requires all of the following:

1. Status is admitted by the requested channel.
2. OS `ID`, `VERSION_ID`, and architecture match exactly.
3. At least one normalized PCI ID matches exactly.
4. The detected numeric kernel is within the profile's half-open range.
5. The profile names `intel_vpu` and that exact module is loaded.
6. Exactly one profile matches; zero is unsupported and more than one is an ambiguity error.

Selection output is deterministic and independent of profile input order.

## Stable schema errors

| Code | Meaning |
|---|---|
| `PROFILE_TOML_INVALID` | TOML syntax, type, required field, or unknown field is invalid. |
| `PROFILE_SCHEMA_UNSUPPORTED` | `schema_version` is not supported. |
| `PROFILE_FIELD_INVALID` | A semantic string, source, component key, or kernel module is invalid. |
| `PROFILE_PCI_ID_INVALID` | Hardware is empty or a PCI ID is not normalized lowercase hexadecimal. |
| `PROFILE_HASH_INVALID` | A component SHA-256 is not 64 lowercase hexadecimal characters. |
| `PROFILE_COMPONENT_MISSING` | One of the six required component keys is absent. |
| `PROFILE_QUALIFICATION_MISSING` | A qualified profile lacks complete qualification metadata. |
| `PROFILE_KERNEL_RANGE_INVALID` | Kernel range ordering is invalid. |
| `PROFILE_RESOURCE_LIMIT` | Input, scalar, hardware, conflict, or critical-file bounds are exceeded. |
| `PROFILE_PACKAGE_INVALID` | A package name/version is unsafe, or conflicts are not sorted and unique. |
| `PROFILE_PATH_INVALID` | A critical file path is not normalized beneath an approved system prefix. |
| `PROFILE_PROVENANCE_INVALID` | License or qualification provenance is malformed or incompatible with qualification. |

The offline directory validator additionally reports `PROFILE_SYMLINK_REJECTED` and `DUPLICATE_PROFILE_ID` for directory-level safety and uniqueness failures.

## Compatibility and migration

Readers accept only schema version 1 and fail closed on every other version. The provider, conflict, license, and expanded qualification fields are the approved correction to the unpublished Phase 1 version-1 shape; no production profile or released consumer used the earlier shape. After this correction is frozen, adding optional fields, removing fields, changing meanings, or loosening validation must not be done silently. A later schema change requires a new version, explicit compatibility tests, documented migration rules, and review of every consumer before any production profile adopts it.

Files under `fixtures/profiles/` use the fictional OS `testos`, PCI device `8086:abcd`, `example.invalid` sources, and fixture-only evidence. They demonstrate parsing behavior and can never qualify a production platform.
