# Capability profile schema version 1

An `intel-npu-stack` profile is one independently reviewed compatibility matrix. It binds an exact operating-system release, architecture, PCI hardware allowlist, kernel range, and six userspace/firmware capabilities. Parsing validates structure and immutable identities; qualification remains a separate evidence-backed release decision.

## Top-level fields

| Field | Type | Requirement |
|---|---|---|
| `schema_version` | integer | Must equal `1`. |
| `id` | string | Nonempty stable profile identifier. |
| `stack_release` | string | Nonempty stack release that consumes the profile. |
| `status` | enum | `candidate`, `experimental`, `qualified`, `unsupported`, or `deprecated`. |
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

Each component contains a nonempty `version`, a nonempty `https://` `source` with no whitespace, and a 64-character lowercase hexadecimal `sha256`. These six components form one compatibility matrix; independently newer versions are never combined automatically.

## Status and channel policy

| Status | Stable channel | Experimental channel |
|---|---:|---:|
| `qualified` | eligible | eligible with risk acceptance |
| `experimental` | rejected | eligible with risk acceptance |
| `candidate` | rejected | rejected |
| `unsupported` | rejected | rejected |
| `deprecated` | rejected | rejected |

The experimental channel requires `--accept-experimental-risk`. Supplying that flag with the stable channel is an error. The approved release workflow currently authorizes only the evidence-backed `candidate` to `qualified` promotion; it occurs through a separately reviewed promotion change and never through parsing, validation, upstream discovery, or hardware-test automation. Any other status transition requires an explicit future design decision and cannot inherit qualification from a similar profile.

A `qualified` profile has a `qualification` table with nonempty `evidence_id` and `qualified_at` values. Schema validation checks their presence, not the truth of the evidence; protected release automation must independently bind and verify the evidence and exact artifact digests.

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

The offline directory validator additionally reports `PROFILE_SYMLINK_REJECTED` and `DUPLICATE_PROFILE_ID` for directory-level safety and uniqueness failures.

## Compatibility and migration

Readers accept only schema version 1 and fail closed on every other version. Adding optional fields, removing fields, changing meanings, or loosening validation must not be done silently. A schema change requires a new version, explicit compatibility tests, documented migration rules, and review of every consumer before any production profile adopts it.

Files under `fixtures/profiles/` use the fictional OS `testos`, PCI device `8086:abcd`, `example.invalid` sources, and fixture-only evidence. They demonstrate parsing behavior and can never qualify a production platform.
