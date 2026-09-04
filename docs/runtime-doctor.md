# Runtime status and doctor

`intel-npu-stack` provides two read-only diagnostic commands. Neither command installs packages, changes configuration, loads kernel modules, alters permissions, or downloads a model.

```text
intel-npu-stack status [--json] [--channel stable|experimental]
intel-npu-stack doctor [--json] [--channel stable|experimental]
```

The experimental channel additionally requires `--accept-experimental-risk`. Helper, RPM, root, timeout, and check-skipping options are intentionally not public; production inspection uses package-owned absolute paths and fixed deadlines.

## Choosing a command

`status` inventories the selected profile, exact provider packages and critical-file digests, kernel/module state, device-node access, Level Zero VPU discovery, and OpenVINO NPU discovery. It does not compile a graph or run inference.

`doctor` performs the same checks, then asks the OpenVINO helper to build the project’s small in-memory graph, compile it directly for `NPU`, and run eight synchronous inferences. It does not use `AUTO`, `MULTI`, `HETERO`, CPU fallback, a downloaded model, or a model file. A successful inference report is accepted only when every reported execution device is an NPU and the fixed output is within tolerance.

Run `doctor` as the normal desktop user whose access matters. When run as root, `device.access` is `blocked` with `NORMAL_USER_REQUIRED`; a root invocation cannot prove normal-user access or produce an overall passing doctor result.

## Stable checks

Both commands emit these checks, sorted by ID:

| Check | Meaning |
|---|---|
| `platform.profile` | One compatible, policy-admitted profile was selected. |
| `package.level_zero_loader` | The exact native provider and critical files match the profile. |
| `package.npu_compiler` | The exact native provider and critical files match the profile. |
| `package.npu_firmware` | The exact native provider and critical files match the profile. |
| `package.npu_userspace_driver` | The exact native provider and critical files match the profile. |
| `package.openvino_npu_plugin` | The exact native provider and critical files match the profile. |
| `package.openvino_runtime` | The exact native provider and critical files match the profile. |
| `kernel.module` | The `intel_vpu` kernel module is loaded. |
| `firmware.installed` | The firmware provider matches and its activation state is known. |
| `device.node` | At least one direct accelerator node is present. |
| `device.access` | The relevant normal-user context can open an accelerator node read-write. |
| `runtime.level_zero` | Level Zero exposes an Intel VPU matching the selected profile. |
| `runtime.openvino` | OpenVINO exposes an NPU. |

`doctor` additionally emits:

| Check | Meaning |
|---|---|
| `runtime.inference` | The neutral graph compiled directly for NPU and produced the expected result. |
| `runtime.activity` | An available NPU busy-time counter increased during inference. |

All checks except `runtime.activity` are required. Activity is supporting evidence: an absent, unreadable, invalid, decreasing, or unchanged counter produces a warning and a `degraded` result, not a false failure of otherwise proven direct-NPU inference. `reboot_required` becomes true when a matching provider marked for reboot was installed after the current boot. `relogin_required` remains false in this phase because the read-only verifier has no distribution-neutral proof that a new login will repair access.

## Deadlines and process boundary

The fixed subprocess deadlines are:

| Operation | Deadline |
|---|---:|
| Each RPM package or ownership query | 10 seconds |
| Level Zero enumeration | 10 seconds |
| OpenVINO enumeration | 15 seconds |
| OpenVINO compile and inference | 120 seconds |

The CLI launches the two native helpers directly by absolute package-owned path, clears their inherited environment, supplies only `LC_ALL=C`, closes stdin, drains stdout and stderr concurrently, and kills and reaps a helper that exceeds its deadline. Helper stdout is capped at 64 KiB and must be one strict version-1 JSON object. Stderr is drained with a 16 KiB cap but discarded.

## Stable error codes

Reports may include only these allowlisted diagnostic codes in `details.error_code`:

- Process/protocol: `PROBE_EXECUTABLE_MISSING`, `PROBE_PROCESS_FAILED`, `PROBE_TIMEOUT`, `PROBE_OUTPUT_TOO_LARGE`, `PROBE_OUTPUT_INVALID`, `PROBE_SCHEMA_UNSUPPORTED`.
- Level Zero: `LEVEL_ZERO_PERMISSION_DENIED`, `LEVEL_ZERO_DEPENDENCY_UNAVAILABLE`, `LEVEL_ZERO_NO_VPU`, `LEVEL_ZERO_ENUMERATION_FAILED`, `LEVEL_ZERO_INTERNAL_FAILURE`.
- OpenVINO: `OPENVINO_NO_NPU`, `OPENVINO_ENUMERATION_FAILED`, `OPENVINO_COMPILE_FAILED`, `OPENVINO_WRONG_DEVICE`, `OPENVINO_INFERENCE_FAILED`, `OPENVINO_OUTPUT_INVALID`, `OPENVINO_INTERNAL_FAILURE`.
- Providers: `PACKAGE_NOT_INSTALLED`, `PACKAGE_VERSION_MISMATCH`, `PACKAGE_QUERY_FAILED`, `PACKAGE_OUTPUT_INVALID`, `PACKAGE_OWNERSHIP_MISMATCH`, `PACKAGE_FILE_MISSING`, `PACKAGE_FILE_INVALID`, `PACKAGE_FILE_UNREADABLE`, `PACKAGE_DIGEST_MISMATCH`, `PACKAGE_CONFLICT`, `PACKAGE_INSPECTOR_UNAVAILABLE`.
- Host state: `KERNEL_MODULE_MISSING`, `DEVICE_NODE_MISSING`, `DEVICE_ACCESS_DENIED`, `DEVICE_ACCESS_FAILED`, `NORMAL_USER_REQUIRED`, `ACTIVATION_STATE_UNKNOWN`.
- Optional activity: `ACTIVITY_COUNTER_UNAVAILABLE`, `ACTIVITY_COUNTER_INVALID`, `ACTIVITY_COUNTER_DECREASED`, `ACTIVITY_NOT_OBSERVED`.

Raw RPM output, native stderr, loader or exception messages, environment variables, usernames, UIDs, group names, filesystem paths, PCI bus addresses, UUIDs, serial numbers, and network addresses are never copied into either output mode. JSON contains only the versioned report fields and allowlisted details; human output prints the same checks as `id [status]: summary` without details.

## Results and exit status

- Exit `0`: all required checks passed. Optional warnings make the result `degraded` but retain exit 0.
- Exit `1`: a completed diagnostic is `failed` or `blocked`, including missing hardware, providers, access, or runtime functionality.
- Exit `2`: command misuse, unreadable or invalid installed profile data, or output failure.

A passing diagnostic shows that the selected candidate stack works at the time and in the user context tested. It is not profile qualification, a support declaration, or permission to publish a stable profile; those require the separate qualification and release gates.
