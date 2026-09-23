# Kernel window and per-kernel probes

A qualified profile admits one kernel series through its half-open
`[kernel] min`/`max_exclusive` window, for example `[7.2.5, 7.3.0)`. The window
is chosen when the profile is promoted and must contain every kernel on which
the qualification evidence was collected. Kernels inside the window that were
not part of that evidence are admitted by policy; each one needs a recorded
per-kernel probe. A kernel at or above `max_exclusive` is refused until a
profile is qualified for its series.

Candidate profiles keep single-kernel windows produced by `retarget-candidate`;
this policy applies only to qualified profiles.

## Watching

`.github/workflows/kernel-watch.yml` runs daily. `scripts/ci/check_kernels.py`
reads Fedora 44 kernel updates from Bodhi (stable and testing), compares them
with the windows of every qualified Fedora 44 profile and with
`release/kernel-probes.json`, and opens one deduplicated issue per kernel:

- `probe-required`: inside a qualified window without a passing probe.
- `requalification-required`: above every qualified window.

The workflow can only read the repository and write issues. Until a profile is
qualified it reports nothing to watch.

## Recording a probe

On the qualification hardware, after booting the new kernel:

1. Confirm the kernel release (`uname -r`), that the installed stack is
   unchanged (`rpm -V` of the runtime packages) and that the boot image carries
   the stack's NPU firmware.
2. Run `intel-npu-stack doctor` on the stable channel as a normal user. It must
   pass every check, including direct NPU inference.
3. Keep the doctor JSON and the identity checks together as the probe evidence
   and note its SHA-256.
4. Add an entry to `release/kernel-probes.json` in a reviewed change:

```json
{"kernel": "7.2.7-200.fc44", "result": "pass", "evidence_sha256": "<sha256>", "recorded": "2026-09-24"}
```

A failing probe is recorded with `"result": "fail"`; the kernel then needs a
fix or a narrower window before the issue is closed.
