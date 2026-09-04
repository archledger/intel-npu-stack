// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod activity;
mod device;
mod inspect;
mod package;
mod process;
mod protocol;
mod strict_json;

pub use activity::{
    ActivationInspection, ActivationState, BusyCounterSnapshot, BusyCounters, evaluate_activity,
    inspect_activation, read_busy_counters,
};
pub use device::{DeviceInspection, inspect_devices};
pub use inspect::{
    ActivityInspector, DeviceInspector, FilesystemDeviceInspector, InspectionResult,
    RuntimeInspector, RuntimePaths, SysfsActivityInspector,
};
pub use package::{InstalledPackage, PackageInspection, PackageInspector, RpmPackageInspector};
pub use process::{
    ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, SystemProcessRunner, Termination,
};
pub use protocol::{
    LevelZeroDevice, LevelZeroObservation, MAX_PROBE_STDOUT, OpenVinoEnumerateObservation,
    OpenVinoInferObservation, ProbeErrorCode, ProbeKind, ProbeMode, ProbeObservations,
    ProbeOutcome, ProbeReport, ProtocolError, parse_probe_output,
};
