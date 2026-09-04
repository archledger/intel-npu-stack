// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod package;
mod process;
mod protocol;
mod strict_json;

pub use package::{InstalledPackage, PackageInspection, PackageInspector, RpmPackageInspector};
pub use process::{
    ProcessError, ProcessOutput, ProcessRequest, ProcessRunner, SystemProcessRunner, Termination,
};
pub use protocol::{
    LevelZeroDevice, LevelZeroObservation, MAX_PROBE_STDOUT, OpenVinoEnumerateObservation,
    OpenVinoInferObservation, ProbeErrorCode, ProbeKind, ProbeMode, ProbeObservations,
    ProbeOutcome, ProbeReport, ProtocolError, parse_probe_output,
};
