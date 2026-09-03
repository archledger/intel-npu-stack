// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod error;
mod kernel;
mod profile;

pub use error::SchemaError;
pub use kernel::KernelVersion;
pub use profile::{
    ComponentRequirement, KernelRange, PciId, PlatformSelector, Profile, ProfileStatus,
    QualificationRecord,
};

/// Version of the profile format accepted by this release.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;
