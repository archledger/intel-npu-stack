// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

mod linux;
mod os_release;

use thiserror::Error;

pub use linux::{PlatformFacts, PlatformPaths, detect_platform};
pub use os_release::{OsRelease, parse_os_release};

/// Stable error returned while collecting platform facts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct PlatformError {
    pub code: &'static str,
    pub message: String,
}

impl PlatformError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
