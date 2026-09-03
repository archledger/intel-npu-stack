// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Stable validation error returned for an invalid capability profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct SchemaError {
    pub code: &'static str,
    pub message: String,
}

impl SchemaError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
