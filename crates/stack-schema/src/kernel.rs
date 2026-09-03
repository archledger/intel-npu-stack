// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::SchemaError;

/// Numeric Linux kernel version used for profile range comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl KernelVersion {
    /// Parses `major.minor.patch` and permits a nonempty distribution suffix
    /// introduced by `-`.
    pub fn parse_release(value: &str) -> Result<Self, SchemaError> {
        if value.is_empty() || value.trim() != value {
            return Err(invalid_kernel(value));
        }

        let (numeric, suffix) = match value.split_once('-') {
            Some((numeric, suffix)) if !suffix.is_empty() => (numeric, Some(suffix)),
            Some(_) => return Err(invalid_kernel(value)),
            None => (value, None),
        };
        if suffix.is_some_and(|suffix| suffix.chars().any(char::is_whitespace)) {
            return Err(invalid_kernel(value));
        }

        let components = numeric.split('.').collect::<Vec<_>>();
        if components.len() != 3
            || components.iter().any(|component| {
                component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(invalid_kernel(value));
        }

        let parse = |component: &str| component.parse::<u64>().map_err(|_| invalid_kernel(value));

        Ok(Self {
            major: parse(components[0])?,
            minor: parse(components[1])?,
            patch: parse(components[2])?,
        })
    }
}

fn invalid_kernel(value: &str) -> SchemaError {
    SchemaError::new(
        "PROFILE_FIELD_INVALID",
        format!("invalid kernel release {value:?}"),
    )
}
