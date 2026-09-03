// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::PlatformError;

/// Required operating-system identity fields from `os-release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
}

/// Parses `os-release` assignments as data without invoking a shell.
pub fn parse_os_release(input: &str) -> Result<OsRelease, PlatformError> {
    let mut values = BTreeMap::new();

    for (index, line) in input.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            invalid_os_release(format!("line {} is not an assignment", index + 1))
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(invalid_os_release(format!(
                "line {} has an invalid key",
                index + 1
            )));
        }

        let value = parse_value(raw_value)
            .map_err(|message| invalid_os_release(format!("line {} {message}", index + 1)))?;
        if values.insert(key, value).is_some() {
            return Err(invalid_os_release(format!("duplicate key {key}")));
        }
    }

    let required = |key: &str| {
        values
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| invalid_os_release(format!("missing or empty {key}")))
    };

    Ok(OsRelease {
        id: required("ID")?,
        version_id: required("VERSION_ID")?,
    })
}

fn parse_value(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Ok(String::new());
    }

    let bytes = raw.as_bytes();
    match bytes[0] {
        b'\'' => {
            if raw.len() < 2 || !raw.ends_with('\'') {
                return Err("has an unmatched single quote");
            }
            let inner = &raw[1..raw.len() - 1];
            if inner.contains('\'') {
                return Err("has an embedded single quote");
            }
            Ok(inner.to_owned())
        }
        b'"' => {
            if raw.len() < 2 || !raw.ends_with('"') {
                return Err("has an unmatched double quote");
            }
            unescape_double_quoted(&raw[1..raw.len() - 1])
        }
        _ => {
            if raw.contains(char::is_whitespace) || raw.contains(['\'', '"']) {
                return Err("has invalid unquoted characters");
            }
            Ok(raw.to_owned())
        }
    }
}

fn unescape_double_quoted(inner: &str) -> Result<String, &'static str> {
    let mut output = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }

        let escaped = chars.next().ok_or("ends with a backslash")?;
        match escaped {
            '\\' | '"' | '$' | '`' => output.push(escaped),
            _ => {
                output.push('\\');
                output.push(escaped);
            }
        }
    }
    Ok(output)
}

fn invalid_os_release(message: impl Into<String>) -> PlatformError {
    PlatformError::new("PLATFORM_OS_RELEASE_INVALID", message)
}
