// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

pub mod candidate_collection;
pub mod fedora_openvino_package;
pub mod fedora_package;
pub mod fedora_profile;
pub mod kernel_candidate;
pub mod source_bundle;
pub mod source_lock;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use stack_schema::Profile;
use thiserror::Error;

/// Failure class returned by offline profile validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationFailure {
    /// At least one profile failed a content or safety check.
    #[error("one or more profiles are invalid")]
    InvalidProfiles,
    /// A required filesystem operation failed.
    #[error("filesystem error: {0}")]
    Io(String),
    /// The caller-provided output stream failed.
    #[error("output error: {0}")]
    Output(String),
}

impl ValidationFailure {
    /// Returns the command-line exit code for this failure class.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::InvalidProfiles => 1,
            Self::Io(_) | Self::Output(_) => 2,
        }
    }
}

#[derive(Debug)]
struct Candidate {
    filename: String,
    path: PathBuf,
    kind: CandidateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    File,
    Symlink,
}

/// Validates all direct regular `*.toml` profiles in deterministic order.
///
/// Symlinked profiles are rejected and subdirectories are not traversed.
///
/// # Errors
///
/// Returns [`ValidationFailure::InvalidProfiles`] after reporting every
/// invalid candidate, or an I/O/output variant when validation cannot finish.
pub fn validate_profiles_dir(path: &Path, output: &mut dyn Write) -> Result<(), ValidationFailure> {
    let entries = fs::read_dir(path).map_err(|error| ValidationFailure::Io(error.to_string()))?;
    let mut candidates = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| ValidationFailure::Io(error.to_string()))?;
        let filename = entry.file_name();
        let Some(filename_utf8) = filename.to_str() else {
            return Err(ValidationFailure::Io(
                "profile directory contains a non-UTF-8 filename".to_owned(),
            ));
        };
        if Path::new(filename_utf8)
            .extension()
            .and_then(|value| value.to_str())
            != Some("toml")
        {
            continue;
        }

        let file_type = entry
            .file_type()
            .map_err(|error| ValidationFailure::Io(error.to_string()))?;
        let kind = if file_type.is_symlink() {
            CandidateKind::Symlink
        } else if file_type.is_file() {
            CandidateKind::File
        } else {
            continue;
        };
        candidates.push(Candidate {
            filename: filename_utf8.to_owned(),
            path: entry.path(),
            kind,
        });
    }
    candidates.sort_by(|left, right| left.filename.cmp(&right.filename));

    validate_candidates(candidates, output)
}

fn validate_candidates(
    candidates: Vec<Candidate>,
    output: &mut dyn Write,
) -> Result<(), ValidationFailure> {
    let mut valid_ids = BTreeMap::<String, String>::new();
    let mut invalid_count = 0_usize;

    for candidate in candidates {
        if candidate.kind == CandidateKind::Symlink {
            write_line(
                output,
                format_args!(
                    "error {} PROFILE_SYMLINK_REJECTED profile is a symlink",
                    candidate.filename
                ),
            )?;
            invalid_count += 1;
            continue;
        }

        let input = fs::read_to_string(&candidate.path)
            .map_err(|error| ValidationFailure::Io(error.to_string()))?;
        match Profile::parse_toml(&input) {
            Ok(profile) => {
                if let Some(first_filename) = valid_ids.get(&profile.id) {
                    write_line(
                        output,
                        format_args!(
                            "error {} DUPLICATE_PROFILE_ID profile id {} already appeared in {}",
                            candidate.filename, profile.id, first_filename
                        ),
                    )?;
                    invalid_count += 1;
                } else {
                    write_line(
                        output,
                        format_args!("ok {} {}", candidate.filename, profile.id),
                    )?;
                    valid_ids.insert(profile.id, candidate.filename);
                }
            }
            Err(error) => {
                write_line(
                    output,
                    format_args!(
                        "error {} {} {}",
                        candidate.filename, error.code, error.message
                    ),
                )?;
                invalid_count += 1;
            }
        }
    }

    if invalid_count == 0 {
        write_line(
            output,
            format_args!("validated {} profiles", valid_ids.len()),
        )?;
        Ok(())
    } else {
        let noun = if invalid_count == 1 {
            "profile"
        } else {
            "profiles"
        };
        write_line(
            output,
            format_args!("validation failed: {invalid_count} invalid {noun}"),
        )?;
        Err(ValidationFailure::InvalidProfiles)
    }
}

fn write_line(
    output: &mut dyn Write,
    arguments: std::fmt::Arguments<'_>,
) -> Result<(), ValidationFailure> {
    writeln!(output, "{arguments}").map_err(|error| ValidationFailure::Output(error.to_string()))
}
