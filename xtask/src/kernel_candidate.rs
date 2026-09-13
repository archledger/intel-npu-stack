// SPDX-License-Identifier: Apache-2.0

//! Narrow, evidence-preserving kernel retargeting of unqualified candidates.

use stack_schema::{KernelVersion, Profile, ProfileStatus};

/// Creates a separately identified candidate covering only one kernel patch.
///
/// Preserves every other byte, including source evidence comments. The caller
/// must retain the original and validate new release artifacts independently.
/// No hardware qualification or promotion is performed.
///
/// # Errors
///
/// Rejects invalid/non-candidate profiles, reused or unsafe identities, malformed
/// kernels, patch overflow and unexpected input formatting.
pub fn retarget(input: &str, id: &str, kernel_release: &str) -> Result<String, String> {
    let original = Profile::parse_toml(input).map_err(|error| error.to_string())?;
    if original.status != ProfileStatus::Candidate || original.qualification.is_some() {
        return Err("kernel retargeting requires an unqualified candidate".to_owned());
    }
    if id == original.id
        || id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err("a distinct, filesystem-safe candidate id is required".to_owned());
    }
    let kernel = KernelVersion::parse_release(kernel_release).map_err(|error| error.to_string())?;
    let next = kernel.patch.checked_add(1).ok_or("kernel patch overflow")?;
    let minimum = format!("{}.{}.{}", kernel.major, kernel.minor, kernel.patch);
    let maximum = format!("{}.{}.{}", kernel.major, kernel.minor, next);
    let replacements = [
        (
            format!("id = \"{}\"", original.id),
            format!("id = \"{id}\""),
        ),
        (
            format!("min = \"{}\"", original.kernel.min),
            format!("min = \"{minimum}\""),
        ),
        (
            format!("max_exclusive = \"{}\"", original.kernel.max_exclusive),
            format!("max_exclusive = \"{maximum}\""),
        ),
    ];
    let mut output = input.to_owned();
    for (old, new) in replacements {
        if output.split('\n').filter(|line| *line == old).count() != 1 {
            return Err(
                "candidate selector line is ambiguous or unexpectedly formatted".to_owned(),
            );
        }
        output = output
            .split('\n')
            .map(|line| if line == old { new.as_str() } else { line })
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut restored = Profile::parse_toml(&output).map_err(|error| error.to_string())?;
    restored.id = original.id.clone();
    restored.kernel.min = original.kernel.min.clone();
    restored.kernel.max_exclusive = original.kernel.max_exclusive.clone();
    if restored != original {
        return Err("kernel retargeting changed unrelated profile semantics".to_owned());
    }
    Ok(output)
}

/// Writes a new candidate file, refusing to overwrite any existing path.
///
/// # Errors
///
/// Returns input-validation, read, create-new or write errors. The original
/// candidate is never edited.
pub fn generate(
    candidate: &std::path::Path,
    id: &str,
    kernel_release: &str,
    output: &std::path::Path,
) -> Result<serde_json::Value, String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let input = crate::candidate_collection::read_profile(candidate)?;
    let text = retarget(&input, id, kernel_release)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| error.to_string())?;
    file.write_all(text.as_bytes())
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "schema_version": 1, "qualification_complete": false,
        "original_sha256": format!("{:x}", Sha256::digest(input.as_bytes())),
        "candidate_sha256": format!("{:x}", Sha256::digest(text.as_bytes())),
        "candidate_id": id, "kernel_release": kernel_release,
        "changed_fields": ["id", "kernel.min", "kernel.max_exclusive"]
    }))
}
