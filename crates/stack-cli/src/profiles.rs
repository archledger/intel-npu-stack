// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use stack_schema::Profile;

const MAX_PROFILE_BYTES: u64 = 1_048_576;

pub(crate) fn load_profiles(directory: &Path) -> Result<Vec<Profile>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read profile directory: {error}"))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read profile entry: {error}"))?;
        let filename = entry.file_name();
        let display_name = filename.to_string_lossy().into_owned();
        if Path::new(&filename)
            .extension()
            .and_then(|value| value.to_str())
            != Some("toml")
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect profile {display_name}: {error}"))?;
        if file_type.is_symlink() {
            return Err(format!("profile {display_name} is a symlink"));
        }
        if !file_type.is_file() {
            continue;
        }
        candidates.push((display_name, entry.path()));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));

    candidates
        .into_iter()
        .map(|(filename, path)| {
            let file = File::open(&path)
                .map_err(|error| format!("cannot read profile {filename}: {error}"))?;
            let mut input = String::new();
            file.take(MAX_PROFILE_BYTES + 1)
                .read_to_string(&mut input)
                .map_err(|error| format!("cannot read profile {filename}: {error}"))?;
            Profile::parse_toml(&input)
                .map_err(|error| format!("invalid profile {filename}: {error}"))
        })
        .collect()
}
