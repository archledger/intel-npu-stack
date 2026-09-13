// SPDX-License-Identifier: Apache-2.0

/// Compiled-in release trust for this installer build.
///
/// The release assembly pins the final values when the signed release is
/// composed; this candidate entry deliberately holds an unpinned digest,
/// fingerprint and keyring envelope so a binary built from this state fails
/// closed at transport or trust verification instead of trusting downloaded
/// metadata. Nothing here may be supplied through the environment.
pub(crate) const VERSION: &str = "0.1.0";

pub(crate) const BASE_URL: &str =
    "https://downloads.example.invalid/intel-npu-stack/0.1.0/fedora/44/x86_64/";

pub(crate) const METADATA_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const PRIMARY_FINGERPRINT: &str = "0000000000000000000000000000000000000000";

pub(crate) const KEYRING: &[u8] = include_bytes!("trust/release-public.asc");
