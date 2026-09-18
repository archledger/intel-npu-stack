// SPDX-License-Identifier: Apache-2.0

/// Compiled-in release trust for this installer build.
///
/// The public keyring is the pinned production release-signing key. The
/// version, base URL, metadata digest and primary fingerprint remain
/// release-time values: the release assembly pins them when the signed
/// release is composed, so a binary built from this source-preview state
/// fails closed at transport or trust verification instead of trusting
/// downloaded metadata. Nothing here may be supplied through the
/// environment.
pub(crate) const VERSION: &str = "0.1.0";

pub(crate) const BASE_URL: &str =
    "https://downloads.example.invalid/intel-npu-stack/0.1.0/fedora/44/x86_64/";

pub(crate) const METADATA_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const PRIMARY_FINGERPRINT: &str = "0000000000000000000000000000000000000000";

pub(crate) const KEYRING: &[u8] = include_bytes!("trust/release-public.asc");
