// SPDX-License-Identifier: Apache-2.0

/// Compiled-in release trust for this installer build.
///
/// The public keyring is the pinned production release-signing key and the
/// primary fingerprint names it. The base URL is the immutable versioned
/// release location. The metadata digest is the one release-time value: the
/// release workflow (scripts/ci/release_installer.py) overlays it with the
/// SHA-256 of the signed release.json in a `git archive` export of the
/// tagged commit before building the published installer. A binary built
/// from this source therefore fails closed on the metadata digest instead
/// of trusting downloaded metadata. Nothing here may be supplied through
/// the environment.
pub(crate) const VERSION: &str = "0.1.1";

pub(crate) const BASE_URL: &str = "https://archledger.github.io/intel-npu-stack/0.1.1/";

pub(crate) const METADATA_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const PRIMARY_FINGERPRINT: &str = "1085FBE578732D1CF0C50417A8FE2F718B8763D8";

pub(crate) const KEYRING: &[u8] = include_bytes!("trust/release-public.asc");
