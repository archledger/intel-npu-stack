// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use stack_platform::PlatformFacts;
use stack_schema::{KernelVersion, Profile, ProfileStatus};
use thiserror::Error;

/// User-selected profile channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Stable,
    Experimental,
}

/// Selection policy supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionPolicy {
    pub channel: Channel,
    pub acknowledge_risk: bool,
}

/// Deterministic profile-selection failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SelectionError {
    #[error("no compatible profile")]
    NoCompatibleProfile,
    #[error("experimental channel requires explicit risk acknowledgement")]
    RiskAcknowledgementRequired,
    #[error("multiple compatible profiles: {0:?}")]
    AmbiguousProfiles(Vec<String>),
}

/// Selects exactly one installable profile for the supplied platform facts.
pub fn select_profile<'a>(
    profiles: &'a [Profile],
    facts: &PlatformFacts,
    policy: &SelectionPolicy,
) -> Result<&'a Profile, SelectionError> {
    if policy.channel == Channel::Experimental && !policy.acknowledge_risk {
        return Err(SelectionError::RiskAcknowledgementRequired);
    }

    let mut matches = profiles
        .iter()
        .filter(|profile| status_allowed(profile.status, policy.channel))
        .filter(|profile| platform_matches(profile, facts))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.id.cmp(&right.id));

    match matches.as_slice() {
        [] => Err(SelectionError::NoCompatibleProfile),
        [profile] => Ok(profile),
        _ => Err(SelectionError::AmbiguousProfiles(
            matches.iter().map(|profile| profile.id.clone()).collect(),
        )),
    }
}

fn status_allowed(status: ProfileStatus, channel: Channel) -> bool {
    match channel {
        Channel::Stable => status == ProfileStatus::Qualified,
        Channel::Experimental => {
            matches!(
                status,
                ProfileStatus::Qualified | ProfileStatus::Experimental
            )
        }
    }
}

fn platform_matches(profile: &Profile, facts: &PlatformFacts) -> bool {
    profile.platform.id == facts.os_id
        && profile.platform.version_id == facts.os_version_id
        && profile.platform.arch == facts.arch
        && profile
            .hardware
            .iter()
            .any(|supported| facts.pci_ids.iter().any(|actual| actual == supported))
        && profile.kernel.module == "intel_vpu"
        && facts.intel_vpu_loaded
        && kernel_matches(profile, facts.kernel)
}

fn kernel_matches(profile: &Profile, actual: KernelVersion) -> bool {
    let Ok(minimum) = KernelVersion::parse_release(&profile.kernel.min) else {
        return false;
    };
    let Ok(maximum) = KernelVersion::parse_release(&profile.kernel.max_exclusive) else {
        return false;
    };
    minimum <= actual && actual < maximum
}
