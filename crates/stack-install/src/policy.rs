// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use stack_core::{Channel, SelectionPolicy, select_profile};
use stack_platform::PlatformFacts;
use stack_schema::{PackageManager, Profile};

use crate::InstallError;

/// Public bootstrap options. Parsing and policy evaluation perform no I/O.
#[derive(Debug, Clone, Parser)]
#[command(name = "intel-npu-stack-install", version)]
pub struct InstallOptions {
    /// Inspect and print the verified native transaction without installing.
    #[arg(long)]
    pub dry_run: bool,
    /// Accept the displayed exact transaction without interactive confirmation.
    #[arg(long)]
    pub yes: bool,
    /// Select stable or experimental profile admission policy.
    #[arg(long, default_value = "stable", value_parser = parse_channel)]
    pub channel: Channel,
    /// Acknowledge risk explicitly; required only for the experimental channel.
    #[arg(long)]
    pub accept_experimental_risk: bool,
    /// Require matching native Python bindings in the selected release.
    #[arg(long)]
    pub with_python: bool,
    /// Require matching native development packages in the selected release.
    #[arg(long)]
    pub with_devel: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            yes: false,
            channel: Channel::Stable,
            accept_experimental_risk: false,
            with_python: false,
            with_devel: false,
        }
    }
}

fn parse_channel(value: &str) -> Result<Channel, String> {
    match value {
        "stable" => Ok(Channel::Stable),
        "experimental" => Ok(Channel::Experimental),
        _ => Err("channel must be stable or experimental".into()),
    }
}

/// Validates normal-user execution and selects one exact compatible profile.
///
/// The supplied facts are an injection boundary for tests. A production caller
/// must use the system platform detector, not user-selected paths or overrides.
/// This function neither authenticates metadata nor executes a transaction.
pub fn validate_request(
    options: &InstallOptions,
    facts: &PlatformFacts,
    profiles: &[Profile],
) -> Result<usize, InstallError> {
    if facts.effective_root {
        return Err(InstallError {
            exit_code: 2,
            code: "INSTALL_ROOT_REFUSED",
            message: "run the installer as a normal user; it requests privilege only for the approved native transaction",
        });
    }
    if (options.channel == Channel::Experimental) != options.accept_experimental_risk {
        return Err(InstallError {
            exit_code: 2,
            code: "INSTALL_CHANNEL_RISK_MISMATCH",
            message: "experimental requires --accept-experimental-risk; stable rejects that flag",
        });
    }
    if facts.os_id != "fedora" || facts.os_version_id != "44" || facts.arch != "x86_64" {
        return Err(unsupported());
    }
    for profile in profiles {
        profile
            .validate()
            .map_err(|_| InstallError::metadata("profile validation failed"))?;
        if profile.package_manager != PackageManager::Rpm
            || profile.platform.id != "fedora"
            || profile.platform.version_id != "44"
            || profile.platform.arch != "x86_64"
        {
            return Err(InstallError::metadata(
                "profile is outside the Fedora installer boundary",
            ));
        }
    }
    let policy = SelectionPolicy {
        channel: options.channel,
        acknowledge_risk: options.accept_experimental_risk,
    };
    let selected = select_profile(profiles, facts, &policy).map_err(|_| unsupported())?;
    // Identity, rather than profile ID equality, also handles an unselected
    // entry with the same ID. The selector returns a reference from this slice.
    profiles
        .iter()
        .position(|profile| std::ptr::eq(profile, selected))
        .ok_or_else(unsupported)
}

fn unsupported() -> InstallError {
    InstallError {
        exit_code: 10,
        code: "INSTALL_PROFILE_UNSUPPORTED",
        message: "exactly one compatible profile admitted by this channel is required",
    }
}
