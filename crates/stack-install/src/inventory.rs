// SPDX-License-Identifier: Apache-2.0

use std::{cmp::Ordering, collections::BTreeSet, time::Duration};

use sha2::{Digest, Sha256};
use stack_runtime::{ProcessRequest, ProcessRunner, Termination};

use crate::InstallError;

const MAX_INVENTORY_BYTES: usize = 8_388_608;
const INVENTORY_FORMAT: &str = "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n";

/// One installed native RPM identity. Install-only and multilib entries remain
/// separate records; a package name alone is not a unique database key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledRpm {
    pub name: String,
    pub evr: String,
    pub arch: String,
    pub install_time: u64,
}

/// Immutable observation of the native package database, not another database.
#[derive(Debug)]
pub struct NativeInventory {
    packages: Vec<InstalledRpm>,
    fingerprint: String,
}

impl NativeInventory {
    /// Parses complete bounded RPM query records and rejects duplicate NEVRAs.
    pub fn parse_query(bytes: &[u8]) -> Result<Self, InstallError> {
        if bytes.is_empty() || bytes.len() > MAX_INVENTORY_BYTES || !bytes.ends_with(b"\n") {
            return Err(observation_error());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| observation_error())?;
        let mut packages = Vec::new();
        let mut identities = BTreeSet::new();
        for line in text
            .strip_suffix('\n')
            .ok_or_else(observation_error)?
            .split('\n')
        {
            let fields = line.split('|').collect::<Vec<_>>();
            if fields.len() != 4
                || !rpm_name(fields[0])
                || !valid_evr(fields[1])
                || fields[2].is_empty()
                || fields[2].len() > 32
                || !(fields[2]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || (fields[0] == "gpg-pubkey" && fields[2] == "(none)"))
                || fields[3].is_empty()
                || !fields[3].bytes().all(|b| b.is_ascii_digit())
                || !identities.insert((fields[0], fields[1], fields[2]))
            {
                return Err(observation_error());
            }
            let install_time = fields[3].parse().map_err(|_| observation_error())?;
            packages.push(InstalledRpm {
                name: fields[0].to_owned(),
                evr: fields[1].to_owned(),
                arch: fields[2].to_owned(),
                install_time,
            });
            if packages.len() > 100_000 {
                return Err(observation_error());
            }
        }
        packages.sort();
        let mut hash = Sha256::new();
        for package in &packages {
            hash.update(format!(
                "{}|{}|{}|{}\n",
                package.name, package.evr, package.arch, package.install_time
            ));
        }
        Ok(Self {
            packages,
            fingerprint: format!("{:x}", hash.finalize()),
        })
    }

    /// Reads the Fedora system database without user macro-file overrides.
    pub fn query(runner: &dyn ProcessRunner) -> Result<Self, InstallError> {
        let output = native_rpm(
            runner,
            &[
                "--dbpath",
                "/usr/lib/sysimage/rpm",
                "-qa",
                "--qf",
                INVENTORY_FORMAT,
            ],
            MAX_INVENTORY_BYTES,
        )?;
        Self::parse_query(&output)
    }

    /// Returns a deterministic observation including install-only versions.
    pub fn packages(&self) -> &[InstalledRpm] {
        &self.packages
    }

    /// Identifies package identities and installation times, independent of
    /// query order. It is not proof that installed payload files are unchanged.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Refuses a stale observation before replay. DNF still owns transaction
    /// locking and re-resolution; this does not lock the database across calls.
    pub fn verify_unchanged(&self, runner: &dyn ProcessRunner) -> Result<(), InstallError> {
        if Self::query(runner)?.fingerprint != self.fingerprint {
            return Err(InstallError {
                exit_code: 30,
                code: "INSTALL_STATE_CHANGED",
                message: "installed packages changed after planning",
            });
        }
        Ok(())
    }
}

/// Compares complete validated epoch/version/release strings with RPM's own
/// `rpm.ver` implementation. Version data cannot introduce Lua syntax.
pub fn compare_rpm_versions(
    left: &str,
    right: &str,
    runner: &dyn ProcessRunner,
) -> Result<Ordering, InstallError> {
    if !valid_evr(left) || !valid_evr(right) {
        return Err(observation_error());
    }
    let expression = format!(
        "%{{lua: local a=rpm.ver(\"{left}\"); local b=rpm.ver(\"{right}\"); if a < b then print(-1) elseif a > b then print(1) else print(0) end}}"
    );
    match native_rpm(runner, &["--eval", &expression], 16)?.as_slice() {
        b"-1\n" => Ok(Ordering::Less),
        b"0\n" => Ok(Ordering::Equal),
        b"1\n" => Ok(Ordering::Greater),
        _ => Err(observation_error()),
    }
}

fn native_rpm(
    runner: &dyn ProcessRunner,
    args: &[&str],
    stdout_limit: usize,
) -> Result<Vec<u8>, InstallError> {
    let args = ["--macros", "/usr/lib/rpm/macros", "--noplugins"]
        .into_iter()
        .chain(args.iter().copied())
        .map(Into::into)
        .collect();
    let result = runner
        .run(&ProcessRequest {
            executable: "/usr/bin/rpm".into(),
            args,
            timeout: Duration::from_secs(10),
            stdout_limit,
            stderr_limit: 16_384,
            environment: Vec::new(),
        })
        .map_err(|_| observation_error())?;
    if result.termination != Termination::Exit(0)
        || result.stdout_overflow
        || result.stderr_overflow
    {
        return Err(observation_error());
    }
    Ok(result.stdout)
}

fn rpm_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
}

pub(crate) fn valid_evr(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let Some((epoch, vr)) = value.split_once(':') else {
        return false;
    };
    let Some((version, release)) = vr.split_once('-') else {
        return false;
    };
    let scalar = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+~^".contains(&b))
    };
    !epoch.is_empty()
        && epoch.bytes().all(|b| b.is_ascii_digit())
        && epoch.parse::<u32>().is_ok()
        && (epoch.len() == 1 || !epoch.starts_with('0'))
        && scalar(version)
        && scalar(release)
}

fn observation_error() -> InstallError {
    InstallError {
        exit_code: 30,
        code: "INSTALL_RPM_OBSERVATION_FAILED",
        message: "native RPM package state or version ordering could not be verified",
    }
}
