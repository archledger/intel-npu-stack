// SPDX-License-Identifier: Apache-2.0

use crate::{InstallError, InstallOptions, NativePlan};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, BufReader, IsTerminal, Read, Write},
};

/// Interactive input boundary. Production uses the controlling terminal,
/// independently of redirected stdin. Review never launches a process.
pub trait ConfirmationPrompt {
    fn read_response(&mut self) -> io::Result<String>;
}

#[derive(Debug, Default)]
pub struct SystemConfirmationPrompt;

impl ConfirmationPrompt for SystemConfirmationPrompt {
    fn read_response(&mut self) -> io::Result<String> {
        let mut terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        if !terminal.is_terminal() {
            return Err(io::Error::other("controlling terminal unavailable"));
        }
        terminal.write_all(b"Apply this exact transaction? Type yes to continue: ")?;
        terminal.flush()?;
        let mut response = String::new();
        BufReader::new(terminal.take(65)).read_line(&mut response)?;
        Ok(response)
    }
}

/// User approval for this exact immutable plan, not a native-state lock or
/// signature verdict. Execution must consume it and recheck transaction bytes,
/// RPM identities/signatures and the installed-state observation before replay.
#[derive(Debug)]
pub struct ApprovedPlan<'a> {
    plan: &'a NativePlan,
}

impl ApprovedPlan<'_> {
    pub fn plan(&self) -> &NativePlan {
        self.plan
    }
}

#[derive(Debug)]
pub enum PlanReview<'a> {
    DryRun,
    NoChanges,
    Approved(ApprovedPlan<'a>),
}

/// Displays and flushes every action before accepting explicit approval.
/// Dry runs and exact no-ops cannot produce an execution approval receipt.
pub fn review_plan<'a>(
    plan: &'a NativePlan,
    options: &InstallOptions,
    output: &mut dyn Write,
    prompt: &mut dyn ConfirmationPrompt,
) -> Result<PlanReview<'a>, InstallError> {
    output
        .write_all(plan.preview().as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| InstallError {
            exit_code: 30,
            code: "INSTALL_OUTPUT_FAILED",
            message: "could not display the exact native transaction",
        })?;
    if options.dry_run {
        return Ok(PlanReview::DryRun);
    }
    if plan.is_empty() {
        return Ok(PlanReview::NoChanges);
    }
    if !options.yes {
        let response = prompt.read_response().map_err(|_| confirmation_error())?;
        let Some(line) = response.strip_suffix('\n') else {
            return Err(confirmation_error());
        };
        if response.len() > 64 || line.contains('\n') || !line.trim().eq_ignore_ascii_case("yes") {
            return Err(confirmation_error());
        }
    }
    Ok(PlanReview::Approved(ApprovedPlan { plan }))
}

fn confirmation_error() -> InstallError {
    InstallError {
        exit_code: 2,
        code: "INSTALL_CONFIRMATION_REQUIRED",
        message: "installation requires a complete yes response on the controlling terminal or explicit --yes",
    }
}
