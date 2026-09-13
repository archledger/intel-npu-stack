// SPDX-License-Identifier: Apache-2.0

use stack_install::{
    ConfirmationPrompt, InstallOptions, NativeInventory, NativePlan, PlanReview, ReleaseManifest,
    review_plan,
};
use stack_runtime::{ProcessError, ProcessOutput, ProcessRequest, ProcessRunner};
use std::{fmt::Write as _, io};

fn plan(no_change: bool) -> NativePlan {
    let manifest = ReleaseManifest::parse_json(include_bytes!("fixtures/release.json")).unwrap();
    let inputs = manifest
        .selected_packages(false, false)
        .unwrap()
        .into_iter()
        .filter(|p| {
            matches!(
                p.name.as_str(),
                "intel-npu-stack" | "intel-npu-stack-tools" | "intel-npu-stack-firmware"
            )
        })
        .collect::<Vec<_>>();
    if no_change {
        let mut text = String::new();
        for p in &inputs {
            writeln!(text, "{}|{}|{}|0", p.name, p.nevr, p.arch).unwrap();
        }
        NativePlan::parse_update(
            None,
            &inputs,
            &NativeInventory::parse_query(text.as_bytes()).unwrap(),
            "intel-npu-test",
            &MustNotRun,
        )
        .unwrap()
    } else {
        NativePlan::parse_install(include_bytes!("fixtures/dnf/install.json"), &inputs).unwrap()
    }
}
struct MustNotRun;
impl ProcessRunner for MustNotRun {
    fn run(&self, _: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        panic!("no process expected")
    }
}
struct NoPrompt;
impl ConfirmationPrompt for NoPrompt {
    fn read_response(&mut self) -> io::Result<String> {
        panic!("no prompt expected")
    }
}
struct Response(Option<String>);
impl ConfirmationPrompt for Response {
    fn read_response(&mut self) -> io::Result<String> {
        self.0
            .take()
            .ok_or_else(|| io::Error::other("no controlling terminal"))
    }
}

#[test]
fn dry_run_displays_exact_plan_without_prompting_or_approval() {
    let p = plan(false);
    let options = InstallOptions {
        dry_run: true,
        yes: true,
        ..Default::default()
    };
    let mut output = Vec::new();
    assert!(matches!(
        review_plan(&p, &options, &mut output, &mut NoPrompt).unwrap(),
        PlanReview::DryRun
    ));
    assert_eq!(String::from_utf8(output).unwrap(), p.preview());
}
#[test]
fn exact_no_op_displays_state_without_prompting_or_approval() {
    let p = plan(true);
    let mut output = Vec::new();
    assert!(matches!(
        review_plan(&p, &InstallOptions::default(), &mut output, &mut NoPrompt).unwrap(),
        PlanReview::NoChanges
    ));
    assert_eq!(output, b"No package changes.\n");
}
#[test]
fn explicit_yes_approves_only_the_displayed_immutable_plan() {
    let p = plan(false);
    let mut output = Vec::new();
    let options = InstallOptions {
        yes: true,
        ..Default::default()
    };
    let PlanReview::Approved(approved) =
        review_plan(&p, &options, &mut output, &mut NoPrompt).unwrap()
    else {
        panic!("expected approval")
    };
    assert!(std::ptr::eq(approved.plan(), &p));
    assert_eq!(output, p.preview().as_bytes());
}
#[test]
fn interactive_confirmation_requires_a_complete_affirmative_line() {
    let p = plan(false);
    for answer in ["yes\n", "YES\r\n"] {
        assert!(matches!(
            review_plan(
                &p,
                &InstallOptions::default(),
                &mut Vec::new(),
                &mut Response(Some(answer.into()))
            )
            .unwrap(),
            PlanReview::Approved(_)
        ));
    }
    for answer in [
        None,
        Some("".into()),
        Some("\n".into()),
        Some("no\n".into()),
        Some("yes".into()),
        Some("yes\nno\n".into()),
        Some("x".repeat(65) + "\n"),
    ] {
        let error = review_plan(
            &p,
            &InstallOptions::default(),
            &mut Vec::new(),
            &mut Response(answer),
        )
        .unwrap_err();
        assert_eq!(error.exit_code, 2);
    }
}
struct BrokenOutput;
impl io::Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("output unavailable"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn display_failure_stops_before_confirmation_even_with_yes() {
    let p = plan(false);
    let options = InstallOptions {
        yes: true,
        ..Default::default()
    };
    assert_eq!(
        review_plan(&p, &options, &mut BrokenOutput, &mut NoPrompt)
            .unwrap_err()
            .exit_code,
        30
    );
}
