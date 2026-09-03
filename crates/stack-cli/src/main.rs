// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use std::io::{self, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use stack_cli::{AppContext, run};
use stack_platform::PlatformPaths;

fn main() -> ExitCode {
    let context = AppContext {
        platform_paths: PlatformPaths::system(),
        profile_dir: PathBuf::from("/usr/share/intel-npu-stack/profiles"),
        arch: std::env::consts::ARCH.to_owned(),
    };
    let mut stdout = BufWriter::new(io::stdout().lock());
    let mut stderr = BufWriter::new(io::stderr().lock());
    run(std::env::args_os(), &context, &mut stdout, &mut stderr)
}
