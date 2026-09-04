// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRequest {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Exit(u8),
    Signal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub termination: Termination,
    pub stdout: Vec<u8>,
    pub stdout_overflow: bool,
    pub stderr_overflow: bool,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    #[error("process executable must be an absolute path")]
    InvalidExecutable,
    #[error("process could not be spawned")]
    Spawn,
    #[error("process exceeded its deadline")]
    Timeout,
    #[error("process pipe I/O failed")]
    PipeIo,
    #[error("process reader thread could not be joined")]
    Join,
    #[error("process termination status is unsupported")]
    InvalidTermination,
}

pub trait ProcessRunner: Send + Sync {
    /// Runs one process under the request's deadline and output limits.
    ///
    /// # Errors
    ///
    /// Returns a stable error category for invalid configuration, process
    /// lifecycle failures, pipe failures, or a missed deadline.
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessRunner;

impl ProcessRunner for SystemProcessRunner {
    fn run(&self, request: &ProcessRequest) -> Result<ProcessOutput, ProcessError> {
        if !request.executable.is_absolute() {
            return Err(ProcessError::InvalidExecutable);
        }

        let mut child = Command::new(&request.executable)
            .args(&request.args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| ProcessError::Spawn)?;

        let Some(stdout) = child.stdout.take() else {
            kill_and_reap(&mut child);
            return Err(ProcessError::PipeIo);
        };
        let Some(stderr) = child.stderr.take() else {
            kill_and_reap(&mut child);
            return Err(ProcessError::PipeIo);
        };

        let stdout_reader = spawn_reader(stdout, request.stdout_limit).inspect_err(|_| {
            kill_and_reap(&mut child);
        })?;
        let stderr_reader = match spawn_reader(stderr, request.stderr_limit) {
            Ok(reader) => reader,
            Err(error) => {
                kill_and_reap(&mut child);
                let _ = stdout_reader.join();
                return Err(error);
            }
        };

        let started = Instant::now();
        let lifecycle = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok((status, false)),
                Ok(None) if started.elapsed() >= request.timeout => {
                    let _ = child.kill();
                    match child.wait() {
                        Ok(status) => break Ok((status, true)),
                        Err(_) => {
                            kill_and_reap(&mut child);
                            break Err(ProcessError::Spawn);
                        }
                    }
                }
                Ok(None) => {
                    let remaining = request.timeout.saturating_sub(started.elapsed());
                    thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(_) => {
                    kill_and_reap(&mut child);
                    break Err(ProcessError::Spawn);
                }
            }
        };

        let readers = join_readers(stdout_reader, stderr_reader);
        let (status, timed_out) = lifecycle?;
        let (stdout, stderr) = readers?;
        if timed_out {
            return Err(ProcessError::Timeout);
        }

        Ok(ProcessOutput {
            termination: classify_termination(status)?,
            stdout: stdout.bytes,
            stdout_overflow: stdout.overflow,
            stderr_overflow: stderr.overflow,
        })
    }
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}

fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
) -> Result<JoinHandle<Result<CapturedOutput, ProcessError>>, ProcessError> {
    thread::Builder::new()
        .spawn(move || {
            let mut captured = Vec::with_capacity(limit.min(8_192));
            let mut overflow = false;
            let mut buffer = [0_u8; 8_192];
            loop {
                let read = pipe.read(&mut buffer).map_err(|_| ProcessError::PipeIo)?;
                if read == 0 {
                    break;
                }
                let available = limit.saturating_sub(captured.len());
                let retained = available.min(read);
                captured.extend_from_slice(&buffer[..retained]);
                overflow |= retained < read;
            }
            Ok(CapturedOutput {
                bytes: captured,
                overflow,
            })
        })
        .map_err(|_| ProcessError::Spawn)
}

fn join_readers(
    stdout: JoinHandle<Result<CapturedOutput, ProcessError>>,
    stderr: JoinHandle<Result<CapturedOutput, ProcessError>>,
) -> Result<(CapturedOutput, CapturedOutput), ProcessError> {
    let stdout = stdout.join();
    let stderr = stderr.join();
    let stdout = stdout.map_err(|_| ProcessError::Join)?;
    let stderr = stderr.map_err(|_| ProcessError::Join)?;
    Ok((stdout?, stderr?))
}

fn kill_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn classify_termination(status: ExitStatus) -> Result<Termination, ProcessError> {
    use std::os::unix::process::ExitStatusExt;

    if status.signal().is_some() {
        return Ok(Termination::Signal);
    }
    let code = status.code().ok_or(ProcessError::InvalidTermination)?;
    let code = u8::try_from(code).map_err(|_| ProcessError::InvalidTermination)?;
    Ok(Termination::Exit(code))
}

#[cfg(not(unix))]
fn classify_termination(status: ExitStatus) -> Result<Termination, ProcessError> {
    let code = status.code().ok_or(ProcessError::InvalidTermination)?;
    let code = u8::try_from(code).map_err(|_| ProcessError::InvalidTermination)?;
    Ok(Termination::Exit(code))
}
