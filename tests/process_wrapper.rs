use std::process::{Command, Stdio};
use std::time::Duration;

use foxguard::engine::process::{wait_with_output_timeout, TimedOutput};

const PROCESS_TEST_HELPER: &str = env!("CARGO_BIN_EXE_foxguard_process_test_helper");

fn helper_command(mode: &str) -> Command {
    let mut command = Command::new(PROCESS_TEST_HELPER); // foxguard: ignore[rs/no-command-injection]
    command
        .arg(mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn child_producing_large_output_does_not_deadlock() {
    let child = helper_command("large-output")
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn large-output helper: {error}"));

    let result = wait_with_output_timeout(child, Duration::from_secs(10))
        .unwrap_or_else(|error| panic!("failed to wait for large-output helper: {error}"));

    match result {
        TimedOutput::Finished(output) => {
            assert!(output.status.success());
            assert_eq!(output.stdout.len(), 256 * 1024);
        }
        TimedOutput::TimedOut { .. } => panic!("large-output helper should not have timed out"),
    }
}

#[test]
fn timeout_kills_long_running_child() {
    let child = helper_command("sleep")
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn sleep helper: {error}"));

    let result = wait_with_output_timeout(child, Duration::from_millis(200))
        .unwrap_or_else(|error| panic!("failed to wait for sleep helper: {error}"));

    assert!(result.timed_out());
}
