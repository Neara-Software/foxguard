use std::env;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), String> {
    match env::args().nth(1).as_deref() {
        Some("large-output") => emit_large_output(),
        Some("sleep") => sleep_forever(),
        Some(other) => Err(format!("unknown mode: {other}")),
        None => Err("missing mode".to_string()),
    }
}

fn emit_large_output() -> Result<(), String> {
    let chunk = [0u8; 1024];
    let mut stdout = io::stdout().lock();
    for _ in 0..256 {
        stdout
            .write_all(&chunk)
            .map_err(|error| format!("failed to write helper output: {error}"))?;
    }
    stdout
        .flush()
        .map_err(|error| format!("failed to flush helper output: {error}"))
}

fn sleep_forever() -> Result<(), String> {
    thread::sleep(Duration::from_secs(60));
    Ok(())
}
