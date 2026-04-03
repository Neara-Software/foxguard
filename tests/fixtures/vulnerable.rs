// Rust test fixture — intentionally vulnerable code for foxguard detection tests

use std::process::Command;

// rs/unsafe-block
fn unsafe_usage() {
    unsafe {
        let ptr = 0x1234 as *const i32;
        println!("{}", *ptr);
    }
}

// rs/transmute-usage
fn transmute_usage() {
    let x: u32 = unsafe { std::mem::transmute(1.0f32) };
}

// rs/no-command-injection
fn command_injection(user_input: &str) {
    Command::new(user_input).spawn().unwrap();
}

// rs/no-hardcoded-secret
fn secrets() {
    let api_key = "sk-live-abcdef123456789";
    let password = "supersecret123";
    let secret_token = "ghp_xxxxxxxxxxxxxxxxxxxx";
}

// rs/tls-verify-disabled
fn tls_disabled() {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
}

// rs/no-unwrap-in-lib
fn unwrap_usage() {
    let x: Option<i32> = Some(1);
    x.unwrap();
    x.expect("should exist");
}
