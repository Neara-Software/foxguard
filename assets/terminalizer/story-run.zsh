#!/bin/zsh

set -euo pipefail

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR"

fg() {
  ../../target/debug/foxguard "$@"
}

write_secrets_fixture() {
  local aws_id aws_secret github_token stripe_key

  aws_id="AKIA""1234567890ABCDEF"
  aws_secret="ABCD1234+/""wxyz5678+/""MNOP9012+/""qrst3456+/"
  github_token="ghp_""abcdefghijklmnopqrstuvwxyz1234567890"
  stripe_key="sk""_live_""1234567890abcdefghijklmnop"

  : > story-target/secrets.env
  printf 'AWS_ACCESS_KEY_ID=%s\n' "$aws_id" >> story-target/secrets.env
  printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$aws_secret" >> story-target/secrets.env
  printf 'GITHUB_TOKEN=%s\n' "$github_token" >> story-target/secrets.env
  printf 'STRIPE_SECRET_KEY=%s\n' "$stripe_key" >> story-target/secrets.env
}

type_line() {
  local text="$1"
  local i ch

  printf '$ '
  for (( i = 1; i <= ${#text}; i++ )); do
    ch="${text[i]}"
    printf '%s' "$ch"
    sleep 0.018
  done
  printf '\n'
}

note() {
  printf '\033[38;5;223m# %s\033[0m\n' "$1"
  sleep 0.8
}

scene() {
  sleep 0.5
  printf '\033[3J\033[H\033[2J'
  sleep 0.2
}

run_cmd() {
  local text="$1"
  type_line "$text"
  eval "$text"
  sleep 0.9
}

clear
printf '\033[3J\033[H\033[2J'

write_secrets_fixture

note "foxguard dark demo"
note "code scan, secrets, baseline"

run_cmd 'ls -1 story-target'

scene
note "explain traces source -> sink"
run_cmd 'fg story-target --explain || true'

scene
note "secrets are redacted"
run_cmd 'fg secrets story-target || true'

scene
note "baseline existing findings"
run_cmd 'fg baseline story-target --output .demo-baseline.json'

scene
note "next run stays clean"
run_cmd 'fg story-target --baseline .demo-baseline.json'
