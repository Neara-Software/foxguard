#!/bin/zsh

set -euo pipefail

type_line() {
  local text="$1"
  local i ch

  printf '$ '
  for (( i = 1; i <= ${#text}; i++ )); do
    ch="${text[i]}"
    printf '%s' "$ch"
    sleep 0.025
  done
  printf '\n'
}

pause() {
  sleep "$1"
}

clear
pause 0.4

type_line './target/debug/foxguard assets/terminalizer/demo-target --explain'
./target/debug/foxguard assets/terminalizer/demo-target --explain || true

pause 1.4
