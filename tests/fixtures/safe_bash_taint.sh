#!/usr/bin/env bash
# Negative fixture for the Bash taint engine. Every block either uses a literal
# argument, has its taint killed by printf %q, or never lets the tainted value
# reach a command-execution sink. No bash/taint-* rule may fire.

# NEAR MISS: literal command, no expansion.
eval "echo hello"

# NEAR MISS: clean literal assignment reaching the sink.
cmd="ls -la"
eval "$cmd"

# NEAR MISS: tainted parameter captured but the sink receives a literal.
unused="$1"
eval "whoami"

# NEAR MISS: printf %q shell-quotes the parameter before eval.
safe=$(printf '%q' "$1")
eval "$safe"

# NEAR MISS: read stdin, but the value is shell-quoted before bash -c.
read raw
quoted=$(printf '%q' "$raw")
bash -c "$quoted"

# NEAR MISS: curl output is printed, never executed.
out=$(curl -s http://example.com)
echo "$out"

# NEAR MISS (path traversal): literal file path, no tainted input.
cat /etc/hostname

# NEAR MISS (path traversal): printf %q shell-quotes the parameter before cat.
safe_path=$(printf '%q' "$1")
cat "$safe_path"

# NEAR MISS (SSRF): fixed URL, no request input reaches curl.
curl -s https://status.example.com/health
