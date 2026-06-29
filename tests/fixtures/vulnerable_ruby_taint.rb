# frozen_string_literal: true

# Positive fixture for the Ruby first-party taint engine. Each controller
# action flows an untrusted Rails request source (`params[...]`) into a
# distinct taint sink. Every `rb/taint-*` rule must fire exactly once.
#
# The engine is intraprocedural and analyzes each `method` body in
# isolation, so every flow lives inside its own `def`. The three
# `near_miss_*` actions at the bottom must NOT fire any taint rule.

class VulnerableApp
  class TaintController < ApplicationController
    # POSITIVE (rb/taint-command-injection):
    # params[:cmd] -> system.
    def run_command
      cmd = params[:cmd]
      system(cmd)
    end

    # POSITIVE (rb/taint-sql-injection):
    # params[:name] interpolated into a where() query string.
    def search
      name = params[:name]
      User.where("name = '#{name}'")
    end

    # POSITIVE (rb/taint-xss):
    # params[:html] -> raw() (argument taint). raw() is an argument-style
    # sink, so the engine detects the flow end-to-end. (The receiver-taint
    # form `params[:x].html_safe` is a known v1 precision gap — see
    # docs/taint-tracking.md — and is intentionally not asserted here.)
    def render_html
      html = params[:html]
      raw(html)
    end

    # POSITIVE (rb/taint-unsafe-deserialization):
    # params[:blob] -> Marshal.load.
    def import_blob
      blob = params[:blob]
      Marshal.load(blob)
    end

    # POSITIVE (rb/taint-open-redirect):
    # params[:return_url] -> redirect_to.
    def redirect_after_action
      dest = params[:return_url]
      redirect_to(dest)
    end

    # ── NEAR MISSES (must NOT fire) ─────────────────────────────────────────

    # NEAR MISS: literal argument — no taint reaches the command sink.
    def near_miss_literal_command
      system("/usr/bin/true")
    end

    # NEAR MISS: tainted value captured but never reaches a sink; the sink
    # receives a static literal instead.
    def near_miss_taint_never_reaches_sink
      _unused = params[:ignored]
      redirect_to("/home")
    end

    # NEAR MISS: Shellwords.escape sanitizes the flow before the command.
    def near_miss_sanitized_command
      require "shellwords"
      raw_cmd = params[:cmd]
      safe_cmd = Shellwords.escape(raw_cmd)
      system(safe_cmd)
    end
  end
end
