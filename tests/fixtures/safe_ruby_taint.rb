# frozen_string_literal: true

# Negative fixture for the Ruby first-party taint engine. Every controller
# action either uses a literal argument, has its taint killed by a
# sanitizer, or never lets the tainted value reach a sink. No `rb/taint-*`
# rule may fire.

class SafeApp
  class TaintController < ApplicationController
    # NEAR MISS: literal argument to a command sink.
    def literal_command
      system("/usr/bin/true")
    end

    # NEAR MISS: tainted value captured but the sink receives a literal.
    def taint_never_reaches_sink
      _ignored = params[:ignored]
      redirect_to("/home")
    end

    # NEAR MISS: Shellwords.escape sanitizes the flow before the command.
    def sanitized_command
      require "shellwords"
      raw = params[:cmd]
      safe = Shellwords.escape(raw)
      system(safe)
    end

    # NEAR MISS: tainted value captured but never reaches the query sink;
    # the query is a static literal. (ActiveRecord parameter binding
    # `where("... ?", params[:x])` is NOT used here because the v1 taint
    # engine does not model `?` binding and would flag the tainted second
    # argument — a documented precision limitation.)
    def literal_search
      _name = params[:name]
      User.where("name = 'static'")
    end

    # NEAR MISS: HTML-sanitized output via `sanitize` (a registered taint
    # sanitizer) before the value reaches raw().
    def escaped_html
      html = params[:html]
      raw(sanitize(html))
    end

    # NEAR MISS: fixed allowlisted redirect target.
    def fixed_redirect
      redirect_to("/dashboard")
    end

    # NEAR MISS: untrusted blob is never deserialized — a literal constant
    # is loaded instead.
    def safe_load
      _blob = params[:blob]
      Marshal.load(SAFE_BLOB)
    end
  end
end
