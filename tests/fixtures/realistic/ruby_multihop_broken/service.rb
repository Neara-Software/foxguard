# Middle helper (fileB) for the ruby_multihop_broken fixture.
#
# Unlike the positive fixture, forward() does NOT forward its tainted
# parameter. It passes a clean constant to CommandHelper#run_cmd instead, so
# the composition (which is taint-flow-sensitive) records no params_to_sink
# flow and the chain BREAKS: no taint finding on a directory scan. Ruby's rules
# DO ship sanitizers (e.g. Shellwords.escape), so a sanitizer call would break
# the chain equally; a clean value is used here for symmetry with the other
# multi-hop negatives.

class Service
  def forward(term)
    safe = "constant"
    run_cmd(safe)
  end
end
