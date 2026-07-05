# Middle helper (fileB) for the ruby_multihop fixture.
#
# forward() does NOT contain a sink itself — it forwards its argument to
# CommandHelper#run_cmd in ANOTHER file (fileC). Its single-file summary
# therefore records no params_to_sink; only after the bounded multi-hop
# composition (which resolves the same-directory call to run_cmd and sees that
# helper sink its param) does forward's summary gain params_to_sink = [0]. That
# composed summary is what lets the caller in search_controller fire.

class Service
  def forward(term)
    run_cmd(term)
  end
end
