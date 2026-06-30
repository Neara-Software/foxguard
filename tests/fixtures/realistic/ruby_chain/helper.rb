# Sink helper for the Ruby cross-file taint fixture.
#
# CommandHelper.run() takes a parameter and passes it into a `system` OS
# command sink via string interpolation. The pass-1 cross-file summary
# records params_to_sink for parameter 0 with rule
# rb/taint-command-injection. `term` is a plain method parameter (not a
# taint source), so this file on its own produces no taint finding — the
# flow only exists once a tainted argument is passed in from controller.rb.

module CommandHelper
  def self.run(term)
    system("grep #{term} /var/log/app.log")
  end
end
