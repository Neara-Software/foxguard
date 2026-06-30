# Cross-file taint fixture for the Ruby taint engine (taint-expansion).
#
# Two-file chain: controller.rb (source) -> helper.rb (sink).
#
# Flow:
#   1. params[:name] in UsersController#show (source)
#   2. -> CommandHelper.run(name): the pass-1 summary records that
#      parameter 0 of `run` reaches a `system` command-execution sink, so
#      passing a tainted argument into it produces a cross-file finding here
#      in controller.rb.
#
# Expected when scanning the directory:
#   rb/taint-command-injection : 1   (cross-file, reported in controller.rb)
#
# Scanning controller.rb ALONE must produce 0 rb/taint-command-injection
# findings: the helper body is unseen and `run` is not itself a sink.

class UsersController < ApplicationController
  def show
    name = params[:name]
    CommandHelper.run(name)
  end
end
