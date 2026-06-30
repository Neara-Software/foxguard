<?php
// Sink helper for the PHP cross-file taint fixture.
//
// run_cmd() takes a parameter and passes it into an OS command-execution
// sink. The pass-1 cross-file summary records params_to_sink for parameter 0
// with rule php/taint-command-injection. `$arg` is a plain parameter (not a
// taint source), so this file on its own produces no taint finding — the flow
// only exists once a tainted argument is passed in from handler.php.

function run_cmd($arg) {
    system($arg);
}
