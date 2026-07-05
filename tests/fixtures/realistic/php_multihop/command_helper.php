<?php
// Sink helper (fileC) for the php_multihop fixture.
//
// run_cmd() passes its parameter straight to system(), an OS command sink. Its
// single-file summary records params_to_sink for param 0 with rule
// php/taint-command-injection. Scanned alone, `$arg` is just a parameter (not a
// source), so no taint finding fires here.

function run_cmd($arg) {
    system($arg);
}
