<?php
// Cross-file taint fixture for the PHP taint engine (taint-expansion).
//
// Two-file chain: handler.php (source) -> helper.php (sink).
//
// Flow:
//   1. $_GET['cmd'] in handle() (source)
//   2. -> run_cmd($cmd): the pass-1 summary records that parameter 0 of
//      run_cmd reaches a system() command-execution sink, so passing a
//      tainted argument into it produces a cross-file finding here in
//      handler.php.
//
// Expected when scanning the directory:
//   php/taint-command-injection : 1   (cross-file, reported in handler.php)
//
// Scanning handler.php ALONE must produce 0 php/taint-command-injection
// findings: the helper body is unseen and `run_cmd` is not itself a sink.

function handle() {
    $cmd = $_GET['cmd'];
    run_cmd($cmd);
}
