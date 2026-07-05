<?php
// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file PHP chain where the MIDDLE helper itself makes the cross-file
// call:
//
//   search()  ->  forward()  ->  run_cmd()
//   fileA (source)   fileB          fileC (sink)
//
// fileB's `forward` calls fileC's `run_cmd` directly — so the chain
// A->f->g->sink is only found once fileB's summary is composed one hop deeper
// against fileC's summary. Scanning any single file finds no taint finding;
// only the full-directory scan resolves the chain.

function search() {
    $cmd = $_GET['cmd'];
    forward($cmd);
}
