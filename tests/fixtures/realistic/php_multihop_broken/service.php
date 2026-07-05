<?php
// Middle helper (fileB) for the php_multihop_broken fixture.
//
// Unlike the positive fixture, forward() does NOT forward its tainted
// parameter. It passes a clean constant to run_cmd() instead, so the
// composition (which is taint-flow-sensitive) records no params_to_sink flow
// and the chain BREAKS: no taint finding on a directory scan. PHP's rules DO
// ship sanitizers (e.g. escapeshellarg), so a sanitizer call would break the
// chain equally; a clean value is used here for symmetry with the other
// multi-hop negatives.

function forward($term) {
    $safe = "constant";
    run_cmd($safe);
}
