<?php
// Positive fixtures for the PHP taint engine. Each function flows an
// untrusted superglobal into a taint sink. Each php/taint-* rule must
// fire exactly once. The trailing near-miss functions must produce no
// php/taint-* finding.

// --- php/taint-command-injection -------------------------------------------

// 1. $_GET -> system (direct)
function cmd_direct() {
    system($_GET['cmd']);
}

// --- php/taint-sql-injection ------------------------------------------------

// 2. $_GET -> mysqli_query (procedural MySQL)
function sql_mysqli($conn) {
    mysqli_query($conn, $_GET['q']);
}

// --- php/taint-xss ----------------------------------------------------------

// 3. $_GET -> echo (reflected output)
function xss_echo() {
    echo $_GET['name'];
}

// --- php/taint-file-inclusion -----------------------------------------------

// 4. $_GET -> include (local file inclusion)
function lfi_include() {
    include $_GET['page'];
}

// --- php/taint-unsafe-deserialization ---------------------------------------

// 5. $_GET -> unserialize
function deser_unserialize() {
    unserialize($_GET['data']);
}

// --- Near-miss: tainted value never reaches a sink -------------------------

function near_miss_no_sink() {
    $x = $_GET['x'];
    $y = $x . 'suffix';
    // $y is tainted but is never passed to a sink.
    return $y;
}

// --- Near-miss: literal argument, no source --------------------------------

function near_miss_literal() {
    system('ls -la');
}

// --- Near-miss: sanitizer kills taint before the sink ----------------------

function near_miss_sanitized() {
    system(escapeshellarg($_GET['cmd']));
}
