<?php
// Negative fixtures for the PHP taint engine. Every function either uses
// a literal argument, has its taint killed by a domain-appropriate
// sanitizer, or avoids the dangerous sink entirely. No php/taint-* rule
// may fire.

// --- Safe command execution: escapeshellarg sanitizes the argument ---------

function safe_system_escaped() {
    system(escapeshellarg($_GET['cmd']));
}

// --- Safe command execution: integer coercion kills taint ------------------

function safe_system_intval() {
    system((int) $_GET['n']);
}

// --- Safe SQL: literal query, no tainted input -----------------------------

function safe_sql_literal($conn) {
    mysqli_query($conn, "SELECT 1");
}

// --- Safe SQL: prepared statement (no tainted query) -----------------------

function safe_sql_prepare($pdo) {
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_GET['id']]);
}

// --- Safe XSS: htmlspecialchars escapes output -----------------------------

function safe_echo_escaped() {
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
}

// --- Safe XSS: literal output ----------------------------------------------

function safe_echo_literal() {
    echo "Hello, world";
}

// --- Safe file inclusion: literal path --------------------------------------

function safe_include_literal() {
    include 'lib/init.php';
}

// --- Safe deserialization: literal data, no tainted input ------------------

function safe_unserialize_literal() {
    unserialize('a:0:{}');
}
