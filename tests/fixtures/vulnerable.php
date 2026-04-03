<?php
// PHP test fixture — intentionally vulnerable code for foxguard detection tests

// php/no-eval
eval($userInput);

// php/no-command-injection
exec($userInput);
system($userInput);
passthru($userInput);
shell_exec($userInput);
`$userInput`;

// php/no-sql-injection
mysqli_query($conn, "SELECT * FROM users WHERE id = $userId");

// php/no-unserialize
unserialize($data);

// php/no-file-inclusion
include($userInput);
require($userInput);
include_once($userInput);

// php/no-weak-crypto
$hash = md5($data);
$hash2 = sha1($data);

// php/no-hardcoded-secret
$password = "supersecret123";
$api_key = "sk-live-abcdef123456789";
$secret_token = "ghp_xxxxxxxxxxxxxxxxxxxx";

// php/no-ssrf
file_get_contents($userUrl);
curl_init($userUrl);

// php/no-extract
extract($_GET);

// php/no-preg-eval
preg_replace('/pattern/e', 'replacement', $input);
