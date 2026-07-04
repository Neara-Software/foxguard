// Middle helper (fileB) for the js_multihop_sanitized fixture.
//
// Unlike the positive fixture, handle() runs the tainted value through
// mysql.escape() — a configured sanitizer for js/taint-sql-injection — before
// forwarding it to store.runQuery(). The sanitizer collapses the value to
// "clean", so the composed summary must NOT record a params_to_sink flow, and
// the chain breaks: no taint finding on a directory scan.

const store = require("./store");
const mysql = { escape(v) { return v; } };

function handle(term) {
    const safe = mysql.escape(term);
    return store.runQuery(safe);
}

module.exports = { handle };
