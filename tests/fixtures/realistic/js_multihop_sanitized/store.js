// Sink helper (fileC) for the js_multihop_sanitized fixture.
//
// Same sink as the positive fixture. The chain is broken upstream (in
// service.handle), so the only finding here is the single-file regex heuristic.

const db = { query(_q) { return []; } };

function runQuery(term) {
    return db.query("SELECT * FROM users WHERE name = '" + term + "'");
}

module.exports = { runQuery };
