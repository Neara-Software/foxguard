// Middle helper (fileB) for the js_multihop fixture.
//
// handle() does NOT contain a sink itself — it forwards its argument to
// store.runQuery() in ANOTHER file (fileC). Its single-file summary therefore
// records nothing; only after the bounded multi-hop composition (which resolves
// the cross-file call to store.runQuery and sees that helper sink its param)
// does handle's summary gain params_to_sink = [0]. That composed summary is
// what lets the caller in routes.js fire.

const store = require("./store");

function handle(term) {
    return store.runQuery(term);
}

module.exports = { handle };
