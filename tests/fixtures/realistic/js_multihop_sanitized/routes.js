// Negative multi-hop fixture (fileA — the source).
//
// Identical shape to js_multihop, but the MIDDLE helper sanitizes the tainted
// value before forwarding it. The multi-hop chain must therefore BREAK: no
// js/taint-sql-injection finding may be emitted on a directory scan.
//
// Expected findings on a directory scan:
//   (no taint rule)
//   js/no-sql-injection : 1  (regex hit on the concatenation in store.js)

const express = require("express");
const service = require("./service");

const app = express();

app.get("/search", (req, res) => {
    const q = req.query.q;
    const rows = service.handle(q);
    res.json({ rows });
});
