// Multi-hop taint chain fixture (issue #175).
//
// Three-file chain: routes.js (source) -> transform.js (passthrough) -> services.js (sink)
//
// The taint flows:
//   1. req.query.q in routes.js (source)
//   2. -> transform.normalize(q) returns the tainted value (passthrough)
//   3. -> services.runQuery(result) sinks into db.query (sink)
//
// Expected findings:
//   js/taint-sql-injection : 1  (multi-hop via transform passthrough)

const express = require("express");
const transform = require("./transform");
const services = require("./services");

const app = express();

app.get("/search", (req, res) => {
    const q = req.query.q;
    const cleaned = transform.normalize(q);
    const rows = services.runQuery(cleaned);
    res.json({ rows });
});
