// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file chain where the MIDDLE helper itself makes the cross-file call:
//
//   routes.js (source)  ->  service.handle()  ->  store.runQuery() (sink)
//      fileA                    fileB                   fileC
//
// Unlike express_chain (where the caller orchestrates both hops in one
// handler), here fileB's `handle` calls fileC's `runQuery` directly — so the
// chain A->f->g->sink is only found once fileB's summary is composed one hop
// deeper against fileC's summary. Scanning any single file finds no taint
// finding; only the full-directory scan resolves the chain.
//
// Expected findings on a directory scan:
//   js/taint-sql-injection : 1  (multi-hop: routes -> service -> store)
//   js/no-sql-injection    : 1  (regex hit on the concatenation in store.js)

const express = require("express");
const service = require("./service");

const app = express();

app.get("/search", (req, res) => {
    const q = req.query.q;
    const rows = service.handle(q);
    res.json({ rows });
});
