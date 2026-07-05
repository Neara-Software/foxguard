// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file Kotlin chain where the MIDDLE helper itself makes the cross-file
// call:
//
//   handle()  ->  forward()  ->  runQuery()
//   fileA (source)   fileB          fileC (sink)
//
// fileB's `forward` calls fileC's `runQuery` directly — so the chain
// A->f->g->sink is only found once fileB's summary is composed one hop deeper
// against fileC's summary. Scanning any single file finds no taint finding;
// only the full-directory scan resolves the chain.

fun handle() {
    val body = call.receiveText()
    forward(body)
}
