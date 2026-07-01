// Cross-file taint fixture for the Kotlin taint engine (taint-expansion).
//
// Two-file chain: Controller.kt (source) -> CommandHelper.kt (sink).
//
// Flow:
//   1. call.receiveText() in Controller.handle (Ktor request-body source)
//   2. -> CommandHelper.run(cmd): the pass-1 summary records that parameter 0
//      of run reaches a Runtime.exec command sink, so passing a tainted
//      argument into it produces a cross-file finding here in Controller.kt.
//
// Expected when scanning the directory:
//   kt/taint-command-injection : 1   (cross-file, reported in Controller.kt)
//
// Scanning Controller.kt ALONE must produce 0 kt/taint-command-injection
// findings: the helper body is unseen and `run` is not itself a sink.

package com.example.chain

fun handle(call: ApplicationCall) {
    val cmd = call.receiveText()
    CommandHelper.run(cmd)
}
