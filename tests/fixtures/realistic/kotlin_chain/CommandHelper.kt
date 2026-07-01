// Sink helper for the Kotlin cross-file taint fixture.
//
// run() takes a parameter and passes it into a Runtime.exec command sink. The
// pass-1 cross-file summary records params_to_sink for parameter 0 with rule
// kt/taint-command-injection. `term` is a plain parameter (not a taint
// source), so this file on its own produces no taint finding — the flow only
// exists once a tainted argument is passed in from Controller.kt.

package com.example.chain

object CommandHelper {
    fun run(term: String) {
        Runtime.getRuntime().exec(term)
    }
}
