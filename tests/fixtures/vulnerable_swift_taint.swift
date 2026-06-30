// Positive fixture for the Swift taint engine.
//
// Each function flows a dynamically-constructed string (interpolation or
// concatenation with a non-literal operand) into a dangerous call. Every
// `swift/taint-*` rule must fire exactly once across this file.
import Foundation
import WebKit

// swift/taint-sql-injection — interpolated SQL into sqlite3_exec.
func sqlInjection(input: String, db: OpaquePointer) {
    let query = "SELECT * FROM users WHERE name = '\(input)'"
    sqlite3_exec(db, query, nil, nil, nil)
}

// swift/taint-command-injection — interpolated command into system().
func commandInjection(input: String) {
    system("echo \(input)")
}

// swift/taint-js-injection — interpolated script into evaluateJavaScript.
func jsInjection(input: String, webView: WKWebView) {
    webView.evaluateJavaScript("document.title = '\(input)'")
}

// swift/taint-nsexpression-injection — interpolated format into NSExpression.
func nsExpressionInjection(input: String) {
    let expr = NSExpression(format: "1 + \(input)")
    _ = expr
}

// ─── Near-misses: dynamic strings into UNRELATED calls (no sink) ────────────

// Interpolated string into a logging call — not a tracked sink, no finding.
func nearMissLogging(input: String) {
    print("user said \(input)")
    NSLog("value = \(input)")
}

// Concatenated string passed to a harmless helper — not a tracked sink.
func nearMissHelper(input: String) {
    let label = "Hello, " + input
    updateLabel(label)
}
