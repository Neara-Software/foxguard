// Negative counterpart for the Swift taint engine.
//
// Every function passes a STATIC string literal (no interpolation, no
// concatenation with a non-literal operand) into the same sinks, so the
// dynamically-constructed-string source never fires. No `swift/taint-*`
// rule may fire on this file.
import Foundation
import WebKit

// Literal SQL — fully static, parameter bound separately.
func safeSql(input: String, db: OpaquePointer, stmt: inout OpaquePointer?) {
    let query = "SELECT * FROM users WHERE name = ?"
    sqlite3_prepare_v2(db, query, -1, &stmt, nil)
    sqlite3_exec(db, "PRAGMA foreign_keys = ON", nil, nil, nil)
}

// Literal command — static argument.
func safeCommand() {
    system("ls -la")
    popen("uptime", "r")
}

// Literal script — static argument.
func safeJs(webView: WKWebView) {
    webView.evaluateJavaScript("document.title = 'static'")
}

// Literal NSExpression format — static argument.
func safeNsExpression() {
    let expr = NSExpression(format: "1 + 1")
    _ = expr
}

// Dynamic string, but flowing into a non-sink call.
func safeDynamicNonSink(input: String) {
    let msg = "user: " + input
    print(msg)
}
