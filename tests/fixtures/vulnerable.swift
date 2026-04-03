import Foundation
import WebKit
import CommonCrypto
import Security

// Rule 1: Hardcoded secrets
let apiKey = "sk-live-abc123def456"
let password = "SuperSecret123!"
var token = "ghp_xxxxxxxxxxxxxxxxxxxx"

// Rule 2: Command injection
func runCommand(userInput: String) {
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", userInput]
    task.launch()
}

// Rule 3: Weak crypto
func hashData(data: Data) {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5(data.bytes, CC_LONG(data.count), &digest)
    let sha1Hash = data.sha1
    let md5Hash = Insecure.MD5.hash(data: data)
}

// Rule 4: Insecure transport
let endpoint = "http://api.example.com/v1/users"
let config = "http://config.internal.company.net/settings"

// Rule 5: evaluateJavaScript with dynamic input
func executeJS(webView: WKWebView, script: String) {
    webView.evaluateJavaScript(script) { result, error in
        print(result ?? "no result")
    }
}

// Rule 6: SQL injection via string interpolation
func getUser(db: OpaquePointer, userId: String) {
    let query = "SELECT * FROM users WHERE id = '\(userId)'"
    sqlite3_exec(db, query, nil, nil, nil)
}

// Rule 7: Insecure keychain accessibility
func storeInKeychain(value: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        kSecValueData as String: value.data(using: .utf8)!
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// Rule 8: TLS disabled
func configureTrust() {
    let policy = ServerTrustPolicy.disableEvaluation
    let trust = URLCredential(trust: serverTrust)
    let config = URLSessionConfiguration.default
    config.allowsExpiredCertificates = true
    config.allowsExpiredRoots = true
}

// Rule 9: Path traversal with FileManager
func readFile(userPath: String) {
    let fileManager = FileManager.default
    let contents = try fileManager.contentsOfDirectory(atPath: userPath)
    try fileManager.removeItem(atPath: userPath)
}

// Rule 10: SSRF via URL with dynamic input
func fetchData(urlString: String) {
    let url = URL(string: urlString)!
    let task = URLSession.shared.dataTask(with: url) { data, response, error in
        print(data ?? "no data")
    }
    task.resume()
}
