export interface Rule {
  id: string;
  cwe: string;
  desc: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface RuleGroup {
  name: string;
  slug: string;
  rules: Rule[];
}

const jsRules: Rule[] = [
  { id: 'js/no-eval', cwe: 'CWE-95', desc: 'Use of eval() allows arbitrary code execution', severity: 'critical' },
  { id: 'js/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'js/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation or template literal', severity: 'critical' },
  { id: 'js/no-xss-innerhtml', cwe: 'CWE-79', desc: 'Assignment to innerHTML may lead to XSS', severity: 'high' },
  { id: 'js/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via exec/spawn with dynamic input', severity: 'critical' },
  { id: 'js/no-document-write', cwe: 'CWE-79', desc: 'document.write() with dynamic content enables XSS', severity: 'high' },
  { id: 'js/no-open-redirect', cwe: 'CWE-601', desc: 'Open redirect via user-controlled URL', severity: 'medium' },
  { id: 'js/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'js/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via unsanitized user input', severity: 'high' },
  { id: 'js/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via dynamic outbound request URL', severity: 'high' },
  { id: 'js/no-prototype-pollution', cwe: 'CWE-1321', desc: 'Prototype pollution via object merge', severity: 'high' },
  { id: 'js/no-unsafe-regex', cwe: 'CWE-1333', desc: 'ReDoS-vulnerable regular expression', severity: 'medium' },
  { id: 'js/no-cors-star', cwe: 'CWE-942', desc: 'Permissive CORS policy (Access-Control-Allow-Origin: *)', severity: 'medium' },
  { id: 'js/express-no-hardcoded-session-secret', cwe: 'CWE-798', desc: 'Hardcoded session secret in express-session config', severity: 'high' },
  { id: 'js/express-cookie-no-secure', cwe: 'CWE-614', desc: 'Cookie config missing secure flag', severity: 'medium' },
  { id: 'js/express-cookie-no-httponly', cwe: 'CWE-1004', desc: 'Cookie config missing httpOnly flag', severity: 'medium' },
  { id: 'js/express-cookie-no-samesite', cwe: 'CWE-352', desc: 'Cookie config missing a safe sameSite setting', severity: 'medium' },
  { id: 'js/express-session-saveuninitialized-true', cwe: 'CWE-359', desc: 'express-session configured with saveUninitialized: true', severity: 'medium' },
  { id: 'js/express-direct-response-write', cwe: 'CWE-79', desc: 'XSS via res.send/res.write with user input', severity: 'high' },
  { id: 'js/jwt-hardcoded-secret', cwe: 'CWE-798', desc: 'JWT signing or verification with a hardcoded secret', severity: 'high' },
  { id: 'js/jwt-none-algorithm', cwe: 'CWE-347', desc: 'JWT configured to use the none algorithm', severity: 'high' },
  { id: 'js/jwt-ignore-expiration', cwe: 'CWE-613', desc: 'JWT verification configured to ignore token expiration', severity: 'high' },
  { id: 'js/jwt-decode-without-verify', cwe: 'CWE-347', desc: 'JWT decoded without signature verification', severity: 'high' },
  { id: 'js/jwt-verify-missing-algorithms', cwe: 'CWE-347', desc: 'JWT verification without an explicit algorithms allowlist', severity: 'high' },
];

const pyRules: Rule[] = [
  { id: 'py/no-eval', cwe: 'CWE-95', desc: 'Use of eval()/exec() allows arbitrary code execution', severity: 'critical' },
  { id: 'py/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'py/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string formatting', severity: 'critical' },
  { id: 'py/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via os.system/subprocess', severity: 'critical' },
  { id: 'py/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via unsanitized user input', severity: 'high' },
  { id: 'py/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via dynamic outbound request URL', severity: 'high' },
  { id: 'py/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'py/no-pickle', cwe: 'CWE-502', desc: 'Deserialization of untrusted data via pickle', severity: 'high' },
  { id: 'py/no-yaml-load', cwe: 'CWE-502', desc: 'Unsafe yaml.load() without SafeLoader', severity: 'high' },
  { id: 'py/no-debug-true', cwe: 'CWE-489', desc: 'DEBUG=True left enabled in production config', severity: 'medium' },
  { id: 'py/no-open-redirect', cwe: 'CWE-601', desc: 'Open redirect via user-controlled URL', severity: 'medium' },
  { id: 'py/no-cors-star', cwe: 'CWE-942', desc: 'Permissive CORS policy (CORS_ALLOW_ALL_ORIGINS)', severity: 'medium' },
  { id: 'py/flask-debug-mode', cwe: 'CWE-489', desc: 'Flask app.run(debug=True) exposes debugger in production', severity: 'high' },
  { id: 'py/django-secret-key-hardcoded', cwe: 'CWE-798', desc: 'Django SECRET_KEY hardcoded in source', severity: 'high' },
  { id: 'py/flask-secret-key-hardcoded', cwe: 'CWE-798', desc: 'Flask SECRET_KEY hardcoded in source', severity: 'high' },
  { id: 'py/session-cookie-secure-disabled', cwe: 'CWE-614', desc: 'SESSION_COOKIE_SECURE disabled in source', severity: 'medium' },
  { id: 'py/session-cookie-httponly-disabled', cwe: 'CWE-1004', desc: 'SESSION_COOKIE_HTTPONLY disabled in source', severity: 'medium' },
  { id: 'py/session-cookie-samesite-disabled', cwe: 'CWE-352', desc: 'SESSION_COOKIE_SAMESITE disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-secure-disabled', cwe: 'CWE-614', desc: 'CSRF_COOKIE_SECURE disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-httponly-disabled', cwe: 'CWE-1004', desc: 'CSRF_COOKIE_HTTPONLY disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-samesite-disabled', cwe: 'CWE-352', desc: 'CSRF_COOKIE_SAMESITE disabled in source', severity: 'medium' },
  { id: 'py/csrf-exempt', cwe: 'CWE-352', desc: 'View marked csrf_exempt', severity: 'high' },
  { id: 'py/wtf-csrf-disabled', cwe: 'CWE-352', desc: 'Flask-WTF CSRF protection disabled in source', severity: 'high' },
  { id: 'py/wtf-csrf-check-default-disabled', cwe: 'CWE-352', desc: 'Flask-WTF default CSRF checks disabled in source', severity: 'high' },
  { id: 'py/django-allowed-hosts-wildcard', cwe: 'CWE-346', desc: 'Django ALLOWED_HOSTS allows all hosts', severity: 'medium' },
  { id: 'py/secure-ssl-redirect-disabled', cwe: 'CWE-319', desc: 'Django SECURE_SSL_REDIRECT disabled in source', severity: 'medium' },
];

const goRules: Rule[] = [
  { id: 'go/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation or fmt.Sprintf', severity: 'critical' },
  { id: 'go/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via exec.Command with dynamic input', severity: 'critical' },
  { id: 'go/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'go/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'go/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via http.Get/http.Post with variable URL', severity: 'high' },
  { id: 'go/insecure-tls-skip-verify', cwe: 'CWE-295', desc: 'TLS verification disabled with InsecureSkipVerify', severity: 'high' },
  { id: 'go/gin-no-trusted-proxies', cwe: 'CWE-346', desc: 'Gin engine without SetTrustedProxies', severity: 'medium' },
  { id: 'go/net-http-no-timeout', cwe: 'CWE-400', desc: 'http.ListenAndServe without timeout config', severity: 'medium' },
];

export const ruleGroups: RuleGroup[] = [
  { name: 'JavaScript / TypeScript', slug: 'js', rules: jsRules },
  { name: 'Python', slug: 'py', rules: pyRules },
  { name: 'Go', slug: 'go', rules: goRules },
];

export const totalRules = ruleGroups.reduce((sum, g) => sum + g.rules.length, 0);
