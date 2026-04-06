import { ruleGroups } from './rules';

export interface Feature {
  icon: string;
  title: string;
  desc: string;
}

export const features: Feature[] = [
  {
    icon: '< 1s',
    title: 'Single binary',
    desc: 'No JVM, no Python runtime, no network calls. Rust-native and fast enough for pre-commit hooks.',
  },
  {
    icon: 'hook',
    title: 'Pre-commit ready',
    desc: 'Run foxguard init to install a repo-local hook and get a starter .foxguard.yml.',
  },
  {
    icon: '.yaml',
    title: 'Bring your own rules',
    desc: 'Load a useful Semgrep-compatible YAML subset on top of built-ins when you need it.',
  },
  {
    icon: 'base',
    title: 'Baselines',
    desc: 'Accept existing findings once and focus only on new ones with a baseline file.',
  },
  {
    icon: 'secret',
    title: 'Secrets scanning',
    desc: 'Detect leaked credentials and private keys with redacted output and binary-safe handling.',
  },
  {
    icon: 'SARIF',
    title: 'CI-friendly output',
    desc: 'Terminal output locally, JSON and SARIF for automation and GitHub Code Scanning.',
  },
];

export interface FrameworkGroup {
  title: string;
  desc: string;
  badges: string[];
  ruleCount: number;
}

const countForSlugs = (...slugs: string[]) =>
  ruleGroups
    .filter((group) => slugs.includes(group.slug))
    .reduce((sum, group) => sum + group.rules.length, 0);

export const frameworkGroups: FrameworkGroup[] = [
  {
    title: 'Express / Node',
    desc: 'Session secrets, cookie flags, JWT hardening, reflected response writes.',
    badges: ['session', 'cookies', 'jwt', 'xss'],
    ruleCount: countForSlugs('js'),
  },
  {
    title: 'Flask / Django',
    desc: 'Secret keys, debug mode, CSRF protection, session cookie flags, and Django host/redirect hardening.',
    badges: ['secret keys', 'csrf', 'session', 'debug'],
    ruleCount: countForSlugs('py'),
  },
  {
    title: 'Gin / net/http',
    desc: 'Trusted proxies, missing timeouts, SSRF, TLS verification bypass.',
    badges: ['proxies', 'timeouts', 'ssrf', 'tls'],
    ruleCount: countForSlugs('go'),
  },
  {
    title: 'Rails / Ruby',
    desc: 'Mass assignment, CSRF bypass, unsafe deserialization, XSS escaping.',
    badges: ['params', 'csrf', 'marshal', 'xss'],
    ruleCount: countForSlugs('rb'),
  },
  {
    title: 'Spring / Java',
    desc: 'SQL injection, XXE, deserialization, CSRF config, CORS policy.',
    badges: ['sql', 'xxe', 'csrf', 'cors'],
    ruleCount: countForSlugs('java'),
  },
  {
    title: 'PHP / Laravel',
    desc: 'Eval, file inclusion, unserialize, command injection, extract.',
    badges: ['eval', 'include', 'unserialize', 'ssrf'],
    ruleCount: countForSlugs('php'),
  },
  {
    title: 'Rust',
    desc: 'Unsafe blocks, transmute, command injection, TLS verification.',
    badges: ['unsafe', 'transmute', 'tls', 'unwrap'],
    ruleCount: countForSlugs('rs'),
  },
  {
    title: 'C# / .NET',
    desc: 'SQL injection, deserialization, XXE, LDAP injection, CORS.',
    badges: ['sql', 'xxe', 'ldap', 'cors'],
    ruleCount: countForSlugs('cs'),
  },
  {
    title: 'Swift / iOS',
    desc: 'Keychain security, transport security, JS injection, TLS.',
    badges: ['keychain', 'tls', 'transport', 'webview'],
    ruleCount: countForSlugs('swift'),
  },
];

export interface CompatFeature {
  label: string;
  supported: boolean;
}

export const compatFeatures: CompatFeature[] = [
  { label: 'pattern', supported: true },
  { label: 'pattern-regex', supported: true },
  { label: 'pattern-either', supported: true },
  { label: 'pattern-not', supported: true },
  { label: 'pattern-not-regex', supported: true },
  { label: 'pattern-inside', supported: true },
  { label: 'pattern-not-inside', supported: true },
  { label: 'patterns (AND)', supported: true },
  { label: 'metavariable-regex', supported: true },
  { label: 'paths.include/exclude', supported: true },
  { label: 'Full Semgrep syntax', supported: false },
];
