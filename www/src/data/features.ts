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

export const frameworkGroups: FrameworkGroup[] = [
  {
    title: 'Express / Node',
    desc: 'Session secrets, cookie flags, JWT hardening, reflected response writes.',
    badges: ['session', 'cookies', 'jwt', 'xss'],
    ruleCount: 24,
  },
  {
    title: 'Flask / Django',
    desc: 'Secret keys, debug mode, CSRF protection, session cookie flags.',
    badges: ['secret keys', 'csrf', 'session', 'debug'],
    ruleCount: 26,
  },
  {
    title: 'Gin / net/http',
    desc: 'Trusted proxies, missing timeouts, SSRF, TLS verification bypass.',
    badges: ['proxies', 'timeouts', 'ssrf', 'tls'],
    ruleCount: 8,
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
