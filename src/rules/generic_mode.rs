//! Semgrep `generic` mode (a.k.a. spacegrep / `languages: [generic]`).
//!
//! Generic mode does **not** use a tree-sitter AST. It matches a tokenized
//! pattern against the raw text of a file, where:
//!
//! * `...` is an ellipsis that matches any run of tokens (including across
//!   whitespace and newlines, per semgrep's default for generic patterns),
//! * `$X` metavariables bind a single token span and enforce equality (the
//!   same metavariable must bind the same text everywhere it appears),
//! * every other token must match literally.
//!
//! This module is intentionally self-contained so it can evolve without
//! touching the AST-backed Semgrep bridge in `semgrep_compat.rs`. The compat
//! bridge only routes `languages: [generic]` (and the `regex` alias) rules
//! here; all generic/spacegrep matching logic lives in this file.
//!
//! ## Scope
//!
//! Supported: `pattern`, `pattern-either`, `pattern-not`, `pattern-regex`
//! (passthrough), `...` ellipsis, `$METAVAR` binding with equality
//! enforcement, and `paths.include` / `paths.exclude` scoping (handled by the
//! shared [`PathFilter`] on the compat side).
//!
//! Deliberately **not** implemented here: `metavariable-comparison` and
//! `metavariable-pattern` (owned by other modules), `pattern-inside` /
//! `pattern-not-inside` for generic mode, and the deep-vs-shallow ellipsis
//! brace-aware matching semgrep applies to brace-delimited languages. Generic
//! mode here treats the file as a flat token stream.

use crate::rules::common::get_source_line;
use crate::rules::semgrep_compat::PathFilter;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Every file language foxguard can hand to a rule. A generic-mode rule is
/// language-agnostic — semgrep runs it against any file that matches the
/// rule's `paths:` scope — so we register one rule instance per detectable
/// language and let the (shared) [`PathFilter`] narrow the targets. The
/// compiled matcher is shared via `Arc`, so the per-language fan-out is cheap.
const ALL_LANGUAGES: &[Language] = &[
    Language::JavaScript,
    Language::Python,
    Language::Go,
    Language::Ruby,
    Language::Java,
    Language::Php,
    Language::Rust,
    Language::CSharp,
    Language::Swift,
    Language::Kotlin,
    Language::C,
    Language::NginxConf,
    Language::ApacheConf,
    Language::HAProxyConf,
    Language::Dockerfile,
    Language::Manifest,
];

// ─── Tokenizer ──────────────────────────────────────────────────────────────

/// A single token with its byte span in the original source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Token<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

/// Tokenize `source` into a flat stream of word / punctuation tokens,
/// discarding whitespace. A "word" is a maximal run of ASCII alphanumerics
/// and underscores; every other non-whitespace byte becomes its own
/// single-character token. This mirrors spacegrep's default tokenization
/// closely enough for the config-file rule packs we target.
fn tokenize(source: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if is_word_byte(b) {
            let start = i;
            while i < bytes.len() && is_word_byte(bytes[i]) {
                i += 1;
            }
            tokens.push(Token {
                text: &source[start..i],
                start,
                end: i,
            });
        } else {
            // Multi-byte UTF-8 punctuation: take the whole char so byte spans
            // stay on char boundaries.
            let char_len = utf8_char_len(b);
            let end = (i + char_len).min(source.len());
            tokens.push(Token {
                text: &source[i..end],
                start: i,
                end,
            });
            i = end;
        }
    }
    tokens
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

// ─── Compiled pattern ─────────────────────────────────────────────────────────

/// A single element of a tokenized generic pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternElem {
    /// `...` — matches any run of tokens (zero or more).
    Ellipsis,
    /// `$X` — binds a single token's text, enforcing equality on repeats.
    Metavar(String),
    /// A literal token that must match exactly.
    Literal(String),
}

/// Compile a generic pattern string into a token sequence.
fn compile_pattern(pattern: &str) -> Vec<PatternElem> {
    tokenize(pattern)
        .into_iter()
        .map(|tok| classify(tok.text))
        .collect::<Vec<_>>()
        .pipe_coalesce_ellipsis()
}

/// Classify a single pattern token. The `$` of a metavariable tokenizes
/// separately from its name (since `$` is punctuation and the name is a word),
/// so the `$ NAME` fold happens later in [`fold_dollars`].
fn classify(text: &str) -> RawElem {
    if text == "$" {
        RawElem::Dollar
    } else {
        RawElem::Elem(PatternElem::Literal(text.to_string()))
    }
}

/// Intermediate token before `$` + name coalescing and `.` + `.` + `.`
/// (ellipsis) coalescing.
#[derive(Debug, Clone)]
enum RawElem {
    Dollar,
    Elem(PatternElem),
}

trait CoalesceExt {
    fn pipe_coalesce_ellipsis(self) -> Vec<PatternElem>;
}

impl CoalesceExt for Vec<RawElem> {
    fn pipe_coalesce_ellipsis(self) -> Vec<PatternElem> {
        // First fold `$` + word into a metavar, then fold `.` `.` `.` into an
        // ellipsis. Both run in a single left-to-right pass each.
        let folded_metavars = fold_dollars(self);
        fold_ellipsis(folded_metavars)
    }
}

fn fold_dollars(raw: Vec<RawElem>) -> Vec<PatternElem> {
    let mut out = Vec::new();
    let mut iter = raw.into_iter().peekable();
    while let Some(elem) = iter.next() {
        match elem {
            RawElem::Dollar => {
                // `$` followed by a literal word → metavariable.
                if let Some(RawElem::Elem(PatternElem::Literal(name))) = iter.peek() {
                    if is_metavar_name(name) {
                        let name = name.clone();
                        iter.next();
                        out.push(PatternElem::Metavar(format!("${name}")));
                        continue;
                    }
                }
                // Lone `$` is a literal dollar sign.
                out.push(PatternElem::Literal("$".to_string()));
            }
            RawElem::Elem(e) => out.push(e),
        }
    }
    out
}

fn fold_ellipsis(elems: Vec<PatternElem>) -> Vec<PatternElem> {
    let mut out: Vec<PatternElem> = Vec::new();
    let mut dots = 0usize;
    for elem in elems {
        if matches!(&elem, PatternElem::Literal(l) if l == ".") {
            dots += 1;
            if dots == 3 {
                out.push(PatternElem::Ellipsis);
                dots = 0;
            }
            continue;
        }
        // Flush any pending stray dots (fewer than 3) as literals.
        for _ in 0..dots {
            out.push(PatternElem::Literal(".".to_string()));
        }
        dots = 0;
        out.push(elem);
    }
    for _ in 0..dots {
        out.push(PatternElem::Literal(".".to_string()));
    }
    out
}

fn is_metavar_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ─── Matcher ──────────────────────────────────────────────────────────────────

/// The compiled matching strategy for one generic rule.
#[derive(Debug, Clone)]
enum GenericMatcher {
    /// Tokenized pattern.
    Pattern(Vec<PatternElem>),
    /// `pattern-regex` passthrough against the raw text.
    Regex(Regex),
    /// `pattern-either` — any inner matcher matching is a match.
    Either(Vec<GenericMatcher>),
    /// One positive matcher with negative filters (`pattern-not`).
    ///
    /// A candidate is dropped if any negative matcher overlaps its span.
    Filtered {
        positive: Box<GenericMatcher>,
        negatives: Vec<GenericMatcher>,
    },
}

#[derive(Debug, Clone)]
struct GenericMatch {
    start_byte: usize,
    end_byte: usize,
}

impl GenericMatcher {
    fn find_all(&self, source: &str, tokens: &[Token<'_>]) -> Vec<GenericMatch> {
        match self {
            GenericMatcher::Pattern(elems) => find_pattern(elems, tokens),
            GenericMatcher::Regex(re) => re
                .find_iter(source)
                .map(|m| GenericMatch {
                    start_byte: m.start(),
                    end_byte: m.end(),
                })
                .collect(),
            GenericMatcher::Either(inner) => {
                let mut all = Vec::new();
                for m in inner {
                    all.extend(m.find_all(source, tokens));
                }
                dedup(all)
            }
            GenericMatcher::Filtered {
                positive,
                negatives,
            } => {
                let mut matches = positive.find_all(source, tokens);
                if !negatives.is_empty() {
                    let neg: Vec<GenericMatch> = negatives
                        .iter()
                        .flat_map(|n| n.find_all(source, tokens))
                        .collect();
                    matches.retain(|m| !neg.iter().any(|n| overlaps(m, n)));
                }
                matches
            }
        }
    }
}

fn overlaps(a: &GenericMatch, b: &GenericMatch) -> bool {
    a.start_byte < b.end_byte && b.start_byte < a.end_byte
}

fn dedup(mut matches: Vec<GenericMatch>) -> Vec<GenericMatch> {
    matches.sort_by_key(|m| (m.start_byte, m.end_byte));
    matches.dedup_by_key(|m| (m.start_byte, m.end_byte));
    matches
}

/// Try to match `elems` against the token stream, starting at every token
/// position. Returns the byte span of each match.
fn find_pattern(elems: &[PatternElem], tokens: &[Token<'_>]) -> Vec<GenericMatch> {
    if elems.is_empty() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for start in 0..tokens.len() {
        let mut bindings: HashMap<String, String> = HashMap::new();
        if let Some(end_idx) = match_from(elems, tokens, start, &mut bindings) {
            // `end_idx` is one past the last matched token. Skip empty matches
            // (e.g. a pattern that is only a trailing ellipsis).
            if end_idx > start {
                let span_start = tokens[start].start;
                let span_end = tokens[end_idx - 1].end;
                matches.push(GenericMatch {
                    start_byte: span_start,
                    end_byte: span_end,
                });
            }
        }
    }
    dedup(matches)
}

/// Recursive token matcher. Returns the index one past the last matched token
/// on success. `...` matches a (lazy) run of tokens; `$X` binds one token with
/// equality enforcement; literals must match exactly.
fn match_from(
    elems: &[PatternElem],
    tokens: &[Token<'_>],
    mut ti: usize,
    bindings: &mut HashMap<String, String>,
) -> Option<usize> {
    let mut pi = 0;
    while pi < elems.len() {
        match &elems[pi] {
            PatternElem::Ellipsis => {
                // Trailing ellipsis matches the rest (including nothing); the
                // span ends at the last preceding matched token, so return the
                // current cursor position.
                if pi + 1 == elems.len() {
                    return Some(ti);
                }
                // Lazily advance: try to match the remainder of the pattern at
                // each subsequent token position.
                let rest = &elems[pi + 1..];
                for skip in ti..=tokens.len() {
                    let mut trial = bindings.clone();
                    if let Some(end) = match_from(rest, tokens, skip, &mut trial) {
                        *bindings = trial;
                        return Some(end);
                    }
                }
                return None;
            }
            PatternElem::Metavar(name) => {
                let tok = tokens.get(ti)?;
                if let Some(existing) = bindings.get(name) {
                    if existing != tok.text {
                        return None;
                    }
                } else {
                    bindings.insert(name.clone(), tok.text.to_string());
                }
                ti += 1;
                pi += 1;
            }
            PatternElem::Literal(lit) => {
                let tok = tokens.get(ti)?;
                if tok.text != lit {
                    return None;
                }
                ti += 1;
                pi += 1;
            }
        }
    }
    Some(ti)
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

/// A compiled generic-mode rule. One instance per detectable language (the
/// matcher is shared via `Arc`); path filtering decides which files actually
/// run it.
pub struct GenericRule {
    id: String,
    message: String,
    severity: Severity,
    lang: Language,
    cwe: Option<String>,
    matcher: Arc<GenericMatcher>,
    path_filter: Option<Arc<PathFilter>>,
}

impl Rule for GenericRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn cwe(&self) -> Option<&str> {
        self.cwe.as_deref()
    }
    fn description(&self) -> &str {
        &self.message
    }
    fn language(&self) -> Language {
        self.lang
    }

    fn applies_to_path(&self, path: &Path) -> bool {
        self.path_filter
            .as_ref()
            .is_none_or(|filter| filter.matches(path))
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let tokens = tokenize(source);
        let mut matches = self.matcher.find_all(source, &tokens);
        matches.sort_by_key(|m| (m.start_byte, m.end_byte));
        matches.dedup_by_key(|m| (m.start_byte, m.end_byte));

        matches
            .into_iter()
            .map(|m| {
                let (line, column) = byte_offset_to_position(source, m.start_byte);
                let (end_line, end_column) = byte_offset_to_position(source, m.end_byte);
                Finding {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    cwe: self.cwe.clone(),
                    description: self.message.clone(),
                    file: String::new(),
                    line,
                    column,
                    end_line,
                    end_column,
                    snippet: get_source_line(source, m.start_byte),
                    source_line: None,
                    source_description: None,
                    sink_line: None,
                    sink_description: None,
                    fix_suggestion: None,
                    sink_start_byte: None,
                    sink_end_byte: None,
                    // Generic-mode matches are text-based and fuzzier than
                    // curated AST rules; mirror the AST-bridge default.
                    confidence: 0.7,
                    taint_hops: None,
                    tags: vec![],
                    crypto_algorithm: None,
                    cnsa2_deadline: None,
                    dep_name: None,
                    dep_version: None,
                    dep_ecosystem: None,
                    dep_purl: None,
                    dep_vulnerability_id: None,
                    dep_fixed_version: None,
                    dep_source: None,
                    dep_vulnerability_severity: None,
                    dep_path: vec![],
                }
            })
            .collect()
    }
}

fn byte_offset_to_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let byte_offset = byte_offset.min(source.len());
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |pos| pos + 1);
    let column = byte_offset - line_start + 1;
    (line, column)
}

// ─── Construction (called from the compat bridge) ──────────────────────────────

/// Build the generic matcher tree from the flat fields of a generic rule.
///
/// `pattern`, `pattern-regex`, `pattern-either`, and `pattern-not` are the
/// generic-mode subset we support; `patterns:` AND-blocks fall back to the
/// first positive (semgrep generic packs in our scope do not use AND-blocks).
fn build_matcher(
    pattern: Option<&str>,
    pattern_regex: Option<&str>,
    pattern_either: &[String],
    pattern_not: Option<&str>,
) -> Result<GenericMatcher, String> {
    let positive = if let Some(p) = pattern {
        GenericMatcher::Pattern(compile_pattern(p))
    } else if let Some(re) = pattern_regex {
        GenericMatcher::Regex(compile_regex(re)?)
    } else if !pattern_either.is_empty() {
        let inner = pattern_either
            .iter()
            .map(|p| GenericMatcher::Pattern(compile_pattern(p)))
            .collect();
        GenericMatcher::Either(inner)
    } else {
        return Err("generic rule has no pattern / pattern-regex / pattern-either".to_string());
    };

    if let Some(pn) = pattern_not {
        Ok(GenericMatcher::Filtered {
            positive: Box::new(positive),
            negatives: vec![GenericMatcher::Pattern(compile_pattern(pn))],
        })
    } else {
        Ok(positive)
    }
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| format!("Invalid pattern-regex '{pattern}': {e}"))
}

/// Parameters extracted from the compat YAML layer, kept as a small POD so the
/// compat-side dispatch stays a couple of lines.
pub struct GenericRuleSpec<'a> {
    pub id: &'a str,
    pub message: &'a str,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub pattern: Option<&'a str>,
    pub pattern_regex: Option<&'a str>,
    pub pattern_either: Vec<String>,
    pub pattern_not: Option<&'a str>,
    pub path_filter: Option<PathFilter>,
}

/// Compile a generic-mode rule spec into one boxed [`GenericRule`] per
/// detectable language. The compiled matcher and path filter are shared via
/// `Arc` so the fan-out is cheap.
pub fn build_generic_rules(spec: GenericRuleSpec<'_>) -> Result<Vec<Box<dyn Rule>>, String> {
    let matcher = Arc::new(build_matcher(
        spec.pattern,
        spec.pattern_regex,
        &spec.pattern_either,
        spec.pattern_not,
    )?);
    let path_filter = spec.path_filter.map(Arc::new);

    let rules = ALL_LANGUAGES
        .iter()
        .map(|&lang| {
            Box::new(GenericRule {
                id: format!("semgrep/{}", spec.id),
                message: spec.message.to_string(),
                severity: spec.severity,
                lang,
                cwe: spec.cwe.clone(),
                matcher: Arc::clone(&matcher),
                path_filter: path_filter.clone(),
            }) as Box<dyn Rule>
        })
        .collect();

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, source: &str) -> Vec<(usize, usize)> {
        let m = GenericMatcher::Pattern(compile_pattern(pattern));
        let tokens = tokenize(source);
        m.find_all(source, &tokens)
            .into_iter()
            .map(|m| byte_offset_to_position(source, m.start_byte))
            .collect()
    }

    #[test]
    fn tokenizes_words_and_punctuation() {
        let toks: Vec<&str> = tokenize("ssl_protocols TLSv1;")
            .iter()
            .map(|t| t.text)
            .collect();
        assert_eq!(toks, vec!["ssl_protocols", "TLSv1", ";"]);
    }

    #[test]
    fn compiles_metavar_and_ellipsis() {
        let elems = compile_pattern("listen $PORT ... ssl");
        assert_eq!(
            elems,
            vec![
                PatternElem::Literal("listen".to_string()),
                PatternElem::Metavar("$PORT".to_string()),
                PatternElem::Ellipsis,
                PatternElem::Literal("ssl".to_string()),
            ]
        );
    }

    #[test]
    fn lone_dollar_is_literal() {
        let elems = compile_pattern("cost $ 5");
        assert_eq!(
            elems,
            vec![
                PatternElem::Literal("cost".to_string()),
                PatternElem::Literal("$".to_string()),
                PatternElem::Literal("5".to_string()),
            ]
        );
    }

    #[test]
    fn literal_match_finds_line() {
        let positions = matches(
            "ssl_protocols TLSv1",
            "server {\n  ssl_protocols TLSv1;\n}\n",
        );
        assert_eq!(positions, vec![(2, 3)]);
    }

    #[test]
    fn ellipsis_matches_token_run() {
        // `...` should span across other directives.
        let positions = matches(
            "location ... proxy_pass",
            "location /api {\n  proxy_pass http://up;\n}\n",
        );
        assert_eq!(positions.len(), 1);
    }

    #[test]
    fn ellipsis_crosses_newlines() {
        let positions = matches("foo ... baz", "foo\nbar\nbaz\n");
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].0, 1);
    }

    #[test]
    fn metavar_equality_is_enforced() {
        // Same metavar twice must bind the same token.
        assert_eq!(matches("$X = $X", "a = a").len(), 1);
        assert!(matches("$X = $X", "a = b").is_empty());
    }

    #[test]
    fn metavar_binds_single_token() {
        let positions = matches("set $KEY $VAL", "set color red\nset size 10\n");
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn pattern_not_filters_overlapping_matches() {
        let matcher = GenericMatcher::Filtered {
            positive: Box::new(GenericMatcher::Pattern(compile_pattern(
                "ssl_protocols ...",
            ))),
            negatives: vec![GenericMatcher::Pattern(compile_pattern(
                "ssl_protocols TLSv1_3",
            ))],
        };
        let source = "ssl_protocols TLSv1;\nssl_protocols TLSv1_3;\n";
        let tokens = tokenize(source);
        let found = matcher.find_all(source, &tokens);
        // The TLSv1_3 line is excluded by pattern-not; only the TLSv1 line
        // (up to the line-ending `;`) survives. Ellipsis is greedy-lazy and
        // may span further, so assert the surviving match starts on line 1.
        assert!(!found.is_empty());
        for m in &found {
            assert_eq!(byte_offset_to_position(source, m.start_byte).0, 1);
        }
    }

    #[test]
    fn multiline_pattern_matches_across_lines() {
        let positions = matches(
            "server { ... listen 80",
            "server {\n  server_name x;\n  listen 80;\n}\n",
        );
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].0, 1);
    }

    #[test]
    fn regex_passthrough_matches() {
        let m = GenericMatcher::Regex(compile_regex(r"AKIA[0-9A-Z]{4}").unwrap());
        let source = "key = AKIA1234XYZ\n";
        let tokens = tokenize(source);
        assert_eq!(m.find_all(source, &tokens).len(), 1);
    }

    #[test]
    fn build_generic_rules_fans_out_per_language() {
        let spec = GenericRuleSpec {
            id: "generic-test",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: Some("ssl_protocols TLSv1"),
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();
        assert_eq!(rules.len(), ALL_LANGUAGES.len());
        assert_eq!(rules[0].id(), "semgrep/generic-test");
    }
}
