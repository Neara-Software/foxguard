pub mod go;
pub mod javascript;
pub mod python;
pub mod semgrep_compat;

use crate::{Finding, Language, Severity};
use std::path::Path;

/// A security rule that checks parsed source code for vulnerabilities.
pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn severity(&self) -> Severity;
    fn cwe(&self) -> Option<&str>;
    fn description(&self) -> &str;
    fn language(&self) -> Language;
    fn applies_to_path(&self, _path: &Path) -> bool {
        true
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding>;
}

/// Registry holding all available rules.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleRegistry {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn new() -> Self {
        let mut registry = Self { rules: Vec::new() };

        // Register JavaScript rules
        registry.register(Box::new(javascript::NoEval));
        registry.register(Box::new(javascript::NoHardcodedSecret));
        registry.register(Box::new(javascript::NoSqlInjection));
        registry.register(Box::new(javascript::NoXssInnerHtml));
        registry.register(Box::new(javascript::NoCommandInjection));
        registry.register(Box::new(javascript::NoDocumentWrite));
        registry.register(Box::new(javascript::NoOpenRedirect));
        registry.register(Box::new(javascript::NoWeakCrypto));
        registry.register(Box::new(javascript::NoPathTraversal));
        registry.register(Box::new(javascript::NoSsrf));
        registry.register(Box::new(javascript::NoPrototypePollution));
        registry.register(Box::new(javascript::NoUnsafeRegex));
        registry.register(Box::new(javascript::NoCorsStar));
        registry.register(Box::new(javascript::ExpressNoHardcodedSessionSecret));
        registry.register(Box::new(javascript::ExpressCookieNoSecure));
        registry.register(Box::new(javascript::ExpressCookieNoHttpOnly));
        registry.register(Box::new(javascript::ExpressCookieNoSameSite));
        registry.register(Box::new(javascript::ExpressDirectResponseWrite));
        registry.register(Box::new(javascript::JwtHardcodedSecret));
        registry.register(Box::new(javascript::JwtNoneAlgorithm));
        registry.register(Box::new(javascript::JwtIgnoreExpiration));

        // Register Python rules
        registry.register(Box::new(python::NoEval));
        registry.register(Box::new(python::NoHardcodedSecret));
        registry.register(Box::new(python::NoSqlInjection));
        registry.register(Box::new(python::NoCommandInjection));
        registry.register(Box::new(python::NoPathTraversal));
        registry.register(Box::new(python::NoSsrf));
        registry.register(Box::new(python::NoWeakCrypto));
        registry.register(Box::new(python::NoPickle));
        registry.register(Box::new(python::NoYamlLoad));
        registry.register(Box::new(python::NoDebugTrue));
        registry.register(Box::new(python::NoOpenRedirect));
        registry.register(Box::new(python::NoCorsStar));
        registry.register(Box::new(python::FlaskDebugMode));
        registry.register(Box::new(python::DjangoSecretKeyHardcoded));
        registry.register(Box::new(python::FlaskSecretKeyHardcoded));
        registry.register(Box::new(python::SessionCookieSecureDisabled));
        registry.register(Box::new(python::SessionCookieHttpOnlyDisabled));
        registry.register(Box::new(python::SessionCookieSameSiteDisabled));
        registry.register(Box::new(python::CsrfCookieSecureDisabled));
        registry.register(Box::new(python::CsrfCookieHttpOnlyDisabled));
        registry.register(Box::new(python::CsrfCookieSameSiteDisabled));

        // Register Go rules
        registry.register(Box::new(go::NoSqlInjection));
        registry.register(Box::new(go::NoCommandInjection));
        registry.register(Box::new(go::NoHardcodedSecret));
        registry.register(Box::new(go::NoWeakCrypto));
        registry.register(Box::new(go::NoSsrf));
        registry.register(Box::new(go::InsecureTlsSkipVerify));
        registry.register(Box::new(go::GinNoTrustedProxies));
        registry.register(Box::new(go::NetHttpNoTimeout));

        registry
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn rules_for_language(&self, language: Language) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.language() == language)
            .map(|r| r.as_ref())
            .collect()
    }

    #[allow(dead_code)]
    pub fn all_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}
