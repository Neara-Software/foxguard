use crate::Language;

/// Parse source code into a tree-sitter Tree for the given language.
pub fn parse_file(source: &str, language: Language) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();

    let ts_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
    };

    parser.set_language(&ts_language).ok()?;
    parser.parse(source, None)
}
