use super::{find_node_at_byte, node_text, CodeEdit};

/// Fix JavaScript XSS: wrap innerHTML/outerHTML/document.write assignments
/// with DOMPurify.sanitize().
///
/// Handles:
/// - `el.innerHTML = expr` -> `el.innerHTML = DOMPurify.sanitize(expr)`
/// - `document.write(expr)` -> `document.write(DOMPurify.sanitize(expr))`
pub fn fix_javascript(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let node = find_node_at_byte(root, sink_start)?;

    // Walk up to find the relevant assignment or call
    let mut current = node;
    loop {
        match current.kind() {
            // Assignment: el.innerHTML = expr
            "assignment_expression" | "augmented_assignment_expression" => {
                return fix_assignment(source, current);
            }
            // Call: document.write(expr)
            "call_expression"
                if current.start_byte() <= sink_start && current.end_byte() >= sink_end =>
            {
                return fix_write_call(source, current);
            }
            // Expression statement wrapping an assignment
            "expression_statement" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    if child.kind() == "assignment_expression" {
                        return fix_assignment(source, child);
                    }
                }
            }
            _ => {}
        }
        current = current.parent()?;
    }
}

/// Fix `el.innerHTML = expr` -> `el.innerHTML = DOMPurify.sanitize(expr)`
fn fix_assignment(source: &str, assign_node: tree_sitter::Node) -> Option<Vec<CodeEdit>> {
    let left = assign_node.child_by_field_name("left")?;
    let right = assign_node.child_by_field_name("right")?;

    let left_text = node_text(left, source);

    // Check this is an innerHTML/outerHTML assignment
    if !left_text.contains("innerHTML") && !left_text.contains("outerHTML") {
        return None;
    }

    let right_text = node_text(right, source);

    // Don't double-wrap if already sanitized
    if right_text.contains("DOMPurify.sanitize") || right_text.contains("sanitize(") {
        return None;
    }

    let replacement = format!("DOMPurify.sanitize({})", right_text);

    Some(vec![CodeEdit {
        start_byte: right.start_byte(),
        end_byte: right.end_byte(),
        replacement,
    }])
}

/// Fix `document.write(expr)` -> `document.write(DOMPurify.sanitize(expr))`
fn fix_write_call(source: &str, call_node: tree_sitter::Node) -> Option<Vec<CodeEdit>> {
    let func = call_node
        .child_by_field_name("function")
        .or_else(|| call_node.child_by_field_name("callee"))?;
    let func_text = node_text(func, source);

    if !func_text.contains("write") && !func_text.contains("writeln") {
        return None;
    }

    let args = call_node.child_by_field_name("arguments")?;
    let first_arg = first_positional_arg(args)?;
    let arg_text = node_text(first_arg, source);

    // Don't double-wrap
    if arg_text.contains("DOMPurify.sanitize") {
        return None;
    }

    let replacement = format!("DOMPurify.sanitize({})", arg_text);

    Some(vec![CodeEdit {
        start_byte: first_arg.start_byte(),
        end_byte: first_arg.end_byte(),
        replacement,
    }])
}

fn first_positional_arg(args: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = args.walk();
    let result = args
        .named_children(&mut cursor)
        .find(|child| child.kind() != "spread_element");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parse_file;
    use crate::Language;

    #[test]
    fn test_fix_innerhtml_assignment() {
        let source = "element.innerHTML = userInput";
        let tree = parse_file(source, Language::JavaScript).unwrap();
        // The sink covers the whole expression
        let edits = fix_javascript(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].replacement, "DOMPurify.sanitize(userInput)");
    }

    #[test]
    fn test_fix_document_write() {
        let source = "document.write(userInput)";
        let tree = parse_file(source, Language::JavaScript).unwrap();
        let edits = fix_javascript(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].replacement, "DOMPurify.sanitize(userInput)");
    }

    #[test]
    fn test_no_double_wrap() {
        let source = "element.innerHTML = DOMPurify.sanitize(userInput)";
        let tree = parse_file(source, Language::JavaScript).unwrap();
        let result = fix_javascript(source, &tree, 0, source.len());
        assert!(result.is_none());
    }
}
