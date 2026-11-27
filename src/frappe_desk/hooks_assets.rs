//! Reading of the asset hooks of `hooks.py`, shared by the include rules.

use super::super::*;

/// The hooks whose value names JS / CSS files of the app.
pub(super) const ASSET_HOOKS: &[&str] = &[
    "app_include_js",
    "app_include_css",
    "web_include_js",
    "web_include_css",
    "webform_include_js",
    "webform_include_css",
    "doctype_js",
    "doctype_list_js",
    "doctype_tree_js",
    "doctype_kanban_js",
    "doctype_calendar_js",
    "page_js",
    "email_css",
];

/// `(1-based line, path)` of every `.js` / `.css` string assigned to an asset hook, in any
/// layout (string, list, dict, comprehension). Comments register nothing; a query is dropped.
pub(super) fn asset_strings(hooks: &str) -> Vec<(usize, String)> {
    let Ok(re) = Regex::new(r#"["']([^"'\n]+?\.(?:js|css))(?:\?[^"'\n]*)?["']"#) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut inside = false;
    for (i, raw) in hooks.lines().enumerate() {
        let code = strip_comment(raw);
        if !inside {
            let name: String = code
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect();
            let rest = code[name.len()..].trim_start();
            if !ASSET_HOOKS.contains(&name.as_str())
                || !(rest.starts_with('=') || rest.starts_with("+=") || rest.starts_with('['))
            {
                continue;
            }
            inside = true;
        }
        out.extend(re.captures_iter(&code).map(|m| (i + 1, m[1].to_string())));
        depth += code.matches(['[', '(', '{']).count() as i32
            - code.matches([']', ')', '}']).count() as i32;
        if depth <= 0 {
            inside = false;
            depth = 0;
        }
    }
    out
}
