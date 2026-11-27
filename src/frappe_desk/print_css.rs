//! A small reader of the CSS of printable pages, shared by the print rules.

use super::super::*;
use super::support::*;

/// One declaration of a style rule that reaches paper.
pub(super) struct Decl {
    pub selector: String,
    pub property: String,
    pub value: String,
    pub line: usize,
}

/// The text with CSS and Jinja spans replaced by spaces, newlines kept so line numbers hold.
fn blanked(text: &str) -> String {
    let Ok(re) = Regex::new(r"(?s)/\*.*?\*/|\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}|<!--.*?-->") else {
        return text.to_string();
    };
    re.replace_all(text, |m: &regex::Captures| {
        m[0].chars()
            .map(|c| if c == '\n' { '\n' } else { ' ' })
            .collect::<String>()
    })
    .into_owned()
}

/// `(media queries, selector, property, value, line)` of one CSS text starting at `base`.
fn parse(css: &str, base: usize, out: &mut impl Extend<(String, Decl)>) {
    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut line = base;
    let mut start = base;
    let flush = |stack: &[String], buf: &str, line: usize| -> Option<(String, Decl)> {
        let selector = stack.iter().rev().find(|s| !s.starts_with('@'))?.clone();
        let (p, v) = buf.split_once(':')?;
        let media = stack
            .iter()
            .filter(|s| s.starts_with("@media"))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        Some((
            media,
            Decl {
                selector,
                property: p.trim().to_lowercase(),
                value: v.trim().to_lowercase(),
                line,
            },
        ))
    };
    for ch in css.chars() {
        match ch {
            '{' => {
                stack.push(buf.trim().to_string());
                buf.clear();
            }
            '}' | ';' => {
                out.extend(flush(&stack, &buf, start));
                buf.clear();
                if ch == '}' {
                    stack.pop();
                }
            }
            _ => {
                if buf.trim().is_empty() {
                    start = line;
                }
                buf.push(ch);
            }
        }
        if ch == '\n' {
            line += 1;
        }
    }
}

/// Class, id and element tokens of one selector (`.bar a.on` -> `.bar`, `a`, `.on`).
fn tokens(selector: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"[.#]?[A-Za-z_][\w-]*") else {
        return Vec::new();
    };
    re.find_iter(selector)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Every printable `.html` / `.css` file of the app (it declares `@page`, and with
/// `or_print_media` also `@media print`) with the declarations that reach paper: not inside a
/// screen-only media query and not under a class or id that print hides. Inline `style=`
/// attributes count, with an empty selector.
pub(super) fn printable(c: &Ctx, or_print_media: bool) -> Vec<(PathBuf, Vec<Decl>)> {
    let (Ok(style), Ok(inline)) = (
        Regex::new(r"(?is)<style[^>]*>(.*?)</style>"),
        Regex::new(r#"(?i)\sstyle\s*=\s*"([^"]*)""#),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in sources(c, &["html", "css"]) {
        let text = blanked(&read(p));
        if !(text.contains("@page") || (or_print_media && text.contains("@media print"))) {
            continue;
        }
        let mut all: Vec<(String, Decl)> = Vec::new();
        if p.extension().is_some_and(|e| e == "css") {
            parse(&text, 1, &mut all);
        } else {
            for m in style.captures_iter(&text) {
                if let Some(body) = m.get(1) {
                    parse(body.as_str(), line_at(&text, body.start()), &mut all);
                }
            }
            for m in inline.captures_iter(&text) {
                if let Some(body) = m.get(1) {
                    let rule = format!("inline{{{}}}", body.as_str());
                    parse(&rule, line_at(&text, body.start()), &mut all);
                }
            }
        }
        let hidden: BTreeSet<String> = all
            .iter()
            .filter(|(media, d)| {
                media.contains("print") && d.property == "display" && d.value.starts_with("none")
            })
            .flat_map(|(_, d)| d.selector.split(',').filter_map(|s| tokens(s).pop()))
            .filter(|t| t.starts_with(['.', '#']))
            .collect();
        let paper = all
            .into_iter()
            .filter(|(media, d)| {
                let screen_only = media.contains("screen") && !media.contains("print");
                let unseen = d
                    .selector
                    .split(',')
                    .all(|s| tokens(s).iter().any(|t| hidden.contains(t)));
                !screen_only && !unseen
            })
            .map(|(_, d)| d)
            .collect();
        out.push((p.clone(), paper));
    }
    out
}
