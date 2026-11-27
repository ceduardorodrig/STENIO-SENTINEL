//! FRAPPE-DOCTYPE-JS-REGISTERED (GB-095).

use super::super::*;
use super::hooks_assets::asset_strings;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-DOCTYPE-JS-REGISTERED",
    name: "Client Script No One Loads",
    severity: "ERROR",
    tag: "frappe",
    summary: "A file of `public/js/` that no asset hook of hooks.py names and no template, page, script or bundle import of the app references (tests and comments do not count). `*.bundle.*` files are built entries and are skipped.",
    rationale: "GB-095: Frappe loads a client script only through hooks (`doctype_js`, `app_include_js`, `doctype_calendar_js`, ...) or the `<doctype>.js` convention (desk/form/meta.py), so a file in public/js that lost its entry ships in the image and never runs, with no error.",
    bad_example: "public/js/sprint_calendar.js   # doctype_calendar_js entry removed",
    good_example: "doctype_calendar_js = {\"Sprint\": \"public/js/sprint_calendar.js\"}",
    remediation: "Register the file in hooks.py (or load it from a template / import), or delete it.",
};

/// The code of `text` without its comments, by file type.
fn code_of(path: &Path, text: &str) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => text
            .lines()
            .map(strip_comment)
            .collect::<Vec<_>>()
            .join("\n"),
        Some("js") | Some("ts") => blank_js_comments(text),
        _ => text.to_string(),
    }
}

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let js_dir = c.pkg.join("public").join("js");
    let scripts: Vec<&PathBuf> = sources(c, &["js"])
        .filter(|p| p.starts_with(&js_dir) && !p.to_string_lossy().contains(".bundle."))
        .collect();
    if scripts.is_empty() {
        return Vec::new();
    }
    let hooked: Vec<String> = asset_strings(&read(&c.pkg.join("hooks.py")))
        .into_iter()
        .map(|(_, s)| s)
        .collect();
    let others: Vec<(&PathBuf, String)> = sources(c, &["py", "js", "ts", "html", "json", "vue"])
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("hooks.py"))
        .map(|p| (p, code_of(p, &read(p))))
        .collect();
    let mut out = Vec::new();
    for script in scripts {
        let tail = rel(&c.pkg.join("public"), script);
        let Some(stem) = script.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(import) = Regex::new(&format!(
            r#"(?:import|require)\b[^\n]*["'][./][^"'\n]*\b{}(?:\.js)?["']"#,
            regex::escape(stem)
        )) else {
            continue;
        };
        let named = hooked.iter().any(|h| h.ends_with(&tail))
            || others
                .iter()
                .any(|(p, code)| *p != script && (code.contains(&tail) || import.is_match(code)));
        if !named {
            let r = rel(&c.root, script);
            out.push(finding(
                &EXPLAIN,
                &r,
                1,
                &tail,
                format!("`{r}` is loaded by nothing: no hooks.py entry names it and no template, script or import references it, so it never runs."),
            ));
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let hooks = (
        "app/hooks.py",
        "doctype_calendar_js = {\"Sprint\": \"public/js/sprint_calendar.js\"}\n",
    );
    let unhooked = (
        "app/hooks.py",
        "# doctype_calendar_js = {\"Sprint\": \"public/js/sprint_calendar.js\"}\n",
    );
    let cal = (
        "app/public/js/sprint_calendar.js",
        "// public/js/unused.js\n",
    );
    let page = (
        "app/www/p.html",
        "<script src=\"/assets/app/js/page.js\"></script>\n",
    );
    let loaded = ("app/public/js/page.js", "import \"./helper\";\n");
    let helper = ("app/public/js/helper.js", "1\n");
    let stray = ("app/public/js/unused.js", "1\n");
    let test = ("app/tests/t.py", "X = \"public/js/unused.js\"\n");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[hooks, cal, page, loaded, helper])
            && fires(
                run,
                &[hooks, cal, stray, test],
                1,
                &["unused.js", "hooks.py"],
            )
            && fires(
                run,
                &[unhooked, cal],
                1,
                &["sprint_calendar.js", "hooks.py"],
            ),
    )]
}
