//! FRAPPE-INCLUDE-TARGET-EXISTS (GB-105).

use super::super::*;
use super::hooks_assets::asset_strings;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-INCLUDE-TARGET-EXISTS",
    name: "Hook Includes An Asset The App Does Not Ship",
    severity: "ERROR",
    tag: "frappe",
    summary: "A JS/CSS path of an asset hook in hooks.py (app_include_*, web_include_*, webform_include_*, doctype_*_js, page_js, email_css) that is this app's and has no file: `/assets/<app>/x` and `public/x` resolve under the package, a bare `*.bundle.*` name anywhere under public/. Other apps' assets are not judged.",
    rationale: "GB-105 (2026-11-05, rc101): nothing checked that the file an `app_include_js` entry names exists, so a rename ships a 404 include and a silently missing guard. FRAPPE-HOOK-TARGETS reads dotted Python paths only.",
    bad_example: "app_include_js = [\"/assets/app/js/nav_permisions.js\"]",
    good_example: "app_include_js = [\"/assets/app/js/nav_permissions.js\"]   # app/public/js/nav_permissions.js",
    remediation: "Fix the path or ship the file under public/.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let hooks = c.pkg.join("hooks.py");
    let public = c.pkg.join("public");
    let own = format!("assets/{}/", c.app);
    let mut out = Vec::new();
    for (line, path) in asset_strings(&read(&hooks)) {
        let p = path.trim_start_matches('/');
        let exists = if let Some(rest) = p.strip_prefix(&own) {
            public.join(rest).is_file()
        } else if p.starts_with("assets/") || p.contains("://") || p.contains('{') {
            continue; // another app, a CDN, or a computed name
        } else if p.starts_with("public/") {
            c.pkg.join(p).is_file()
        } else if p.contains(".bundle.") {
            c.files.iter().any(|f| {
                f.starts_with(&public)
                    && f.file_name().and_then(|n| n.to_str())
                        == Path::new(p).file_name().and_then(|n| n.to_str())
            })
        } else {
            continue;
        };
        if !exists {
            out.push(finding(
                &EXPLAIN,
                &rel(&c.root, &hooks),
                line,
                &path,
                format!("hooks.py includes `{path}`, and the app ships no such file under public/: the browser gets a 404."),
            ));
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let hooks = (
        "app/hooks.py",
        "app_include_js = [\n\tf\"/assets/app/js/a.js?v={v}\",\n\t\"x.bundle.js\",\n\t\"/assets/frappe/js/y.js\",\n]\ndoctype_js = {\n\t\"Task\": \"public/js/t.js\",\n}\n# web_include_css = \"/assets/app/css/gone.css\"\n",
    );
    let a = ("app/public/js/a.js", "1\n");
    let b = ("app/public/js/x.bundle.js", "1\n");
    let t = ("app/public/js/t.js", "1\n");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[hooks, a, b, t])
            && fires(run, &[hooks, b, t], 1, &["/assets/app/js/a.js"])
            && fires(run, &[hooks, a, b], 1, &["public/js/t.js"])
            && fires(run, &[hooks, a, t], 1, &["x.bundle.js"]),
    )]
}
