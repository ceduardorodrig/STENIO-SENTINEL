//! UI-ASSET-VERSION-PARITY (GB-170).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "UI-ASSET-VERSION-PARITY",
    name: "Cache-Busted Assets Without A Version Endpoint",
    severity: "ERROR",
    tag: "frappe",
    summary: "hooks.py cache-busts an include with `?v={...}` but no `@frappe.whitelist` function of the app (allowing GET) returns `__version__`, so an open tab cannot learn that it is stale.",
    rationale: "GB-170 (rc123): five of six open sessions were older than the deploy and a user read a stale Desk as `the platform has no such field`. The URL stamp only helps a page that is loaded again.",
    bad_example: "app_include_js = [f\"/assets/app/js/a.js?v={_app_version}\"]   # and no endpoint",
    good_example: "@frappe.whitelist(methods=[\"GET\"])\ndef running():\n\treturn {\"version\": __version__}",
    remediation: "Expose a whitelisted GET returning the app version, poll it from the Desk, and test it by calling it.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let hooks = c.pkg.join("hooks.py");
    let text = read(&hooks);
    let Some(at) = text.lines().position(|l| strip_comment(l).contains("?v={")) else {
        return Vec::new();
    };
    let Ok(decorator) = Regex::new(
        r"(?m)^@(?:frappe\.)?whitelist\(([^)]*)\)\s*\n(?:@[^\n]*\n)*(?:async\s+)?def\s+(\w+)",
    ) else {
        return Vec::new();
    };
    let served = sources(c, &["py"]).any(|p| {
        let src = read(p);
        let lines: Vec<&str> = src.lines().collect();
        decorator.captures_iter(&src).any(|m| {
            let verbs = &m[1];
            let get = !verbs.contains("methods") || verbs.contains("GET");
            get && py_function(&lines, &m[2]).is_some_and(|(_, body)| {
                body.lines().any(|l| {
                    let l = py_strip_comment(l);
                    l.trim_start().starts_with("return")
                        && (l.contains("__version__") || l.contains("_app_version"))
                })
            })
        })
    });
    if served {
        return Vec::new();
    }
    vec![finding(
        &EXPLAIN,
        &rel(&c.root, &hooks),
        at + 1,
        "?v={",
        "Assets are cache-busted with `?v=` but no whitelisted GET returns `__version__`: an open tab cannot tell it is stale.".to_string(),
    )]
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let hooks = (
        "app/hooks.py",
        "app_include_js = [f\"/assets/app/js/a.js?v={_app_version}\"]\n",
    );
    let good = (
        "app/version.py",
        "@frappe.whitelist(methods=[\"GET\"])\ndef running():\n\treturn {\"version\": __version__}\n",
    );
    let post = (
        "app/version.py",
        "@frappe.whitelist(methods=[\"POST\"])\ndef running():\n\treturn {\"version\": __version__}\n",
    );
    let prose = (
        "app/version.py",
        "@frappe.whitelist()\ndef running():\n\t# returns __version__\n\treturn {}\n",
    );
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[hooks, good])
            && silent(run, &[("app/hooks.py", "app_name = \"app\"\n")])
            && fires(run, &[hooks], 1, &["__version__"])
            && fires(run, &[hooks, post], 1, &["whitelisted GET"])
            && fires(run, &[hooks, prose], 1, &["whitelisted GET"]),
    )]
}
