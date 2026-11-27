//! FRAPPE-PO-CATALOGUE-RESOLVES (GB-084).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-PO-CATALOGUE-RESOLVES",
    name: "Translation Catalogue That Does Not Resolve",
    severity: "ERROR",
    tag: "frappe",
    summary: "The `locale_file` of `[frappe]` resolves neither inside the package nor under the app root (ERROR), or none is configured and no `.po` exists in `<package>/locale` or `<app>/locale` (WARN). Every catalogue rule would otherwise compare against nothing.",
    rationale: "GB-084 (2026-11-05): the sidebar, label and Select rules looked only inside the package while the bench layout keeps the catalogue one level up, so they reported zero findings on a tree with 6840 msgids.",
    bad_example: "[frappe]\nlocale_file = \"locale/pt_BR.po\"   # the file moved",
    good_example: "[frappe]\nlocale_file = \"locale/pt_BR.po\"   # app/locale/pt_BR.po exists",
    remediation: "Point locale_file at the catalogue, or ship one.",
};

const UNCHECKED: &str = "FRAPPE-SIDEBAR-COVERAGE, FRAPPE-SELECT-CASE, FRAPPE-DOCTYPE-LABEL-TRANSLATED, FRAPPE-I18N-SOURCE-LITERALS, FRAPPE-TEMPLATE-LITERALS-TRANSLATED and FRAPPE-REQD-MESSAGES";

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    if catalogue(c).is_some() {
        return Vec::new();
    }
    let (tried, configured) = match &c.cfg.locale_file {
        Some(f) => (
            format!(
                "{} and {}",
                c.pkg.join(f).display(),
                c.root.join(f).display()
            ),
            true,
        ),
        None => (
            format!(
                "{} and {}",
                c.pkg.join("locale").display(),
                c.root.join("locale").display()
            ),
            false,
        ),
    };
    let mut v = finding(
        &EXPLAIN,
        &rel(&c.root, &c.pkg.join("hooks.py")),
        1,
        "locale",
        format!("No translation catalogue resolves (tried {tried}): {UNCHECKED} checked nothing."),
    );
    if !configured {
        v.severity = Severity::Warning;
    }
    vec![v]
}

fn configured_missing() -> bool {
    let files = [
        ("app/hooks.py", "x = 1\n"),
        ("app/locale/pt_BR.po", "msgid \"a\"\nmsgstr \"b\"\n"),
    ];
    let files: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect();
    let Some(root) = write_fixture("po-configured", &files) else {
        return false;
    };
    let count = |locale: &str| {
        let cfg = FrappeConfig {
            app: Some("app".into()),
            locale_file: Some(locale.to_string()),
            ..FrappeConfig::default()
        };
        build_ctx(&root, &cfg).ok().map(|c| {
            run(&c)
                .iter()
                .filter(|v| v.severity == Severity::Error && v.message.contains("tried"))
                .count()
        })
    };
    let ok = count("locale/pt_BR.po") == Some(0) && count("locale/es.po") == Some(1);
    let _ = fs::remove_dir_all(&root);
    ok
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let inside = ("app/locale/pt_BR.po", "msgid \"a\"\nmsgstr \"b\"\n");
    let bench = ("locale/pt_BR.po", "msgid \"a\"\nmsgstr \"b\"\n");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[inside])
            && silent(run, &[bench])
            && fires(run, &[], 1, &["tried", "checked nothing"])
            && configured_missing(),
    )]
}
