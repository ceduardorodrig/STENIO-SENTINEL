//! FRAPPE-DOCTYPE-DECLARED-EVERYWHERE (GB-208, absorbs GB-153).

use super::*;
use regex::Regex;
use std::collections::BTreeSet;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-DOCTYPE-DECLARED-EVERYWHERE",
        name: "DocType Missing One Of Its Declarations",
        severity: "ERROR",
        tag: "frappe",
        summary: "Every non-child DocType must appear in each registry the app has: `MATRIX` of tests/w5_permissions.py, `const INFO` of public/js/<app>.js, a translated msgid in the pt_BR catalogue, and a sidebar link or an allowlist (`sidebar_allowlist` file or a test `NO_SIDEBAR`). One finding per DocType lists every gap. Stale names in `MATRIX` and `INFO` are reported too. A registry the app does not have is not judged.",
        rationale: "GB-153/GB-208: Asset Custody and Knowledge Snapshot were declared in some places and not in others; the release battery, three separate gates and manual `rg` found the gaps one at a time, at release time.",
        bad_example: "# new doctype `Asset Custody`, only the sidebar link added",
        good_example: "MATRIX = {\"Asset Custody\": \"rw----\"}\nconst INFO = {\n\t\"Asset Custody\": [\"x\", \"Who holds it.\"],\n\t};\nmsgid \"Asset Custody\"",
        remediation: "Add every declaration the message lists; delete declarations of DocTypes that no longer exist.",
    },
};

/// Keys of the `const INFO` map (`"Name": [...]`), read as the app's visual test reads them.
fn info_keys(text: &str, head: &Regex, key: &Regex) -> Option<(usize, Vec<(usize, String)>)> {
    let at = head.find(text)?.end().saturating_sub(1);
    let body = &text[at..];
    // The map closes on its own line; the nested value arrays are not keys.
    let body = body.find("};").map_or(body, |end| &body[..end]);
    let entries = key
        .captures_iter(body)
        .filter_map(|m| m.get(1))
        .map(|g| (g.start(), g.as_str().to_string()))
        .collect();
    Some((at, entries))
}

/// Keys of the object literal that follows `head`, with the byte offset of the literal.
fn keys(text: &str, head: &Regex) -> Option<(usize, Vec<(usize, String)>)> {
    let at = head.find(text)?.end().saturating_sub(1);
    let body = &text[at..];
    Some((at, super::privacy_lists::literal_names(body)))
}

fn rule(c: &Ctx) -> Vec<Violation> {
    let (Ok(matrix_head), Ok(info_head), Ok(core_head)) = (
        Regex::new(r"(?m)^MATRIX\s*=\s*\{"),
        Regex::new(r"const INFO\s*=\s*\{"),
        Regex::new(r"(?m)^FRAPPE_DOCTYPES\s*=\s*\{"),
    ) else {
        return Vec::new();
    };
    let matrix_file = c.pkg.join("tests/w5_permissions.py");
    let matrix_text = super::super::read(&matrix_file);
    let matrix = keys(&matrix_text, &matrix_head);
    let info_file = c.pkg.join(format!("public/js/{}.js", c.app));
    let info_text = super::super::read(&info_file);
    let info = Regex::new(r#""([^"\n]+)"\s*:\s*\["#)
        .ok()
        .and_then(|key| info_keys(&info_text, &info_head, &key));
    let catalogue = super::super::catalogue(c);

    let mut sidebar_seen = false;
    let mut linked: BTreeSet<String> = BTreeSet::new();
    for p in c.files.iter().filter(|p| {
        p.extension().is_some_and(|e| e == "json")
            && p.components().any(|k| k.as_os_str() == "sidebar")
    }) {
        sidebar_seen = true;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&super::super::read(p)) {
            let items = v.get("items").and_then(|i| i.as_array());
            for i in items.into_iter().flatten() {
                if let Some(to) = i.get("link_to").and_then(|s| s.as_str()) {
                    linked.insert(to.to_string());
                }
            }
        }
    }
    if let Some(f) = &c.cfg.sidebar_allowlist {
        linked.extend(
            super::super::read(&c.root.join(f))
                .lines()
                .map(|l| l.split(['|', '#']).next().unwrap_or("").trim().to_string()),
        );
    }
    for (_, _, text) in test_modules(c) {
        linked.extend(
            super::sidebar_lists::no_sidebar_names(&text)
                .into_iter()
                .map(|(_, n)| n),
        );
    }

    let mut out = Vec::new();
    let has = |list: &Option<(usize, Vec<(usize, String)>)>, name: &str| {
        list.as_ref()
            .is_none_or(|(_, v)| v.iter().any(|(_, n)| n == name))
    };
    for d in c.doctypes.iter().filter(|d| !d.is_child) {
        let mut gaps = Vec::new();
        if !has(&matrix, &d.name) {
            gaps.push("permission matrix row (tests/w5_permissions.py MATRIX)".to_string());
        }
        if !has(&info, &d.name) {
            gaps.push(format!("INFO entry (public/js/{}.js)", c.app));
        }
        if let Some((file, map)) = &catalogue
            && map.get(&d.name).is_none_or(|t| t.is_empty())
        {
            gaps.push(format!("translated msgid ({file})"));
        }
        if sidebar_seen && !linked.contains(&d.name) {
            gaps.push("sidebar link or allowlist entry".to_string());
        }
        if !gaps.is_empty() {
            out.push(hit(
                &ITEM,
                &d.rel,
                1,
                &d.name,
                format!("DocType `{}` lacks: {}.", d.name, gaps.join("; ")),
            ));
        }
    }
    if c.doctypes.is_empty() {
        return out;
    }
    // Stale declarations. Frappe's own DocTypes listed by the app's visual test are legitimate.
    let visual = super::super::read(&c.pkg.join("tests/visual_pure.py"));
    let core: Vec<String> = keys(&visual, &core_head)
        .map(|(_, v)| v.into_iter().map(|(_, n)| n).collect())
        .unwrap_or_default();
    for (list, text, file, what) in [
        (&matrix, &matrix_text, &matrix_file, "MATRIX"),
        (&info, &info_text, &info_file, "INFO"),
    ] {
        let Some((at, entries)) = list else { continue };
        for (offset, name) in entries {
            if !c.doctypes.iter().any(|d| &d.name == name)
                && !core.contains(name)
                && !super::privacy_lists::CORE_DOCTYPES.contains(&name.as_str())
            {
                let line = text[..at + offset].matches('\n').count() + 1;
                out.push(hit(&ITEM, &rel(&c.root, file), line, name, format!(
                    "{what} declares `{name}`, which is not a DocType of the app (renamed or deleted)."
                )));
            }
        }
    }
    out
}

fn self_test() -> bool {
    let a = doctype("Part", "");
    let matrix = "MATRIX = {\n\t\"Part\": \"r-\",\n}\n";
    let info = "const INFO = {\n\t\t\"Part\": [\"x\", \"A part.\"],\n\t};\n";
    let po = "msgid \"Part\"\nmsgstr \"Peca\"\n";
    let side = "{\"items\":[{\"link_to\":\"Part\"}]}";
    let run = |matrix: &str, info: &str, po: &str, side: &str| {
        probe(
            &ITEM,
            &FrappeConfig::default(),
            &[
                ("app/m/doctype/part/part.json", &a),
                ("app/tests/w5_permissions.py", matrix),
                ("app/public/js/app.js", info),
                ("app/locale/pt_BR.po", po),
                ("app/sidebar/app/app.json", side),
            ],
        )
    };
    let n = |v: Option<Vec<Violation>>| v.map(|v| v.len());
    let all_gone = run(
        "MATRIX = {\n}\n",
        "const INFO = {\n\t};\n",
        "",
        "{\"items\":[]}",
    );
    let one_report_lists_four = all_gone.is_some_and(|v| {
        v.len() == 1
            && ["MATRIX", "INFO", "msgid", "sidebar"]
                .iter()
                .all(|w| v[0].message.contains(w))
    });
    let stale = "MATRIX = {\n\t\"Part\": \"r-\",\n\t\"Old Part\": \"r-\",\n}\n";
    n(run(matrix, info, po, side)) == Some(0)
        && one_report_lists_four
        && n(run("MATRIX = {\n}\n", info, po, side)) == Some(1)
        && n(run(matrix, info, "msgid \"Part\"\nmsgstr \"\"\n", side)) == Some(1)
        && n(run(stale, info, po, side)) == Some(1)
}
