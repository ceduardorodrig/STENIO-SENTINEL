//! FRAPPE-PATCH-ORDER-DEPENDENCY (GB-201).

use super::*;
use regex::Regex;
use std::collections::BTreeSet;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-PATCH-ORDER-DEPENDENCY",
        name: "Patch Reads A Field A Later Patch Rewrites",
        severity: "ERROR",
        tag: "frappe",
        summary: "A patch listed in patches.txt reads `DocType.field` (get_all, get_list, get_value, count, exists with a literal DocType) that a patch listed LATER writes with `frappe.db.set_value`, and the reader does not write it itself.",
        rationale: "GB-201: sprint_cycle_backfill reads Squad.status, which group_vocabulary rewrites from `Formed` to `Active`. Only the line order of patches.txt made the backfill see the active squads; reordered, it opens 0 cycles and still prints success.",
        bad_example: "# patches.txt\napp.patches.backfill       # reads Squad.status\napp.patches.vocabulary     # set_value(\"Squad\", name, \"status\", ...)",
        good_example: "# patches.txt\napp.patches.vocabulary\napp.patches.backfill",
        remediation: "List the writer before the reader in patches.txt.",
    },
};

type Use = (String, String);

/// `(reads, writes)` of one patch module, as `(DocType, field)` pairs with literal names only.
fn uses(text: &str) -> (BTreeSet<Use>, BTreeSet<Use>) {
    let (mut reads, mut writes) = (BTreeSet::new(), BTreeSet::new());
    let (Ok(call), Ok(word), Ok(filters), Ok(selected), Ok(value), Ok(written)) = (
        Regex::new(
            r#"frappe(?:\.db)?\.(get_all|get_list|get_value|get_values|count|exists|set_value)\(\s*["']([^"']+)["']"#,
        ),
        Regex::new(r#"["']([a-z_][a-z0-9_]*)["']"#),
        Regex::new(r#"(?s)\{([^{}]*)\}"#),
        Regex::new(r#"(?s)(?:fields\s*=\s*\[([^\]]*)\]|pluck\s*=\s*(["'][a-z0-9_]+["']))"#),
        Regex::new(r#"(?s)^\s*,\s*[^,{]+,\s*(\(?[^()=]*?["'][a-z0-9_]+["'][^()=]*\)?)\s*(?:,|$)"#),
        Regex::new(r#"(?s)^\s*,\s*[^,]+,\s*(?:["']([a-z0-9_]+)["']|\{([^{}]*)\})"#),
    ) else {
        return (reads, writes);
    };
    let Ok(key) = Regex::new(r#"["']([a-z_][a-z0-9_]*)["']\s*:"#) else {
        return (reads, writes);
    };
    for m in call.captures_iter(text) {
        let (Some(all), Some(verb), Some(dt)) = (m.get(0), m.get(1), m.get(2)) else {
            continue;
        };
        let Some(open) = text[all.start()..].find('(').map(|o| all.start() + o) else {
            continue;
        };
        let Some((_, close)) = super::super::balanced_at(text, open, b'(', b')') else {
            continue;
        };
        let Some(rest) = text.get(all.end()..close.max(all.end())) else {
            continue;
        };
        let rest = rest.trim_end_matches(')');
        let dt = dt.as_str().to_string();
        let add = |set: &mut BTreeSet<Use>, field: &str| {
            if field != "name" {
                set.insert((dt.clone(), field.to_string()));
            }
        };
        if verb.as_str() == "set_value" {
            if let Some(w) = written.captures(rest) {
                if let Some(f) = w.get(1) {
                    add(&mut writes, f.as_str());
                }
                if let Some(d) = w.get(2) {
                    for k in key.captures_iter(d.as_str()) {
                        add(&mut writes, &k[1]);
                    }
                }
            }
            continue;
        }
        for f in filters.captures_iter(rest) {
            for k in key.captures_iter(&f[1]) {
                add(&mut reads, &k[1]);
            }
        }
        for s in selected.captures_iter(rest) {
            let list = s.get(1).or_else(|| s.get(2)).map_or("", |g| g.as_str());
            for w in word.captures_iter(list) {
                add(&mut reads, &w[1]);
            }
        }
        if verb.as_str().starts_with("get_value")
            && let Some(v) = value.captures(rest)
        {
            for w in word.captures_iter(&v[1]) {
                add(&mut reads, &w[1]);
            }
        }
    }
    (reads, writes)
}

fn rule(c: &Ctx) -> Vec<Violation> {
    let list = c.pkg.join("patches.txt");
    let label = rel(&c.root, &list);
    let patches: Vec<(usize, String, BTreeSet<Use>, BTreeSet<Use>)> = super::super::read(&list)
        .lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let module = raw.split('#').next()?.split_whitespace().next()?;
            let mut parts: Vec<&str> = module.split('.').collect();
            if parts.first() != Some(&c.app.as_str()) {
                return None;
            }
            if parts.last() == Some(&"execute") {
                parts.pop();
            }
            let file = c.pkg.join(format!("{}.py", parts.get(1..)?.join("/")));
            let (reads, writes) = uses(&super::super::read(&file));
            Some((i + 1, module.to_string(), reads, writes))
        })
        .collect();
    let mut out = Vec::new();
    for (i, (line, reader, reads, own)) in patches.iter().enumerate() {
        for (later, writer, _, writes) in &patches[i + 1..] {
            for (dt, field) in reads.intersection(writes) {
                if !own.contains(&(dt.clone(), field.clone())) {
                    out.push(hit(&ITEM, &label, *line, reader, format!(
                        "`{reader}` reads `{dt}.{field}` but `{writer}` (line {later}) writes it afterwards: on an old database the reader sees the previous value."
                    )));
                }
            }
        }
    }
    out
}

fn self_test() -> bool {
    const READER: &str = "def execute():\n\tfor s in frappe.get_all(\"Squad\", fields=[\"name\", \"status\"], order_by=\"name asc\"):\n\t\topen_cycle(s)\n";
    const WRITER: &str = "def execute():\n\tfor n in frappe.get_all(\"Squad\", filters={\"status\": \"Formed\"}, pluck=\"name\"):\n\t\tfrappe.db.set_value(\"Squad\", n, \"status\", \"Active\")\n";
    const OTHER: &str = "def execute():\n\tfrappe.db.set_value(\"Squad\", \"x\", {\"title\": 1})\n";
    let run = |order: &str, writer: &str| {
        count(
            &ITEM,
            &[
                ("app/patches.txt", order),
                ("app/patches/backfill.py", READER),
                ("app/patches/vocabulary.py", writer),
            ],
        )
    };
    let wrong = "app.patches.backfill\napp.patches.vocabulary\n";
    let right = "app.patches.vocabulary\napp.patches.backfill\n";
    run(wrong, WRITER) == Some(1) && run(right, WRITER) == Some(0) && run(wrong, OTHER) == Some(0)
}
