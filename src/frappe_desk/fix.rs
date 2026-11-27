//! `--scope frappe --fix` (GB-024): the mechanical repairs of FRAPPE-LINK-TITLE and
//! FRAPPE-DOCTYPE-LABEL-TRANSLATED.

use super::super::*;

/// Replace the value of `"modified"` with now, in Frappe's format.
fn bump_modified(text: &str, now: &str) -> String {
    match Regex::new(r#"("modified"\s*:\s*")[^"]*(")"#) {
        Ok(re) => re
            .replace(text, |m: &regex::Captures| {
                format!("{}{now}{}", &m[1], &m[2])
            })
            .into_owned(),
        Err(_) => text.to_string(),
    }
}

/// `search_fields` added to a DocType JSON without reformatting it.
fn with_search_field(text: &str, field: &str) -> Option<String> {
    let empty = Regex::new(r#"("search_fields"\s*:\s*)"\s*""#).ok()?;
    if empty.is_match(text) {
        return Some(
            empty
                .replace(text, |m: &regex::Captures| format!("{}\"{field}\"", &m[1]))
                .into_owned(),
        );
    }
    let head = Regex::new(r#"(?m)^([ \t]*)"doctype"\s*:"#).ok()?;
    let m = head.captures(text)?;
    let at = m.get(0)?.start();
    let mut out = text.to_string();
    out.insert_str(at, &format!("{}\"search_fields\": \"{field}\",\n", &m[1]));
    serde_json::from_str::<Value>(&out).ok().map(|_| out)
}

fn po_quote(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// Applies the repairs and returns one line per change. A second run changes nothing.
pub(crate) fn apply(root: &Path, cfg: &FrappeConfig) -> Result<Vec<String>, String> {
    let c = build_ctx(root, cfg)?;
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string();
    let mut done = Vec::new();
    let targets: BTreeSet<&str> = c
        .doctypes
        .iter()
        .flat_map(|d| d.fields.iter())
        .filter(|f| f.fieldtype == "Link")
        .map(|f| f.options.as_str())
        .collect();
    let flagged = !rule_link_title(&c).is_empty();
    for d in c
        .doctypes
        .iter()
        .filter(|d| flagged && !d.title_ok && !d.is_child && targets.contains(d.name.as_str()))
    {
        let pick = ["Data", "Link"]
            .iter()
            .find_map(|t| d.fields.iter().find(|f| f.fieldtype == *t));
        let Some(field) = pick else {
            continue;
        };
        let Some(text) = with_search_field(&d.text, &field.fieldname) else {
            continue;
        };
        fs::write(c.root.join(&d.rel), bump_modified(&text, &now))
            .map_err(|e| format!("{}: {e}", d.rel))?;
        done.push(format!(
            "{}: search_fields = {}, modified bumped",
            d.rel, field.fieldname
        ));
    }
    let Some((pr, _)) = catalogue(&c) else {
        return Ok(done);
    };
    let missing: BTreeSet<String> = rule_labels(&c)
        .iter()
        .filter_map(|v| {
            let rest = v.message.strip_prefix('`')?;
            rest.split_once("` has no msgid in ")
                .map(|(t, _)| t.to_string())
        })
        .collect();
    if !missing.is_empty() {
        let path = c.root.join(&pr);
        let mut text = fs::read_to_string(&path).map_err(|e| format!("{pr}: {e}"))?;
        for id in &missing {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "\n# stenio-fix: translation needed\nmsgid \"{}\"\nmsgstr \"\"\n",
                po_quote(id)
            ));
        }
        fs::write(&path, text).map_err(|e| format!("{pr}: {e}"))?;
        done.push(format!(
            "{pr}: {} msgid(s) appended with an empty msgstr",
            missing.len()
        ));
    }
    Ok(done)
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let files: Vec<(String, String)> = [
        ("app/hooks.py", "x = 1\n"),
        ("app/locale/pt_BR.po", "msgid \"Code\"\nmsgstr \"Codigo\"\n"),
        (
            "app/m/doctype/part/part.json",
            "{\n \"doctype\": \"DocType\",\n \"modified\": \"2020-01-01 00:00:00.000000\",\n \"name\": \"Part\",\n \"fields\": [{\"fieldname\": \"code\", \"fieldtype\": \"Data\", \"label\": \"Code\"}]\n}\n",
        ),
        (
            "app/m/doctype/use/use.json",
            "{\"doctype\":\"DocType\",\"name\":\"Use\",\"fields\":[{\"fieldname\":\"part\",\"fieldtype\":\"Link\",\"options\":\"Part\",\"label\":\"Used \\\"Part\\\"\"}]}",
        ),
    ]
    .iter()
    .map(|(p, t)| (p.to_string(), t.to_string()))
    .collect();
    let ok = write_fixture("desk-fix", &files).is_some_and(|root| {
        let cfg = FrappeConfig {
            app: Some("app".into()),
            ..FrappeConfig::default()
        };
        let state = || {
            build_ctx(&root, &cfg).ok().map(|c| {
                (
                    rule_link_title(&c).len(),
                    rule_labels(&c)
                        .iter()
                        .filter(|v| v.message.contains("no msgid"))
                        .count(),
                )
            })
        };
        let before = state();
        let first = apply(&root, &cfg);
        let after = state();
        let second = apply(&root, &cfg);
        let part = read(&root.join("app/m/doctype/part/part.json"));
        let ok = before == Some((1, 1))
            && first.is_ok_and(|v| v.len() == 2)
            && after == Some((0, 0))
            && second.is_ok_and(|v| v.is_empty())
            && part.contains("\"search_fields\": \"code\"")
            && !part.contains("2020-01-01");
        let _ = fs::remove_dir_all(&root);
        ok
    });
    vec![("FRAPPE-FIX-LINK-TITLE-AND-LABELS".to_string(), ok)]
}
