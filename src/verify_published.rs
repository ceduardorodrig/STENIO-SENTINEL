//! `verify-release` check `published-content` (GB-149): a Single published from a file of the app
//! must hold, on the live site, the same bytes as that file inside the running image.
//!
//! Declared per document: `[[frappe.published_content]] doctype, field, file` (`file` relative to
//! the app repository, as the image carries it under `apps/<app>/`). Nothing declared: no check.

use super::{Check, Cmd, Ctx, Status, Transport, check};
use crate::config::{FrappeConfig, PublishedContent};

const NAME: &str = "published-content";

fn plain(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// Remote command printing the size and the sha256 of one packaged file; None when unsafe.
pub(super) fn image_file_cmd(dir: &str, path: &str) -> Option<String> {
    plain(path, "_./-").then(|| {
        format!(
            "cd {dir} && docker compose exec -T backend sh -c 'wc -c < apps/{path} && sha256sum apps/{path}'"
        )
    })
}

fn sql(p: &PublishedContent) -> Option<String> {
    (plain(&p.doctype, "_ -") && plain(&p.field, "_")).then(|| {
        format!(
            "select length(value), sha2(value, 256) from tabSingles where doctype = \"{}\" and field = \"{}\"",
            p.doctype, p.field
        )
    })
}

/// `(size, sha256)` from whitespace-separated output: the number, then the 64-digit hash.
fn size_and_hash(out: &str) -> Option<(u64, String)> {
    let mut words = out.split_whitespace();
    let size = words.next()?.parse().ok()?;
    let hash = words.next()?;
    (hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| (size, hash.to_ascii_lowercase()))
}

fn one(t: &dyn Transport, c: &Ctx, app: &str, p: &PublishedContent) -> Check {
    let what = format!("{}.{}", p.doctype, p.field);
    let skip = |why: String| check(Status::Warn, NAME, format!("{what}: skipped, {why}"));
    let Some(query) = sql(p) else {
        return skip("unsafe doctype or field name in the configuration".into());
    };
    let image = match t.run(&Cmd::ImageFile(format!("{app}/{}", p.file)), c) {
        Ok(r) if r.code == 0 => match size_and_hash(&r.stdout) {
            Some(v) => v,
            None => return skip(format!("cannot hash {} in the running image", p.file)),
        },
        Ok(r) => return skip(format!("image unreadable (exit {}) for {}", r.code, p.file)),
        Err(e) => return skip(format!("image unreachable: {e}")),
    };
    let site = match t.run(&Cmd::Sql(query), c) {
        Ok(r) if r.code == 0 => r.stdout,
        Ok(r) => return skip(format!("site query failed (exit {})", r.code)),
        Err(e) => return skip(format!("site unreachable: {e}")),
    };
    if site.trim().is_empty() {
        return check(
            Status::Fail,
            NAME,
            format!(
                "{what}: the site holds no value; the image carries {} bytes sha256 {}",
                image.0,
                &image.1[..12]
            ),
        );
    }
    let Some(live) = size_and_hash(&site) else {
        return skip("unexpected answer from the site".into());
    };
    let (status, verdict) = if live == image {
        (Status::Pass, "==")
    } else {
        (Status::Fail, "!=")
    };
    check(
        status,
        NAME,
        format!(
            "{what}: site {} bytes sha256 {} {verdict} image {} {} bytes sha256 {}",
            live.0,
            &live.1[..12],
            p.file,
            image.0,
            &image.1[..12]
        ),
    )
}

pub(super) fn checks(t: &dyn Transport, c: &Ctx, fc: &FrappeConfig) -> Vec<Check> {
    let app = fc.app.clone().unwrap_or_default();
    fc.published_content
        .iter()
        .flatten()
        .map(|p| one(t, c, &app, p))
        .collect()
}

pub(super) fn self_test_cases() -> Vec<(String, bool)> {
    use super::Fake;
    use std::collections::BTreeMap;
    let doc = PublishedContent {
        doctype: "Handbook".into(),
        field: "content".into(),
        file: "app/docs/manual.html".into(),
    };
    let fc = FrappeConfig {
        app: Some("app".into()),
        published_content: Some(vec![doc.clone()]),
        ..FrappeConfig::default()
    };
    let c = Ctx {
        dir: "/srv/app".into(),
        site: "frontend".into(),
    };
    let (new, old) = ("a".repeat(64), "b".repeat(64));
    let image = Cmd::ImageFile("app/app/docs/manual.html".into());
    let Some(query) = sql(&doc) else {
        return vec![("verify-release published-content query".into(), false)];
    };
    let run = |site: Option<String>| -> Option<(Status, String)> {
        let mut m = BTreeMap::from([(image.clone(), (0, format!("42\n{new}  apps/x\n")))]);
        if let Some(s) = site {
            m.insert(Cmd::Sql(query.clone()), (0, s));
        }
        checks(&Fake(m), &c, &fc)
            .pop()
            .map(|k| (k.status, k.detail))
    };
    let same = run(Some(format!("42\t{new}\n")));
    let stale = run(Some(format!("37\t{old}\n")));
    let empty = run(Some(String::new()));
    let unreachable = run(None);
    vec![
        (
            "verify-release published-content: equal bytes pass".into(),
            same.is_some_and(|(s, _)| s == Status::Pass),
        ),
        (
            "verify-release published-content: mutation, a stale body fails with sizes and hashes"
                .into(),
            stale.is_some_and(|(s, d)| {
                s == Status::Fail
                    && [
                        "Handbook.content",
                        "37 bytes",
                        "42 bytes",
                        &old[..12],
                        &new[..12],
                    ]
                    .iter()
                    .all(|w| d.contains(w))
            }),
        ),
        (
            "verify-release published-content: mutation, a missing value fails".into(),
            empty.is_some_and(|(s, _)| s == Status::Fail),
        ),
        (
            "verify-release published-content: an unreachable site is skipped with a reason".into(),
            unreachable.is_some_and(|(s, d)| s == Status::Warn && d.contains("skipped")),
        ),
        (
            "verify-release published-content: a path with shell characters is refused".into(),
            image_file_cmd("/srv/app", "x; rm -rf y").is_none()
                && image_file_cmd("/srv/app", "app/app/docs/manual.html").is_some(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn published_content_proves_itself() {
        for (name, ok) in super::self_test_cases() {
            assert!(ok, "{name}");
        }
    }
}
