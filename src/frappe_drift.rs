//! `stenio frappe-drift`: is the Frappe/ERPNext base-image pin of a repository the latest v<N> release,
//! and does the version the running image reports match the pin? (GB-242, family GB-067/GB-070)
//!
//! Offline by construction: the latest version comes from `--latest`, `--latest-file` (a GitHub
//! releases JSON array or one version per line) or, only with `--online`, the GitHub releases API
//! through the engine HTTP helper. The pin is read from `ARG BASE_IMAGE=<image>:v<X.Y.Z>` in the
//! repository Dockerfile.

use clap::Parser;
use std::path::{Path, PathBuf};

type Ver = (u64, u64, u64);

#[derive(Parser, Debug)]
#[command(
    name = "stenio frappe-drift",
    about = "Base-image pin vs latest release and vs the running Frappe version (read-only)"
)]
struct DriftArgs {
    #[arg(
        long,
        help = "Repository directory (Dockerfile inside) or the Dockerfile itself"
    )]
    repo: PathBuf,
    #[arg(
        long,
        help = "Frappe version reported by the running image (bench version)"
    )]
    runtime_frappe: Option<String>,
    #[arg(long, help = "Latest release, e.g. v16.55.2")]
    latest: Option<String>,
    #[arg(
        long,
        help = "File with a GitHub releases JSON array or one version per line"
    )]
    latest_file: Option<PathBuf>,
    #[arg(
        long,
        help = "Fetch the latest release from the GitHub API of frappe/frappe"
    )]
    online: bool,
}

/// Parses `v16.53.0`, `16.53.0` or `frappe/erpnext:v16.53.0` into a numeric triple.
fn parse_ver(s: &str) -> Option<Ver> {
    let tail = s
        .rsplit(':')
        .next()
        .unwrap_or(s)
        .trim()
        .trim_start_matches('v');
    let mut it = tail.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it
        .next()?
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((a, b, c))
}

fn fmt_ver(v: Ver) -> String {
    format!("v{}.{}.{}", v.0, v.1, v.2)
}

/// The `BASE_IMAGE` pin of a Dockerfile text, as (image reference, version).
fn parse_pin(dockerfile: &str) -> Option<(String, Ver)> {
    dockerfile.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("ARG BASE_IMAGE=")?;
        Some((rest.trim().to_string(), parse_ver(rest)?))
    })
}

/// Highest stable release of the pin's major series in a releases JSON array or a plain list.
fn latest_in_series(text: &str, major: u64) -> Option<Ver> {
    let mut tags: Vec<(String, bool)> = Vec::new();
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Array(items)) => {
            for it in items {
                let name = it
                    .get("tag_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let pre = ["prerelease", "draft"]
                    .iter()
                    .any(|k| it.get(*k).and_then(|v| v.as_bool()).unwrap_or(false));
                tags.push((name.to_string(), pre));
            }
        }
        _ => tags.extend(text.lines().map(|l| (l.trim().to_string(), false))),
    }
    tags.iter()
        .filter(|(_, pre)| !pre)
        .filter_map(|(t, _)| parse_ver(t))
        .filter(|v| v.0 == major)
        .max()
}

/// Verdict lines (and failure flag) for a pin, the latest release and an optional runtime version.
fn verdicts(pin: Ver, latest: Ver, runtime: Option<&str>) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut fail = false;
    if pin < latest {
        fail = true;
        lines.push(format!(
            "FAIL behind: {} -> {}",
            fmt_ver(pin),
            fmt_ver(latest)
        ));
    } else {
        lines.push(format!(
            "PASS up-to-date pin={} latest={}",
            fmt_ver(pin),
            fmt_ver(latest)
        ));
    }
    if let Some(r) = runtime {
        match parse_ver(r) {
            Some(rv) if rv == pin => lines.push(format!(
                "PASS pin-vs-runtime: {} == {}",
                fmt_ver(pin),
                fmt_ver(rv)
            )),
            Some(rv) => {
                fail = true;
                lines.push(format!(
                    "FAIL pin-vs-runtime: {} != {}",
                    fmt_ver(pin),
                    fmt_ver(rv)
                ));
            }
            None => {
                fail = true;
                lines.push(format!(
                    "FAIL pin-vs-runtime: unparsable runtime version '{r}'"
                ));
            }
        }
    }
    (lines, fail)
}

fn dockerfile_path(repo: &Path) -> PathBuf {
    if repo.is_dir() {
        repo.join("Dockerfile")
    } else {
        repo.to_path_buf()
    }
}

fn latest_source(a: &DriftArgs, major: u64) -> Result<Ver, String> {
    let text = if let Some(l) = &a.latest {
        l.clone()
    } else if let Some(f) = &a.latest_file {
        std::fs::read_to_string(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?
    } else if a.online {
        crate::health::http_get_body(
            "https://api.github.com/repos/frappe/frappe/releases?per_page=100",
        )
        .ok_or_else(|| "GitHub releases API unreachable".to_string())?
    } else {
        return Err("give one of --latest, --latest-file or --online".into());
    };
    latest_in_series(&text, major).ok_or_else(|| format!("no stable v{major}.* release found"))
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match DriftArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let path = dockerfile_path(&a.repo);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            println!("ERROR cannot read {}: {e}", path.display());
            return 2;
        }
    };
    let Some((image, pin)) = parse_pin(&text) else {
        println!(
            "ERROR no `ARG BASE_IMAGE=<image>:v<X.Y.Z>` pin in {}",
            path.display()
        );
        return 2;
    };
    let latest = match latest_source(&a, pin.0) {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR {e}");
            return 2;
        }
    };
    let (lines, fail) = verdicts(pin, latest, a.runtime_frappe.as_deref());
    println!("{}", lines.join("\n"));
    println!("  pin {image} in {}", path.display());
    i32::from(fail)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let df = "FROM x\nARG BASE_IMAGE=frappe/erpnext:v16.53.0\n";
    let pin = parse_pin(df).map(|p| p.1);
    let rel = r#"[{"tag_name":"v16.55.2"},{"tag_name":"v16.56.0-rc1","prerelease":true},{"tag_name":"v15.99.0"}]"#;
    let latest = latest_in_series(rel, 16);
    let behind = verdicts((16, 53, 0), (16, 55, 2), Some("16.55.1"));
    let ok = verdicts((16, 55, 2), (16, 55, 2), Some("16.55.2"));
    vec![
        (
            "frappe-drift: pin parsed from Dockerfile".into(),
            pin == Some((16, 53, 0)),
        ),
        (
            "frappe-drift: prerelease and other majors ignored".into(),
            latest == Some((16, 55, 2)),
        ),
        (
            "frappe-drift: older pin FAILs behind and pin-vs-runtime".into(),
            behind.1
                && behind.0[0] == "FAIL behind: v16.53.0 -> v16.55.2"
                && behind.0[1].starts_with("FAIL pin-vs-runtime"),
        ),
        (
            "frappe-drift: current pin PASSes".into(),
            !ok.1 && ok.0[0].starts_with("PASS up-to-date"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn plain_list_and_numeric_order() {
        assert_eq!(
            latest_in_series("v16.9.0\nv16.10.1\nv15.1.1\n", 16),
            Some((16, 10, 1))
        );
        assert_eq!(parse_ver("frappe/erpnext:v16.53.0"), Some((16, 53, 0)));
        assert_eq!(parse_ver("nonsense"), None);
    }

    #[test]
    fn ahead_pin_passes_and_bad_runtime_fails() {
        assert!(!verdicts((16, 56, 0), (16, 55, 2), None).1);
        assert!(verdicts((16, 55, 2), (16, 55, 2), Some("junk")).1);
    }

    #[test]
    fn missing_pin_is_none() {
        assert!(parse_pin("FROM x\n").is_none());
    }
}
