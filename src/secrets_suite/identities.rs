//! `stenio secret-identities` (GB-227): one value under two key names means a provider is being fed
//! another provider's credential, and a configured provider whose credential is not in the store is
//! not provisioned. Values are compared in memory; the report carries names and sources only.

use super::store::{labelled, load};
use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MIN_LEN: usize = 12;

#[derive(Parser, Debug)]
#[command(about = "Find one secret value under several names (names and sources only)")]
struct Args {
    #[arg(long, value_name = "LABEL=PATH", help = "Env file")]
    env: Vec<String>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Provider auth JSON ({provider: {key}})"
    )]
    auth_json: Vec<PathBuf>,
    #[arg(long, help = "The central store; providers must be provisioned there")]
    store: Option<PathBuf>,
    #[arg(long, help = "Decrypt sops files in memory")]
    decrypt: bool,
    #[arg(
        long,
        value_name = "NAME=NAME",
        help = "Declared alias: these two names may carry one value"
    )]
    same: Vec<String>,
}

fn env_name_of_provider(provider: &str) -> String {
    format!(
        "{}_API_KEY",
        provider.to_ascii_uppercase().replace(['-', '.', ' '], "_")
    )
}

/// `(provider, credential)` pairs of an auth file.
fn auth_keys(path: &Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e.kind()))?;
    // The parse error is dropped on purpose: it may quote the file.
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| format!("{} is not valid JSON", path.display()))?;
    let Some(map) = json.as_object() else {
        return Ok(Vec::new());
    };
    Ok(map
        .iter()
        .filter_map(|(provider, v)| {
            let key = ["key", "api_key", "apiKey", "token"]
                .iter()
                .find_map(|f| v.get(f)?.as_str())?;
            Some((provider.clone(), key.to_string()))
        })
        .collect())
}

fn credential_value(v: &str) -> bool {
    v.len() >= MIN_LEN
        && !v.starts_with(['/', '$', '<', '['])
        && !v.starts_with("http")
        && !v.starts_with("ENC[")
}

fn check(args: &Args) -> Result<Vec<String>, String> {
    // value -> identity name -> sources
    let mut values: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    let mut add = |value: &str, name: &str, source: &str| {
        if credential_value(value) {
            values
                .entry(value.to_string())
                .or_default()
                .entry(name.to_string())
                .or_default()
                .insert(source.to_string());
        }
    };
    let mut envs = Vec::new();
    for spec in &args.env {
        envs.push(labelled(spec)?);
    }
    if let Some(s) = &args.store {
        envs.push(("store".to_string(), s.clone()));
    }
    let mut store_names = BTreeSet::new();
    let mut store_values = BTreeSet::new();
    for (label, path) in &envs {
        let loaded = load(path, args.decrypt)?;
        for (k, v) in &loaded.entries {
            if label == "store" {
                store_names.insert(k.clone());
                store_values.insert(v.clone());
            }
            if crate::infra::key_looks_secret(k) {
                add(v, k, label);
            }
        }
    }
    let mut fails = Vec::new();
    for path in &args.auth_json {
        for (provider, key) in auth_keys(path)? {
            let name = env_name_of_provider(&provider);
            add(&key, &name, &format!("provider {provider}"));
            if args.store.is_some() && !store_names.contains(&name) && !store_values.contains(&key)
            {
                fails.push(format!(
                    "FAIL (b) provider {provider}: credential not in the store (neither {name} nor the same value)"
                ));
            }
        }
    }
    let declared = |a: &str, b: &str| {
        args.same.iter().any(|s| {
            s.split_once('=')
                .is_some_and(|(x, y)| (x == a && y == b) || (x == b && y == a))
        })
    };
    for names in values.values() {
        let all: Vec<&String> = names.keys().collect();
        let Some(first) = all.first() else {
            continue;
        };
        if all.iter().skip(1).any(|n| !declared(first, n)) {
            let list: Vec<String> = names
                .iter()
                .map(|(n, s)| format!("{n} ({})", s.iter().cloned().collect::<Vec<_>>().join(", ")))
                .collect();
            fails.push(format!(
                "FAIL (a) one value under {} names: {}",
                all.len(),
                list.join("; ")
            ));
        }
    }
    fails.sort();
    Ok(fails)
}

pub fn run_cli(argv: &[String]) -> i32 {
    let args = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    if args.env.is_empty() && args.auth_json.is_empty() && args.store.is_none() {
        eprintln!("stenio: secret-identities needs --env, --auth-json or --store");
        return 2;
    }
    match check(&args) {
        Ok(fails) => {
            for l in &fails {
                println!("{l}");
            }
            let verdict = if fails.is_empty() { "PASS" } else { "FAIL" };
            println!("stenio: {verdict} secret-identities fails={}", fails.len());
            i32::from(!fails.is_empty())
        }
        Err(e) => {
            eprintln!("stenio: secret-identities {e}");
            2
        }
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let v = super::dumps::FAKE_VALUE;
    let aliased = format!("OPENCODE_GO_API_KEY={v}\nOPENAI_API_KEY={v}\n");
    let clean = format!("OPENCODE_GO_API_KEY={v}\n");
    let auth =
        format!("{{\"opencode-go\":{{\"key\":\"{v}\"}},\"openrouter\":{{\"key\":\"other{v}\"}}}}");
    let d = super::fixture(
        "ident",
        &[
            ("alias.env", &aliased),
            ("clean.env", &clean),
            ("auth.json", &auth),
        ],
    );
    let p = |n: &str| d.join(n).display().to_string();
    let run = |argv: Vec<String>| {
        let mut full = vec!["i".to_string()];
        full.extend(argv);
        Args::try_parse_from(full)
            .ok()
            .and_then(|a| check(&a).ok())
            .map(|f| f.join("\n"))
    };
    let env = |n: &str| vec!["--env".to_string(), format!("hermes={}", p(n))];
    let red = run(env("alias.env"));
    let green = run(env("clean.env"));
    let mut declared = env("alias.env");
    declared.extend(["--same".into(), "OPENAI_API_KEY=OPENCODE_GO_API_KEY".into()]);
    let declared = run(declared);
    let provider = run(vec![
        "--auth-json".into(),
        p("auth.json"),
        "--store".into(),
        p("clean.env"),
    ]);
    let _ = std::fs::remove_dir_all(&d);
    vec![
        (
            "secret identities: mutation, alias names both variables, no value".to_string(),
            red.as_deref().is_some_and(|r| {
                r.contains("OPENAI_API_KEY") && r.contains("OPENCODE_GO_API_KEY") && !r.contains(v)
            }),
        ),
        (
            "secret identities: alias removed is green".to_string(),
            green.as_deref() == Some(""),
        ),
        (
            "secret identities: declared alias accepted".to_string(),
            declared.as_deref() == Some(""),
        ),
        (
            "secret identities: unprovisioned provider named, provisioned one not".to_string(),
            provider.as_deref().is_some_and(|r| {
                r.contains("provider openrouter") && !r.contains("provider opencode-go:")
            }),
        ),
    ]
}
