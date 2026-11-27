//! `--self-test`: the two guarantees the ledger rests on are checked on a throwaway database,
//! then each is removed on purpose to prove that its check turns red.

use std::path::{Path, PathBuf};

use super::config::Config;
use super::ledger::{self, ClaimRequest, Handback, Join};
use super::store::{Faults, Store};
use super::{HubResult, audit, quota};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(label: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!(
        "stenio-hub-selftest-{}-{label}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    Scratch(dir)
}

fn joined(store: &mut Store, cfg: &Config, harness: &str) -> HubResult<String> {
    let request = Join {
        harness: harness.to_string(),
        ..Join::default()
    };
    let out = ledger::join(store, cfg, &request)?;
    let account = harness.to_string();
    let window = quota::Window {
        window: "five_hour".to_string(),
        used_pct: 1.0,
        resets_at: None,
    };
    quota::put(store, &account, "self-test", &[window])?;
    Ok(out["worker"].as_str().unwrap_or_default().to_string())
}

fn claim_row(
    store: &mut Store,
    cfg: &Config,
    worker: &str,
    ttl_secs: u64,
) -> HubResult<serde_json::Value> {
    ledger::claim(
        store,
        cfg,
        &ClaimRequest {
            worker: worker.to_string(),
            resources: vec!["row:GB-001".to_string()],
            ttl_secs: Some(ttl_secs),
            run: None,
            path: None,
        },
    )
}

/// Connections claiming one row at once.
const CONTENDERS: usize = 8;

/// Of many simultaneous claims of one row exactly one wins and every other is told who holds it.
fn exclusive(dir: &Path, faults: Faults) -> HubResult<bool> {
    let cfg = Config::embedded()?;
    let path = dir.join("hub.db");
    // The schema, with or without its constraint, exists before the contenders open it.
    let mut store = Store::open_with(&path, faults)?;
    let workers = (0..CONTENDERS)
        .map(|n| joined(&mut store, &cfg, &format!("contender{n}")))
        .collect::<HubResult<Vec<_>>>()?;
    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let running: Vec<_> = workers
            .iter()
            .map(|worker| {
                let (path, cfg) = (&path, &cfg);
                scope.spawn(move || claim_row(&mut Store::open(path)?, cfg, worker, 600))
            })
            .collect();
        running.into_iter().map(|t| t.join()).collect()
    });
    let won = outcomes.iter().filter(|o| matches!(o, Ok(Ok(_)))).count();
    let held = outcomes
        .iter()
        .filter(|o| matches!(o, Ok(Err(e)) if e.code() == "held"))
        .count();
    Ok(won == 1 && held == CONTENDERS - 1)
}

/// After a takeover the old fence cannot hand the row back.
fn fenced(dir: &Path, faults: Faults) -> HubResult<bool> {
    let cfg = Config::embedded()?;
    let mut store = Store::open_with(&dir.join("hub.db"), faults)?;
    let (a, b) = (
        joined(&mut store, &cfg, "first")?,
        joined(&mut store, &cfg, "second")?,
    );
    let old = claim_row(&mut store, &cfg, &a, 1)?["fence"]
        .as_i64()
        .unwrap_or_default();
    std::thread::park_timeout(std::time::Duration::from_millis(1100));
    while ledger::sweep_now(&mut store)? == 0 {
        std::thread::park_timeout(std::time::Duration::from_millis(100));
    }
    let new = claim_row(&mut store, &cfg, &b, 60)?["fence"]
        .as_i64()
        .unwrap_or_default();
    let stale = ledger::handback(
        &mut store,
        &Handback {
            worker: a,
            row: "GB-001".to_string(),
            fence: old,
            verdict: "done".to_string(),
            proof: Some("self-test".to_string()),
            ..Handback::default()
        },
    );
    Ok(new > old && matches!(stale, Err(e) if e.code() == "stale_fence"))
}

/// After the allowed attempts expire, the row is refused until the owner resets it.
fn budget(dir: &Path, faults: Faults) -> HubResult<bool> {
    let cfg = Config::embedded()?;
    let mut store = Store::open_with(&dir.join("hub.db"), faults)?;
    let worker = joined(&mut store, &cfg, "first")?;
    for _ in 0..cfg.attempts.limit {
        claim_row(&mut store, &cfg, &worker, 1)?;
        std::thread::park_timeout(std::time::Duration::from_millis(1100));
        while ledger::sweep_now(&mut store)? == 0 {
            std::thread::park_timeout(std::time::Duration::from_millis(100));
        }
    }
    let over = claim_row(&mut store, &cfg, &worker, 60);
    if !matches!(over, Err(e) if e.code() == "attempts") {
        return Ok(false);
    }
    ledger::reset_attempts(&mut store, "GB-001", "self-test", true)?;
    Ok(claim_row(&mut store, &cfg, &worker, 60).is_ok())
}

/// An edited event is reported with its sequence number.
fn tamper_evident(dir: &Path) -> HubResult<bool> {
    let cfg = Config::embedded()?;
    let mut store = Store::open(&dir.join("hub.db"))?;
    joined(&mut store, &cfg, "first")?;
    let clean = audit::audit(&mut store, None, false)?["ok"] == true;
    store.write(|tx| {
        tx.execute("UPDATE events SET payload = '{}' WHERE seq = 1", [])?;
        Ok(())
    })?;
    let after = audit::audit(&mut store, None, false)?;
    Ok(clean && after["ok"] == false && after["first_bad_seq"] == 1)
}

fn case(label: &str, run: impl FnOnce(&Path) -> HubResult<bool>) -> bool {
    let dir = scratch(label);
    run(&dir.0).unwrap_or(false)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let no_unique = Faults {
        drop_unique_claim: true,
        ..Faults::default()
    };
    let no_fence = Faults {
        skip_fence_check: true,
        ..Faults::default()
    };
    let no_budget = Faults {
        skip_attempt_budget: true,
        ..Faults::default()
    };
    // A mutation case passes only when the guarantee visibly breaks without its mechanism.
    let broken = |label: &str, run: &dyn Fn(&Path) -> HubResult<bool>| {
        let dir = scratch(label);
        matches!(run(&dir.0), Ok(false))
    };
    vec![
        (
            "hub: a held row refuses a second claim".to_string(),
            case("held", |d| exclusive(d, Faults::default())),
        ),
        (
            "hub: mutation, no unique claim index is red".to_string(),
            broken("no-unique", &|d| exclusive(d, no_unique)),
        ),
        (
            "hub: a stale fence cannot hand back".to_string(),
            case("fence", |d| fenced(d, Faults::default())),
        ),
        (
            "hub: mutation, no fence check is red".to_string(),
            broken("no-fence", &|d| fenced(d, no_fence)),
        ),
        (
            "hub: a row over its attempt budget is refused".to_string(),
            case("budget", |d| budget(d, Faults::default())),
        ),
        (
            "hub: mutation, no attempt budget is red".to_string(),
            broken("no-budget", &|d| budget(d, no_budget)),
        ),
        (
            "hub: an edited event fails the audit".to_string(),
            case("chain", tamper_evident),
        ),
    ]
}
