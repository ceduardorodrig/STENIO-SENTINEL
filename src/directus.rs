use colored::*;
use serde_json::Value;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct DirectusViolation {
    pub rule: &'static str,
    pub message: String,
    pub location: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Default)]
pub struct DirectusAuditReport {
    pub violations: Vec<DirectusViolation>,
    pub checks_passed: usize,
    pub execution_time_ms: f64,
}

/// Audits Directus schemas, relational integrity, currencies, and governance data.
/// Deterministic and testable offline with pure JSON payloads.
pub fn audit_directus_from_json(
    fields_json: &Value,
    _relations_json: Option<&Value>,
    links_json: Option<&Value>,
    decisions_json: Option<&Value>,
    onb_json: Option<&Value>,
    hnd_json: Option<&Value>,
) -> DirectusAuditReport {
    let start = Instant::now();
    let mut violations = Vec::new();
    let mut checks_passed = 0;

    let fields_list = fields_json
        .get("data")
        .and_then(|d| d.as_array())
        .or_else(|| fields_json.as_array());

    if let Some(fields) = fields_list {
        // 1. Critical M2O / M2M Relational Template Check
        let critical_m2o = [
            ("tasks", "assignee", "members"),
            ("tasks", "squad", "squads"),
            ("tasks", "guild", "guilds"),
            ("decisions", "decided_by_member", "members"),
            ("decisions", "cabal", "cabals"),
            ("decisions", "squad", "squads"),
            ("decisions", "guild", "guilds"),
            ("squads", "leader", "members"),
        ];

        for (col, fld, _target_col) in &critical_m2o {
            let field_entry = fields.iter().find(|item| {
                let c = item
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let f = item.get("field").and_then(|v| v.as_str()).unwrap_or("");
                c == *col && f == *fld
            });

            match field_entry {
                None => {
                    violations.push(DirectusViolation {
                        rule: "DIRECTUS-REL-MISSING-FIELD",
                        message: format!(
                            "Relational field {}.{} does not exist in schema",
                            col, fld
                        ),
                        location: format!("{}.{}", col, fld),
                        severity: Severity::Error,
                    });
                }
                Some(entry) => {
                    let meta = entry.get("meta");
                    let interface = meta
                        .and_then(|m| m.get("interface"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let display = meta
                        .and_then(|m| m.get("display"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if interface != "select-dropdown-m2o" || display != "related-values" {
                        violations.push(DirectusViolation {
                            rule: "DIRECTUS-REL-RAW-ID",
                            message: format!(
                                "Field {}.{} must use interface 'select-dropdown-m2o' with display 'related-values' (found interface='{}', display='{}')",
                                col, fld, interface, display
                            ),
                            location: format!("{}.{}", col, fld),
                            severity: Severity::Error,
                        });
                    } else {
                        checks_passed += 1;
                    }
                }
            }
        }

        // 2. BRL Currency Check
        let currency_fields = [
            ("invoices", "value"),
            ("deals", "value"),
            ("profit_share", "total_profit"),
            ("projects", "budget"),
            ("proposals", "value"),
        ];

        for (col, fld) in &currency_fields {
            let field_entry = fields.iter().find(|item| {
                let c = item
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let f = item.get("field").and_then(|v| v.as_str()).unwrap_or("");
                c == *col && f == *fld
            });

            if let Some(entry) = field_entry {
                let meta = entry.get("meta");
                let display = meta
                    .and_then(|m| m.get("display"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let prefix = meta
                    .and_then(|m| m.get("display_options"))
                    .and_then(|o| o.get("prefix"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if display != "formatted-value" || prefix != "R$ " {
                    violations.push(DirectusViolation {
                        rule: "DIRECTUS-BRL-CURRENCY",
                        message: format!(
                            "Monetary field {}.{} is missing BRL formatting (expected display='formatted-value', prefix='R$ ', found display='{}', prefix='{}')",
                            col, fld, display, prefix
                        ),
                        location: format!("{}.{}", col, fld),
                        severity: Severity::Error,
                    });
                } else {
                    checks_passed += 1;
                }
            }
        }
    }

    // 3. Zero Placeholder Links Check
    if let Some(links_data) = links_json {
        let items = links_data
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| links_data.as_array());

        if let Some(links) = items {
            for item in links {
                let url = item.get("url").and_then(|u| u.as_str()).unwrap_or("");
                let title = item
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unnamed");

                if url.contains("localhost")
                    || url.contains("file:///")
                    || url.contains("example.com")
                    || url.contains("dummy")
                {
                    violations.push(DirectusViolation {
                        rule: "DIRECTUS-PLACEHOLDER-LINKS",
                        message: format!(
                            "Link '{}' points to placeholder or local URL: '{}'",
                            title, url
                        ),
                        location: format!("links/{}", title),
                        severity: Severity::Error,
                    });
                } else {
                    checks_passed += 1;
                }
            }
        }
    }

    // 4. Singleton Tab Title Duplication Guard (Anti-Stutter)
    if let Some(onb) = onb_json {
        let title = onb
            .get("data")
            .and_then(|d| d.get("welcome_title"))
            .and_then(|v| v.as_str())
            .or_else(|| onb.get("welcome_title").and_then(|v| v.as_str()))
            .unwrap_or("");

        if title.contains("Guia de Bordo") || title.contains("Onboarding") {
            violations.push(DirectusViolation {
                rule: "DIRECTUS-TAB-STUTTER",
                message: format!(
                    "onboarding.welcome_title repeats the collection name: '{}'",
                    title
                ),
                location: "items/onboarding".to_string(),
                severity: Severity::Warning,
            });
        } else if !title.is_empty() {
            checks_passed += 1;
        }
    }

    if let Some(hnd) = hnd_json {
        let title = hnd
            .get("data")
            .and_then(|d| d.get("title"))
            .and_then(|v| v.as_str())
            .or_else(|| hnd.get("title").and_then(|v| v.as_str()))
            .unwrap_or("");

        if title.contains("Manual") {
            violations.push(DirectusViolation {
                rule: "DIRECTUS-TAB-STUTTER",
                message: format!("handbook.title repeats the collection name: '{}'", title),
                location: "items/handbook".to_string(),
                severity: Severity::Warning,
            });
        } else if !title.is_empty() {
            checks_passed += 1;
        }
    }

    // 5. Outdated Host Mentions in Decisions/ADRs
    if let Some(decisions_data) = decisions_json {
        let items = decisions_data
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| decisions_data.as_array());

        if let Some(adrs) = items {
            for adr in adrs {
                let title = adr.get("title").and_then(|t| t.as_str()).unwrap_or("ADR");
                let context = adr.get("context").and_then(|c| c.as_str()).unwrap_or("");
                let decision = adr.get("decision").and_then(|d| d.as_str()).unwrap_or("");
                let full_text = format!("{} {}", context, decision);

                if full_text.contains("Hostinger") {
                    violations.push(DirectusViolation {
                        rule: "DIRECTUS-OUTDATED-HOST",
                        message: format!("ADR '{}' references legacy host 'Hostinger'", title),
                        location: format!("decisions/{}", title),
                        severity: Severity::Warning,
                    });
                } else {
                    checks_passed += 1;
                }
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    DirectusAuditReport {
        violations,
        checks_passed,
        execution_time_ms: elapsed,
    }
}

/// Connects live to Directus via HTTP REST API and runs the governance auditor.
pub fn audit_directus_live(
    base_url: &str,
    token: Option<&str>,
) -> Result<DirectusAuditReport, String> {
    let clean_url = base_url.trim_end_matches('/');
    let client = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(4))
        .build();

    let auth_header = match token {
        Some(t) if !t.is_empty() => format!("Bearer {}", t),
        _ => match std::env::var("DIRECTUS_TOKEN") {
            Ok(t) if !t.is_empty() => format!("Bearer {}", t),
            _ => String::new(),
        },
    };

    let fetch_json = |endpoint: &str| -> Result<Value, String> {
        let url = format!("{}{}", clean_url, endpoint);
        let mut req = client.get(&url);
        if !auth_header.is_empty() {
            req = req.set("Authorization", &auth_header);
        }

        match req.call() {
            Ok(resp) => {
                let json: Value = resp
                    .into_json()
                    .map_err(|e| format!("Failed to parse JSON from {}: {}", url, e))?;
                Ok(json)
            }
            Err(e) => Err(format!("Directus API request to {} failed: {}", url, e)),
        }
    };

    let fields = fetch_json("/fields")?;
    let relations = fetch_json("/relations").ok();
    let links = fetch_json("/items/links").ok();
    let decisions = fetch_json("/items/decisions").ok();
    let onb = fetch_json("/items/onboarding").ok();
    let hnd = fetch_json("/items/handbook").ok();

    Ok(audit_directus_from_json(
        &fields,
        relations.as_ref(),
        links.as_ref(),
        decisions.as_ref(),
        onb.as_ref(),
        hnd.as_ref(),
    ))
}

/// Formats and displays the Directus Sentinel audit report.
pub fn print_directus_report(report: &DirectusAuditReport) {
    println!(
        "\n{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!(
        "{} [{:.2}ms]",
        "StenioSentinel Directus Governance Engine — Relational & Schema Integrity"
            .bold()
            .cyan(),
        report.execution_time_ms
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );

    let errors_count = report
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .count();
    let warnings_count = report
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Warning)
        .count();

    println!(
        "   🛡️  Checks Passed     : {}",
        report.checks_passed.to_string().green().bold()
    );
    println!(
        "   ❌ Errors (Blocking) : {}",
        errors_count.to_string().red().bold()
    );
    println!(
        "   ⚠️  Warnings          : {}",
        warnings_count.to_string().yellow().bold()
    );

    if !report.violations.is_empty() {
        println!(
            "\n{}",
            "── Detailed Directus Violations ──────────────────────────────────────────────".bold()
        );
        for v in &report.violations {
            match v.severity {
                Severity::Error => {
                    println!(
                        "   {} [{}] in {}:",
                        "❌ ERROR".red().bold(),
                        v.rule.bold(),
                        v.location.cyan()
                    );
                    println!("      {}", v.message);
                }
                Severity::Warning => {
                    println!(
                        "   {}  [{}] in {}:",
                        "⚠️  WARN".yellow().bold(),
                        v.rule.bold(),
                        v.location.cyan()
                    );
                    println!("      {}", v.message);
                }
            }
        }
    } else {
        println!(
            "\n   ✨ {}",
            "All Directus relational, currency, and schema governance checks passed!"
                .green()
                .bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_directus_brl_currency_auditor() {
        // Field with correct BRL formatting
        let valid_fields = json!({
            "data": [
                {
                    "collection": "invoices",
                    "field": "value",
                    "meta": {
                        "display": "formatted-value",
                        "display_options": { "prefix": "R$ " }
                    }
                }
            ]
        });

        let report = audit_directus_from_json(&valid_fields, None, None, None, None, None);
        assert_eq!(report.violations.len(), 8); // other 8 critical m2o are missing
        assert!(
            !report
                .violations
                .iter()
                .any(|v| v.rule == "DIRECTUS-BRL-CURRENCY")
        );

        // Field with missing BRL prefix
        let invalid_fields = json!({
            "data": [
                {
                    "collection": "invoices",
                    "field": "value",
                    "meta": {
                        "display": "formatted-value",
                        "display_options": { "prefix": "$ " }
                    }
                }
            ]
        });

        let report_invalid =
            audit_directus_from_json(&invalid_fields, None, None, None, None, None);
        assert!(report_invalid.iter_currency_violations());
    }

    trait TestHelper {
        fn iter_currency_violations(&self) -> bool;
    }

    impl TestHelper for DirectusAuditReport {
        fn iter_currency_violations(&self) -> bool {
            self.violations
                .iter()
                .any(|v| v.rule == "DIRECTUS-BRL-CURRENCY")
        }
    }
}
