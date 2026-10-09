//! AST-based DRY detection (Fase 2).
//!
//! Complements the line/token engine in [`crate::dry`] with a structure-aware
//! pass over Rust sources. Each statement subtree is reduced to a
//! **formatting-invariant fingerprint** via `syn`: whitespace, line breaks and
//! comments vanish, while identifiers, literals and operators are preserved
//! (Type-1 at AST level). That keeps precision high — over-normalizing away
//! identifiers is what lowers precision in the literature — while catching
//! copy-paste that spans different line counts.
//!
//! Findings are emitted as `Warning` during the rollout window
//! (ARCH-DRY-DUPLICATION stays non-impeditive); they are promoted to `Error`
//! after a fleet audit shows a false-positive rate of zero.

use std::collections::HashMap;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::engine::Violation;
use crate::rule::Severity;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A structural unit extracted from a Rust file: a statement subtree reduced to
/// a formatting-invariant fingerprint.
#[derive(Debug, Clone)]
pub struct AstUnit {
    pub hash: u64,
    pub start_line: usize,
    pub end_line: usize,
    pub tokens: usize,
}

fn fnv(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Serializes a token stream into a formatting-invariant byte buffer, returning
/// `(token_count, bytes)`. Groups keep their delimiter; identifiers/literals keep
/// their spelling; punctuation keeps its char.
fn normalize_ts(ts: TokenStream) -> (usize, Vec<u8>) {
    let mut count = 0;
    let mut out = Vec::new();
    for tt in ts {
        count += 1;
        match tt {
            TokenTree::Group(g) => {
                out.push(0x01);
                out.push(match g.delimiter() {
                    Delimiter::Brace => b'{',
                    Delimiter::Bracket => b'[',
                    Delimiter::Parenthesis => b'(',
                    Delimiter::None => b'_',
                });
                let (inner_count, inner) = normalize_ts(g.stream());
                count += inner_count;
                out.extend_from_slice(&inner);
                out.push(0x02);
            }
            TokenTree::Ident(i) => {
                out.push(0x03);
                out.extend_from_slice(i.to_string().as_bytes());
                out.push(0x00);
            }
            TokenTree::Literal(l) => {
                out.push(0x04);
                out.extend_from_slice(l.to_string().as_bytes());
                out.push(0x00);
            }
            TokenTree::Punct(p) => {
                out.push(0x05);
                out.push(p.as_char() as u8);
            }
        }
    }
    (count, out)
}

struct Collector<'a> {
    units: &'a mut Vec<AstUnit>,
    min_tokens: usize,
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let (tokens, buf) = normalize_ts(stmt.to_token_stream());
        if tokens >= self.min_tokens {
            let span = stmt.span();
            self.units.push(AstUnit {
                hash: fnv(&buf),
                start_line: span.start().line,
                end_line: span.end().line,
                tokens,
            });
        }
        syn::visit::visit_stmt(self, stmt);
    }
}

/// Extracts the structural units of a Rust source. Non-Rust or unparseable
/// sources yield an empty vector (the caller falls back to the line engine).
pub fn rust_units(source: &str, min_tokens: usize) -> Vec<AstUnit> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut units = Vec::new();
    let mut collector = Collector {
        units: &mut units,
        min_tokens,
    };
    collector.visit_file(&file);
    units
}

/// Structural units with at least this many tokens are blocking `Error`s;
/// smaller ones stay `Warning`. Adaptive severity: substantial structural
/// duplication blocks delivery, idiomatic short patterns stay visible without
/// impeding work (ARCH-DRY-DUPLICATION stays non-impeditive).
const AST_ERROR_TOKENS: usize = 40;

/// Detects identical structural units (Type-1) shared by two or more files.
pub fn detect_ast_duplication(
    files: &[(String, Vec<AstUnit>)],
    min_tokens: usize,
) -> Vec<Violation> {
    let mut by_hash: HashMap<u64, Vec<(&str, &AstUnit)>> = HashMap::new();
    for (path, units) in files {
        for u in units {
            if u.tokens >= min_tokens {
                by_hash.entry(u.hash).or_default().push((path.as_str(), u));
            }
        }
    }

    let mut violations = Vec::new();
    for (_hash, occ) in by_hash {
        if occ.len() < 2 {
            continue;
        }
        let (p1, u1) = occ[0];
        // Report a single finding per hash, against the first *different* file.
        let Some((p2, u2)) = occ.iter().find(|(p, _)| *p != p1) else {
            continue;
        };
        violations.push(Violation {
            rule_id: "ARCH-DRY-DUPLICATION".to_string(),
            rule_name: "Code Duplication (DRY Principle)".to_string(),
            severity: if u1.tokens >= AST_ERROR_TOKENS {
                Severity::Error
            } else {
                Severity::Warning
            },
            file_path: p1.to_string(),
            line_number: u1.start_line,
            snippet: format!("L{}-L{} ({} tokens)", u1.start_line, u1.end_line, u1.tokens),
            message: format!(
                "AST structural duplication of {} tokens with '{}' (L{}-L{}).",
                u1.tokens, p2, u2.start_line, u2.end_line
            ),
            suggestion: Some(
                "Extract the duplicated statement/logic into a shared function or method."
                    .to_string(),
            ),
        });
    }
    violations
}
