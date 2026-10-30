use colored::*;
use ignore::WalkBuilder;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub path: String,
    pub title: String,
    pub score: f32,
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct IndexedDoc {
    pub path: String,
    pub title: String,
    pub term_frequencies: HashMap<String, f32>,
    pub norm: f32,
    pub raw_content: String,
}

#[derive(Debug, Clone, Default)]
pub struct SemanticIndex {
    pub documents: Vec<IndexedDoc>,
    pub idf: HashMap<String, f32>,
    #[allow(dead_code)]
    pub total_docs: usize,
}

impl SemanticIndex {
    /// Builds an in-memory TF-IDF semantic search index over all markdown documents in the vault.
    pub fn build(vault_root: &Path) -> Self {
        let walker = WalkBuilder::new(vault_root)
            .standard_filters(true)
            .hidden(false)
            .build();

        let mut raw_docs = Vec::new();
        let mut doc_frequencies: HashMap<String, usize> = HashMap::new();

        for result in walker {
            let Ok(entry) = result else { continue };
            let path = entry.path();
            let path_str = path.to_string_lossy().to_string();

            if path_str.contains("/.stversions/")
                || path_str.contains("/.smart-env/")
                || path_str.contains("/target/")
                || path_str.contains("/node_modules/")
                || path_str.contains("/.obsidian/")
                || path_str.contains("/.git/")
            {
                continue;
            }

            if path.extension().and_then(|s| s.to_str()) != Some("md") {
                continue;
            }

            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            let rel_path = path
                .strip_prefix(vault_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let title = content
                .lines()
                .find(|l| l.starts_with("# "))
                .map(|l| l.trim_start_matches("# ").trim().to_string())
                .unwrap_or_else(|| {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("Untitled")
                        .to_string()
                });

            let tokens = tokenize(&content);
            if tokens.is_empty() {
                continue;
            }

            let mut tf = HashMap::new();
            let total_tokens = tokens.len() as f32;
            for token in &tokens {
                *tf.entry(token.clone()).or_insert(0.0) += 1.0;
            }

            let mut seen_terms = HashSet::new();
            for (term, count) in tf.iter_mut() {
                *count /= total_tokens;
                if seen_terms.insert(term.clone()) {
                    *doc_frequencies.entry(term.clone()).or_insert(0) += 1;
                }
            }

            raw_docs.push((rel_path, title, tf, content));
        }

        let total_docs = raw_docs.len();
        let mut idf = HashMap::new();

        for (term, doc_count) in doc_frequencies {
            // Smoothed IDF: ln(1 + (N - n + 0.5) / (n + 0.5))
            let idf_val = ((total_docs as f32 - doc_count as f32 + 0.5) / (doc_count as f32 + 0.5)
                + 1.0)
                .ln();
            idf.insert(term, idf_val.max(0.1));
        }

        let mut documents = Vec::new();
        for (rel_path, title, tf, raw_content) in raw_docs {
            let mut norm_sq = 0.0;
            for (term, &tf_val) in &tf {
                let idf_val = idf.get(term).copied().unwrap_or(0.1);
                let weight = tf_val * idf_val;
                norm_sq += weight * weight;
            }

            let norm = norm_sq.sqrt();
            documents.push(IndexedDoc {
                path: rel_path,
                title,
                term_frequencies: tf,
                norm: if norm > 0.0 { norm } else { 1.0 },
                raw_content,
            });
        }

        SemanticIndex {
            documents,
            idf,
            total_docs,
        }
    }

    /// Queries the index using cosine similarity against the TF-IDF query vector.
    pub fn search(&self, query: &str, top_k: usize) -> Vec<SearchResult> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() || self.documents.is_empty() {
            return Vec::new();
        }

        let mut query_tf = HashMap::new();
        let total_q_tokens = query_tokens.len() as f32;
        for token in &query_tokens {
            *query_tf.entry(token.clone()).or_insert(0.0) += 1.0;
        }

        let mut query_weights = HashMap::new();
        let mut q_norm_sq = 0.0;
        for (term, count) in query_tf {
            let idf_val = self.idf.get(&term).copied().unwrap_or(0.5);
            let weight = (count / total_q_tokens) * idf_val;
            q_norm_sq += weight * weight;
            query_weights.insert(term, weight);
        }

        let q_norm = q_norm_sq.sqrt();
        if q_norm == 0.0 {
            return Vec::new();
        }

        let mut scored_results = Vec::new();

        for doc in &self.documents {
            let mut dot_product = 0.0;
            for (q_term, &q_weight) in &query_weights {
                if let Some(&doc_tf) = doc.term_frequencies.get(q_term) {
                    let doc_idf = self.idf.get(q_term).copied().unwrap_or(0.1);
                    let doc_weight = doc_tf * doc_idf;
                    dot_product += q_weight * doc_weight;
                }
            }

            let similarity = dot_product / (q_norm * doc.norm);
            if similarity > 0.001 {
                let snippet = extract_snippet(&doc.raw_content, &query_tokens);
                scored_results.push(SearchResult {
                    path: doc.path.clone(),
                    title: doc.title.clone(),
                    score: similarity,
                    snippet,
                });
            }
        }

        scored_results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored_results.truncate(top_k);
        scored_results
    }
}

/// Tokenizes text into lowercase alphanumeric words, filtering out common noise.
fn tokenize(text: &str) -> Vec<String> {
    let stop_words: HashSet<&'static str> = [
        "a", "o", "os", "as", "um", "uma", "uns", "umas", "de", "do", "da", "dos", "das", "em",
        "no", "na", "nos", "nas", "por", "para", "com", "sem", "e", "ou", "se", "que", "the", "of",
        "and", "to", "in", "for", "with", "on", "at", "by", "from", "is", "it",
    ]
    .into_iter()
    .collect();

    text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.len() >= 2 && !stop_words.contains(s.as_str()))
        .collect()
}

/// Extracts a representative 2-line snippet around the best matching query terms.
fn extract_snippet(content: &str, query_tokens: &[String]) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut best_line_idx = 0;
    let mut max_matches = 0;

    for (idx, line) in lines.iter().enumerate() {
        let line_lower = line.to_lowercase();
        let matches = query_tokens
            .iter()
            .filter(|&t| line_lower.contains(t))
            .count();
        if matches > max_matches && !line.trim().starts_with("---") {
            max_matches = matches;
            best_line_idx = idx;
        }
    }

    let start = best_line_idx.saturating_sub(1);
    let end = (best_line_idx + 2).min(lines.len());
    let snippet_lines: Vec<&str> = lines[start..end]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    snippet_lines.join(" ... ")
}

/// Formats and displays semantic search results in the terminal.
pub fn print_semantic_results(query: &str, results: &[SearchResult], elapsed_ms: f64) {
    println!(
        "\n{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!(
        "{} [{:.2}ms]",
        "StenioSentinel Local Semantic Search Engine (TF-IDF Vectorizer)"
            .bold()
            .cyan(),
        elapsed_ms
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!("   🔍 Query   : \"{}\"", query.bold().yellow());
    println!(
        "   📄 Matches : {}\n",
        results.len().to_string().bold().green()
    );

    if results.is_empty() {
        println!("   ⚠️  No relevant documents found for this query in the local vault.");
        return;
    }

    for (i, res) in results.iter().enumerate() {
        let score_pct = (res.score * 100.0).min(100.0);
        println!(
            "   {:2}. {} [{:.1}% match]",
            i + 1,
            res.title.bold().cyan(),
            score_pct.to_string().green().bold()
        );
        println!("       📁 {}", res.path.dimmed());
        if !res.snippet.is_empty() {
            println!("       💬 \"{}\"", res.snippet.italic());
        }
        println!();
    }
}

/// Runs a CLI semantic search query over the vault root.
pub fn run_semantic_search(vault_root: &Path, query: &str, top_k: usize) {
    let start = Instant::now();
    let index = SemanticIndex::build(vault_root);
    let results = index.search(query, top_k);
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    print_semantic_results(query, &results, elapsed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenizer_and_search() {
        let tokens = tokenize("Como funciona a governança de squads e guildas?");
        assert!(tokens.contains(&"funciona".to_string()));
        assert!(tokens.contains(&"governança".to_string()));
        assert!(tokens.contains(&"squads".to_string()));
        assert!(tokens.contains(&"guildas".to_string()));
        assert!(!tokens.contains(&"a".to_string()));
        assert!(!tokens.contains(&"de".to_string()));

        let index = SemanticIndex::default();
        assert_eq!(index.total_docs, 0);
    }
}
