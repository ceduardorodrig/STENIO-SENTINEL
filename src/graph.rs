use colored::*;
use ignore::WalkBuilder;
use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VaultGraph {
    pub graph: DiGraph<String, ()>,
    pub node_indices: HashMap<String, NodeIndex>,
    #[allow(dead_code)]
    pub file_paths: HashMap<String, PathBuf>,
}

impl VaultGraph {
    #[allow(dead_code)]
    pub fn get_path(&self, rel_path: &str) -> Option<&PathBuf> {
        self.file_paths.get(rel_path)
    }
}

#[derive(Debug, Clone)]
pub struct GraphAnalysis {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub density: f64,
    pub orphan_nodes: Vec<String>,
    pub hub_nodes: Vec<(String, usize, usize)>, // (name, in_degree, out_degree)
    pub broken_links: Vec<(String, String)>,    // (from, to)
    pub clusters_count: usize,
}

/// Builds the knowledge graph for all Markdown documents in the vault.
pub fn build_vault_graph(vault_root: &Path) -> (VaultGraph, GraphAnalysis) {
    let mut graph = DiGraph::<String, ()>::new();
    let mut node_indices = HashMap::new();
    let mut file_paths = HashMap::new();
    let mut files_by_name = HashMap::new();

    // Regexes for wikilinks [[target]] and markdown links [text](path.md)
    let re_wikilink = Regex::new(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]").ok();
    let re_mdlink = Regex::new(r"\[[^\]]*\]\(([^)#]+)(?:#[^)]+)?\)").ok();

    // 1. First pass: Collect all valid markdown files as nodes
    let walker = WalkBuilder::new(vault_root)
        .standard_filters(true)
        .hidden(false)
        .build();

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

        let rel_path = path.strip_prefix(vault_root).unwrap_or(path);
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let idx = graph.add_node(rel_str.clone());
        node_indices.insert(rel_str.clone(), idx);
        file_paths.insert(rel_str.clone(), path.to_path_buf());
        files_by_name
            .entry(file_stem.to_lowercase())
            .or_insert_with(Vec::new)
            .push((rel_str, idx));
    }

    // 2. Second pass: Extract links and connect edges
    let mut broken_links = Vec::new();
    let mut edges_added = HashSet::new();

    for (rel_path, &source_idx) in &node_indices {
        let Some(full_path) = file_paths.get(rel_path) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(full_path) else {
            continue;
        };

        // Parse wikilinks
        if let Some(ref re) = re_wikilink {
            for cap in re.captures_iter(&content) {
                let Some(target) = cap.get(1) else { continue };
                let target_raw = target.as_str().trim();
                if target_raw.is_empty() {
                    continue;
                }

                let target_name = target_raw.replace('\\', "/");
                let target_stem = Path::new(&target_name)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&target_name)
                    .to_lowercase();

                if let Some(matches) = files_by_name.get(&target_stem) {
                    if let Some((_, target_idx)) = matches.first() {
                        let edge_key = (source_idx.index(), target_idx.index());
                        if !edges_added.contains(&edge_key) && source_idx != *target_idx {
                            edges_added.insert(edge_key);
                            graph.add_edge(source_idx, *target_idx, ());
                        }
                    }
                } else {
                    broken_links.push((rel_path.clone(), target_raw.to_string()));
                }
            }
        }

        // Parse standard markdown links (relative .md)
        if let Some(ref re) = re_mdlink {
            for cap in re.captures_iter(&content) {
                let Some(target) = cap.get(1) else { continue };
                let target_raw = target.as_str().trim();

                if target_raw.starts_with("http://")
                    || target_raw.starts_with("https://")
                    || target_raw.starts_with("mailto:")
                    || target_raw.starts_with("file://")
                    || target_raw.is_empty()
                {
                    continue;
                }

                if !target_raw.ends_with(".md") && !target_raw.contains(".md#") {
                    continue;
                }

                let clean_target = target_raw.split('#').next().unwrap_or(target_raw);
                let target_stem = Path::new(clean_target)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(clean_target)
                    .to_lowercase();

                if let Some(matches) = files_by_name.get(&target_stem) {
                    if let Some((_, target_idx)) = matches.first() {
                        let edge_key = (source_idx.index(), target_idx.index());
                        if !edges_added.contains(&edge_key) && source_idx != *target_idx {
                            edges_added.insert(edge_key);
                            graph.add_edge(source_idx, *target_idx, ());
                        }
                    }
                } else {
                    broken_links.push((rel_path.clone(), target_raw.to_string()));
                }
            }
        }
    }

    // 3. Graph Analysis
    let total_nodes = graph.node_count();
    let total_edges = graph.edge_count();

    let density = if total_nodes > 1 {
        total_edges as f64 / (total_nodes * (total_nodes - 1)) as f64
    } else {
        0.0
    };

    let mut orphan_nodes = Vec::new();
    let mut node_degrees = Vec::new();

    for (name, &idx) in &node_indices {
        let in_deg = graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .count();
        let out_deg = graph
            .neighbors_directed(idx, petgraph::Direction::Outgoing)
            .count();

        if in_deg == 0 {
            orphan_nodes.push(name.clone());
        }
        node_degrees.push((name.clone(), in_deg, out_deg));
    }

    // Sort hubs by in-degree descending
    node_degrees.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    let hub_nodes = node_degrees.into_iter().take(10).collect();

    orphan_nodes.sort();

    // Strongly connected components (clusters)
    let scc = tarjan_scc(&graph);
    let clusters_count = scc.iter().filter(|c| c.len() > 1).count();

    let analysis = GraphAnalysis {
        total_nodes,
        total_edges,
        density,
        orphan_nodes,
        hub_nodes,
        broken_links,
        clusters_count,
    };

    let vault_graph = VaultGraph {
        graph,
        node_indices,
        file_paths,
    };

    (vault_graph, analysis)
}

/// Formats and prints the knowledge graph analysis to the terminal.
pub fn print_graph_report(analysis: &GraphAnalysis, show_orphans: bool) {
    println!(
        "\n{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!(
        "{}",
        "StenioSentinel Graph Engine (petgraph) — Vault Knowledge Topology"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );

    println!(
        "   📊 Total Documents (Nodes) : {}",
        analysis.total_nodes.to_string().bold()
    );
    println!(
        "   🔗 Total References (Edges): {}",
        analysis.total_edges.to_string().bold()
    );
    println!(
        "   🌐 Network Graph Density    : {:.4}%",
        analysis.density * 100.0
    );
    println!(
        "   🔄 Cyclic Clusters (SCCs)   : {}",
        analysis.clusters_count.to_string().bold()
    );
    println!(
        "   🏝️  Orphan Notes (In-deg 0) : {}",
        analysis.orphan_nodes.len().to_string().yellow().bold()
    );
    println!(
        "   ⚠️  Broken Link References  : {}",
        analysis.broken_links.len().to_string().red().bold()
    );

    println!(
        "\n{}",
        "── 🏛️  Top Knowledge Hubs (Most Referenced Documents) ───────────────".bold()
    );
    for (i, (name, in_deg, out_deg)) in analysis.hub_nodes.iter().enumerate().take(8) {
        println!(
            "   {:2}. {:<48} [{} in / {} out]",
            i + 1,
            name.cyan(),
            in_deg.to_string().green().bold(),
            out_deg.to_string().blue()
        );
    }

    if show_orphans && !analysis.orphan_nodes.is_empty() {
        println!(
            "\n{}",
            "── 🏝️  Orphan Documents (Unreferenced by any note) ─────────────────".bold()
        );
        for orphan in analysis.orphan_nodes.iter().take(20) {
            println!("   ⚠️  {}", orphan.yellow());
        }
        if analysis.orphan_nodes.len() > 20 {
            println!(
                "   ... and {} more orphan notes.",
                analysis.orphan_nodes.len() - 20
            );
        }
    }
}

/// Exports the graph in Graphviz DOT format for SVG/PNG rendering.
pub fn export_dot(vault_graph: &VaultGraph) -> String {
    let mut dot = String::new();
    dot.push_str("digraph VaultKnowledgeGraph {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box, style=\"rounded,filled\", fillcolor=\"#f8fafc\", fontname=\"Helvetica\", fontsize=10];\n");
    dot.push_str("  edge [color=\"#94a3b8\", arrowhead=vee, arrowsize=0.7];\n\n");

    for (name, &idx) in &vault_graph.node_indices {
        let in_deg = vault_graph
            .graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .count();
        let color = if in_deg > 5 {
            "#e0f2fe" // Hub
        } else if in_deg == 0 {
            "#fef3c7" // Orphan
        } else {
            "#ffffff"
        };
        let label = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        dot.push_str(&format!(
            "  \"{}\" [label=\"{}\", fillcolor=\"{}\"];\n",
            idx.index(),
            label,
            color
        ));
    }

    for edge in vault_graph.graph.raw_edges() {
        dot.push_str(&format!(
            "  \"{}\" -> \"{}\";\n",
            edge.source().index(),
            edge.target().index()
        ));
    }

    dot.push_str("}\n");
    dot
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_graph_construction_and_orphan_detection() {
        let temp_dir = std::env::temp_dir().join("stenio_test_graph");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        // Note A links to Note B
        let path_a = temp_dir.join("note-a.md");
        let mut file_a = File::create(&path_a).unwrap_or_else(|_| panic!("file create failed"));
        writeln!(file_a, "Link to [[note-b]] and [c](note-c.md)").unwrap_or_default();

        // Note B is linked by A
        let path_b = temp_dir.join("note-b.md");
        let mut file_b = File::create(&path_b).unwrap_or_else(|_| panic!("file create failed"));
        writeln!(file_b, "I am note B").unwrap_or_default();

        // Note C is linked by A
        let path_c = temp_dir.join("note-c.md");
        let mut file_c = File::create(&path_c).unwrap_or_else(|_| panic!("file create failed"));
        writeln!(file_c, "I am note C").unwrap_or_default();

        // Note D is an orphan (no incoming links)
        let path_d = temp_dir.join("note-d.md");
        let mut file_d = File::create(&path_d).unwrap_or_else(|_| panic!("file create failed"));
        writeln!(file_d, "I am lonely orphan note D").unwrap_or_default();

        let (graph, analysis) = build_vault_graph(&temp_dir);

        assert_eq!(analysis.total_nodes, 4);
        assert_eq!(analysis.total_edges, 2);
        assert!(analysis.orphan_nodes.contains(&"note-a.md".to_string()));
        assert!(analysis.orphan_nodes.contains(&"note-d.md".to_string()));
        assert!(!analysis.orphan_nodes.contains(&"note-b.md".to_string()));
        assert!(graph.get_path("note-a.md").is_some());

        let dot = export_dot(&graph);
        assert!(dot.contains("digraph VaultKnowledgeGraph"));
        assert!(dot.contains("note-a"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
