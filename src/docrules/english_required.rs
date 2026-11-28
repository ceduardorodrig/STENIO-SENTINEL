//! `LANG-ENGLISH-REQUIRED`: English is the default everywhere agents write. New or changed
//! Portuguese is an error in every tree, while the Portuguese that already exists is counted
//! debt that can only shrink.
//!
//! Judged: Markdown, text and HTML prose (frontmatter and tables included), source comments,
//! log/CLI strings, JSON descriptions, file and folder names, commit messages and pull request
//! text. Allowed Portuguese is declared centrally, by path with a reason: the built-in list
//! below (translation catalogues, third-party trees) and the `[language] allow` entries of a
//! `steniocheck.toml`. There is no per-line exemption. "New" is decided by the declared line
//! baseline (content hashes, so it works outside git) or, without one, by what a git tree
//! gained since the merge base with its default branch. A tree with neither is judged whole.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use regex::Regex;

use super::{Ctx, DocRule, finding};
use crate::config::{LanguageConfig, SteniocheckConfig};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "LANG-ENGLISH-REQUIRED",
    check,
    self_test,
    explain: RuleExplanation {
        id: "LANG-ENGLISH-REQUIRED",
        name: "New Portuguese (English Is the Default)",
        severity: "ERROR",
        tag: "doc",
        summary: "Prose, comments, log/CLI strings, JSON descriptions, file names, commit messages and PR text must not gain Portuguese in any tree. Existing text is debt: recorded in the line baseline, or, without one, everything already on the default branch.",
        rationale: "Owner directive of 2026-11-27 (governance/language-policy.md): agents write English unless the owner asks for Portuguese, and the gate blocks the rest; until 4.43 only warnings looked, and only at a few trees.",
        bad_example: "Para instalar o servico, voce precisa rodar o script antes.",
        good_example: "To install the service, run the script first. The button label is `Configurações`.",
        remediation: "Write it in English. A pt-BR user interface string belongs in the translation catalogue; a client deliverable or legal text belongs in a path declared under `[language] allow` with its reason (owner decision, never a per-line marker). Debt listing: `stenio language --path <tree>`.",
    },
};

const PROSE_EXTS: &[&str] = &["md", "txt", "html"];
const CODE_EXTS: &[&str] = &[
    "sh", "bash", "fish", "rs", "py", "ts", "tsx", "js", "jsx", "toml", "yml", "yaml", "sql",
    "css", "go", "json",
];
/// When the rule took effect: what was committed before is history, not new text.
const EFFECTIVE: &str = "2026-11-27T12:00:00Z";
const MAX_BYTES: u64 = 1_000_000;

/// The built-in allowlist, `(gitignore glob, reason)`, shared by every tree.
const BUILTIN_ALLOW: &[(&str, &str)] = &[
    ("**/locale/**", "translation catalogue (product UI)"),
    ("**/locales/**", "translation catalogue (product UI)"),
    ("**/i18n/**", "translation catalogue (product UI)"),
    ("**/translations/**", "translation catalogue (product UI)"),
    ("*.po", "translation catalogue (product UI)"),
    ("*.pot", "translation catalogue (product UI)"),
    (
        "**/pt-br/**",
        "declared Portuguese version of a bilingual document",
    ),
    (
        "**/pt-BR/**",
        "declared Portuguese version of a bilingual document",
    ),
    (
        "*.pt.md",
        "declared Portuguese version of a bilingual document",
    ),
    ("*pt_BR*", "translation file"),
    ("*pt-br*", "translation file"),
    ("**/node_modules/**", "third-party code"),
    ("**/vendor/**", "third-party code"),
    ("**/external/**", "third-party mirrors"),
    ("**/target/**", "build output"),
    ("**/.stversions/**", "sync history"),
    ("*.min.js", "generated code"),
    ("*lock.json", "generated lockfile"),
];

/// Spans of a Markdown line that cite something instead of saying it.
static CITATION: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"``[^`]*``|`[^`]*`|\]\([^)]*\)|\[\[[^\]]*\]\]|<[^>]*>|https?://\S+|"[^"]*"|“[^”]*”|«[^»]*»|\([^()]*\bpt-BR\b[^()]*\)"#,
    )
    .ok()
});

/// Proper names inside a sentence (`the Lei Geral de Proteção de Dados`) and file or identifier
/// tokens. A title-case chain that opens a line is a heading, and is judged.
static NAMES: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?P<lead>\p{Ll}+\s+|\b(?:The|the)\s+)\p{Lu}\p{L}*(?:\s+(?:de|da|do|das|dos|e)\s+\p{Lu}\p{L}*)+|\S*(?:/|_|\p{L}\.\p{L})\S*",
    )
    .ok()
});

/// Words that exist in no English sentence; one of them is enough.
/// Words that exist in no English sentence; one of them is enough.
const STRONG: &[&str] = &[
    "nao",
    "não",
    "voce",
    "você",
    "tambem",
    "também",
    "entao",
    "então",
    "porém",
    "está",
    "estão",
    "são",
    "será",
    "serão",
    "arquivo",
    "arquivos",
    "servico",
    "usuario",
    "usuarios",
    "precisa",
    "precisamos",
    "depois",
    "rodar",
    "voces",
    "estrutura",
    "validade",
    "procedimento",
    "projetos",
    "pendencias",
    "cronograma",
];

/// Portuguese words, diacritics dropped, that are not English words; two distinct ones in a
/// line are a Portuguese line.
const LEXICON: &[&str] = &[
    "para",
    "com",
    "como",
    "uma",
    "pelo",
    "pela",
    "este",
    "esta",
    "esse",
    "essa",
    "isso",
    "isto",
    "aquele",
    "aquela",
    "quando",
    "onde",
    "porque",
    "mais",
    "que",
    "dos",
    "das",
    "seus",
    "suas",
    "seu",
    "sua",
    "mas",
    "sem",
    "sobre",
    "entre",
    "cada",
    "aqui",
    "pode",
    "podem",
    "deve",
    "devem",
    "fazer",
    "fazendo",
    "feito",
    "antes",
    "ainda",
    "apenas",
    "todos",
    "todas",
    "nosso",
    "nossa",
    "meu",
    "minha",
    "mesmo",
    "sempre",
    "nunca",
    "ele",
    "ela",
    "eles",
    "elas",
    "pois",
    "seja",
    "foram",
    "foi",
    "estava",
    "sao",
    "estao",
    "sera",
    "usar",
    "usando",
    "criar",
    "apagar",
    "mudar",
    "rode",
    "instalar",
    "atualizar",
    "atualizado",
    "salvar",
    "remover",
    "erro",
    "falha",
    "falhou",
    "senha",
    "pasta",
    "pastas",
    "servicos",
    "ajuste",
    "ajustes",
    "hoje",
    "ontem",
    "amanha",
    "agora",
    "pendente",
    "pendentes",
    "novo",
    "nova",
    "antigo",
    "quem",
    "qual",
    "quais",
    "muito",
    "pouco",
    "outro",
    "outra",
    "dele",
    "dela",
    "numa",
    "aos",
    "vamos",
    "temos",
    "tem",
    "quer",
    "queremos",
    "dono",
    "projeto",
    "tarefa",
    "tarefas",
    "regra",
    "regras",
    "tela",
    "botao",
    "painel",
    "equipe",
    "planilha",
    "proposta",
    "reuniao",
    "documento",
    "documentos",
    "atual",
    "proximo",
    "passo",
    "passos",
    "ficou",
    "falta",
    "faltam",
    "testes",
    "gravar",
    "enviar",
    "baixar",
    "subir",
    "ligar",
    "desligar",
    "reiniciar",
    "conferir",
    "corrigir",
    "corrigido",
    "esperar",
    "aguardando",
    "iniciando",
    "concluido",
    "encontrado",
    "nenhum",
    "nenhuma",
    "alguma",
    "algum",
    "obrigado",
    "preciso",
    "veja",
    "faz",
    "ser",
    "estar",
    "sendo",
    "assim",
    "caso",
    "contra",
    "ate",
    "apos",
    "segue",
    "ficam",
    "fica",
    "diretorio",
    "cliente",
    "contexto",
    "arquivamento",
    "nomes",
    "arquivado",
    "arquivados",
    "mantidos",
    "projeto",
    "resumo",
    "objetivo",
    "escopo",
    "mesma",
    "arquivada",
    "diretorios",
];

/// Lexicon entries that are also English tokens: they only support another signal.
const WEAK: &[&str] = &[
    "ser", "ate", "caso", "contra", "com", "tem", "faz", "dos", "das",
];

/// Portuguese words that give a file or folder name away.
const NAME_WORDS: &[&str] = &[
    "relatorio",
    "relatorios",
    "roteiro",
    "sessao",
    "acessos",
    "pendencias",
    "proposta",
    "comercial",
    "estudo",
    "modelo",
    "dados",
    "matriz",
    "politica",
    "politicas",
    "privacidade",
    "termo",
    "consentimento",
    "imagem",
    "guia",
    "regras",
    "arquivo",
    "arquivos",
    "tarefas",
    "projeto",
    "projetos",
    "marca",
    "conteudo",
    "usuario",
    "usuarios",
    "senha",
    "servico",
    "servicos",
    "reuniao",
    "planejamento",
    "entrada",
    "pessoas",
    "setores",
    "funcao",
    "arquitetura",
    "traducao",
    "visualizacao",
    "decisoes",
    "governanca",
    "inventario",
    "referencias",
    "rascunho",
    "minuta",
    "contrato",
    "contratos",
    "anexo",
    "novo",
    "nova",
    "ativar",
    "assistente",
    "plataforma",
    "agente",
    "proximos",
    "passos",
    "licoes",
    "ajustes",
    "manutencao",
    "instalacao",
    "configuracao",
];

const BRANDS: &[&str] = &[
    "sumænimá",
    "sumaenima",
    "stênio",
    "stenio",
    "mnemocine",
    "miracena",
    "pokémon",
    "pokemon",
];

static SHELL_OUTPUT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?:^|&&|\|\||;|\{|\bthen\b|\belse\b)\s*(?:echo|printf|log|log_\w+|die|fail|warn|info|err|error|usage|say|notify|notify-send)\s").ok()
});

static CITATION_CODE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"`[^`]*`|https?://\S+|'[^']*'").ok());

static CODE_OUTPUT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\b(?:e?print(?:ln)?!|(?:log::|tracing::)?(?:error|warn|info|debug|trace)!|bail!|anyhow!|log_msg\(|console\.\w+\(|print\(|logging\.\w+\(|new Error\()").ok()
});

static STRING_LITERAL: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`]*)`"#).ok());

static PLACEHOLDER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\$\{[^}]*\}|\$\([^)]*\)|\$\w+|\{[^}]*\}|\\[a-z]").ok());

fn strip(re: &LazyLock<Option<Regex>>, text: &str) -> String {
    match re.as_ref() {
        Some(re) => re.replace_all(text, " ").into_owned(),
        None => text.to_string(),
    }
}

/// Lower-case word without its diacritics.
fn fold(word: &str) -> String {
    word.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' => 'a',
            'é' | 'ê' => 'e',
            'í' => 'i',
            'ó' | 'ô' | 'õ' => 'o',
            'ú' => 'u',
            'ç' => 'c',
            other => other,
        })
        .collect()
}

fn is_portuguese(text: &str) -> bool {
    let text = match NAMES.as_ref() {
        Some(re) => re.replace_all(text, "${lead} ").into_owned(),
        None => text.to_string(),
    };
    let (mut hits, mut weak) = (BTreeSet::new(), BTreeSet::new());
    // Each table cell opens its own sentence, so a capitalised first word is prose.
    let words = text.split('|').flat_map(|cell| {
        cell.split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.chars().any(char::is_alphabetic))
            .enumerate()
    });
    for (index, word) in words {
        if !crate::comments::is_prose_case(word, index == 0) {
            continue;
        }
        let lower = word.to_lowercase();
        if BRANDS.contains(&lower.as_str()) {
            continue;
        }
        let folded = fold(&lower);
        let nasal = lower.chars().count() > 3 && lower.contains(['ã', 'õ', 'ç']);
        let suffix = folded.len() > 5
            && (folded.ends_with("cao") || folded.ends_with("coes"))
            && !["cacao", "macao"].contains(&folded.as_str());
        if nasal || suffix || STRONG.contains(&lower.as_str()) {
            return true;
        }
        if WEAK.contains(&folded.as_str()) {
            weak.insert(folded);
        } else if LEXICON.contains(&folded.as_str()) {
            hits.insert(folded);
        }
    }
    hits.len() >= 2
        || (hits.len() == 1 && !weak.is_empty())
        || crate::comments::is_portuguese_comment_wide(&text)
}

fn is_portuguese_name(component: &str) -> bool {
    let stem = component.to_lowercase();
    stem.chars().any(|c| "áàâãéêíóôõúç".contains(c)) && !BRANDS.iter().any(|b| stem.contains(b))
        || stem
            .split(['-', '_', '.', ' '])
            .any(|w| NAME_WORDS.contains(&w))
}

/// The text a line of `ext` says in natural language, if any.
fn said(ext: &str, line: &str) -> Option<String> {
    if PROSE_EXTS.contains(&ext) {
        if line.trim_start().starts_with('>') {
            return None;
        }
        return Some(strip(&CITATION, line));
    }
    if ext == "json" {
        let (key, value) = line.trim().split_once(':')?;
        return (key.trim() == "\"description\"").then(|| strip(&CITATION_CODE, value));
    }
    let mut out = crate::comments::extract_comment(ext, line)
        .map(|c| strip(&CITATION, c))
        .unwrap_or_default();
    let output = if matches!(ext, "sh" | "bash" | "fish" | "yml" | "yaml") {
        &SHELL_OUTPUT
    } else {
        &CODE_OUTPUT
    };
    if !matches!(ext, "toml" | "sql" | "css")
        && output.as_ref().is_some_and(|re| re.is_match(line))
        && let Some(literal) = STRING_LITERAL.as_ref()
    {
        for c in literal.captures_iter(line) {
            if let Some(m) = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)) {
                out.push(' ');
                out.push_str(&strip(&PLACEHOLDER, m.as_str()));
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The Portuguese lines of one file as `(line number, line)`.
pub(super) fn portuguese_lines(path: &Path, content: &str) -> Vec<(usize, String)> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let mut fence = false;
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if ext == "md" {
            let t = line.trim_start();
            if t.starts_with("```") || t.starts_with("~~~") {
                fence = !fence;
                continue;
            }
            if fence {
                continue;
            }
        }
        if said(ext, line).is_some_and(|t| is_portuguese(&t)) {
            out.push((idx + 1, line.to_string()));
        }
    }
    out
}

/// FNV-1a of the line with its whitespace normalised: stable across moves and re-indentation.
pub(super) fn line_hash(line: &str) -> u64 {
    let normal = line.split_whitespace().collect::<Vec<_>>().join(" ");
    normal.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The tree a file belongs to.
#[derive(Clone)]
pub(super) struct Scope {
    pub(super) root: PathBuf,
    pub(super) baseline: Option<PathBuf>,
    allow: Gitignore,
}

fn scope_at(root: &Path, language: LanguageConfig) -> Option<Scope> {
    let mut builder = GitignoreBuilder::new(root);
    for (glob, _) in BUILTIN_ALLOW {
        builder.add_line(None, glob).ok()?;
    }
    // An entry without a reason allows nothing.
    for entry in language.allow.unwrap_or_default() {
        if !entry.reason.trim().is_empty() {
            builder.add_line(None, &entry.path).ok()?;
        }
    }
    Some(Scope {
        root: root.to_path_buf(),
        baseline: language.baseline.map(|b| root.join(b)),
        allow: builder.build().ok()?,
    })
}

/// The scope governing files of `dir`: the nearest `[language]` table or repository root,
/// else the scanned tree itself.
fn scope_of(dir: &Path, fallback: &Path) -> Option<Scope> {
    for ancestor in dir.ancestors() {
        let declared = ancestor
            .join("steniocheck.toml")
            .is_file()
            .then(|| {
                SteniocheckConfig::load_from_dir(ancestor)
                    .unwrap_or_default()
                    .language
            })
            .flatten();
        if let Some(language) = declared {
            return scope_at(ancestor, language);
        }
        if ancestor.join(".git").exists() {
            return scope_at(ancestor, LanguageConfig::default());
        }
    }
    scope_at(fallback, LanguageConfig::default())
}

impl Scope {
    fn covers(&self, path: &Path) -> bool {
        path.strip_prefix(&self.root).is_ok_and(|rel| {
            !self
                .allow
                .matched_path_or_any_parents(rel, false)
                .is_ignore()
        })
    }
}

/// One Portuguese line of an in-scope file; line 0 stands for the file name.
pub(super) struct Hit {
    pub(super) path: PathBuf,
    pub(super) line: usize,
    pub(super) text: String,
}

fn judged(path: &Path) -> Option<String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if !PROSE_EXTS.contains(&ext) && !CODE_EXTS.contains(&ext) {
        return None;
    }
    if fs::metadata(path).map_or(true, |m| m.len() > MAX_BYTES) {
        return None;
    }
    fs::read_to_string(path).ok()
}

pub(super) fn collect(ctx: &Ctx) -> BTreeMap<PathBuf, (Scope, Vec<Hit>)> {
    let mut cache: HashMap<PathBuf, Option<Scope>> = HashMap::new();
    let mut out: BTreeMap<PathBuf, (Scope, Vec<Hit>)> = BTreeMap::new();
    let mut named = BTreeSet::new();
    let files = if ctx.target.is_file() {
        vec![ctx.target.clone()]
    } else {
        super::walk(&ctx.target)
    };
    for path in files {
        let Some(dir) = path.parent() else {
            continue;
        };
        let scope = cache
            .entry(dir.to_path_buf())
            .or_insert_with(|| scope_of(dir, ctx.root()));
        let Some(scope) = scope.as_ref().filter(|s| s.covers(&path)) else {
            continue;
        };
        let entry = out
            .entry(scope.root.clone())
            .or_insert_with(|| (scope.clone(), Vec::new()));
        // Names: each Portuguese component once, attributed to the first file under it.
        let mut prefix = PathBuf::new();
        for part in path.strip_prefix(&scope.root).iter().flat_map(|r| r.iter()) {
            prefix.push(part);
            if is_portuguese_name(&part.to_string_lossy()) && named.insert(scope.root.join(&prefix))
            {
                entry.1.push(Hit {
                    path: path.clone(),
                    line: 0,
                    text: format!("name:{}", prefix.display()),
                });
            }
        }
        // The ledger quotes Portuguese file names by design.
        if scope.baseline.as_ref() == Some(&path) {
            continue;
        }
        let Some(content) = judged(&path) else {
            continue;
        };
        entry.1.extend(
            portuguese_lines(&path, &content)
                .into_iter()
                .map(|(line, text)| Hit {
                    path: path.clone(),
                    line,
                    text,
                }),
        );
    }
    out
}

pub(super) fn read_baseline(file: &Path) -> Option<HashMap<u64, usize>> {
    let text = fs::read_to_string(file).ok()?;
    Some(
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let mut parts = l.split_whitespace();
                let hash = u64::from_str_radix(parts.next()?, 16).ok()?;
                Some((hash, parts.next()?.parse().ok()?))
            })
            .collect(),
    )
}

pub(super) fn git(root: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.quotepath=false"])
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// What is already history: the newer of the closest merge base with a default branch of the
/// remote (`HEAD` when there is none) and the last commit made before the rule took effect.
fn diff_base(top: &Path) -> String {
    let merged = [
        "origin/HEAD",
        "origin/main",
        "origin/master",
        "origin/DEVELOPMENT",
    ]
    .iter()
    .filter_map(|r| git(top, &["merge-base", "HEAD", r]))
    .filter_map(|base| {
        let base = base.trim().to_string();
        let ahead = git(top, &["rev-list", "--count", &format!("{base}..HEAD")])?;
        Some((ahead.trim().parse::<usize>().ok()?, base))
    })
    .min()
    .map_or_else(|| "HEAD".to_string(), |(_, base)| base);
    let before = format!("--before={EFFECTIVE}");
    match git(top, &["rev-list", "-1", &before, "HEAD"]) {
        Some(old)
            if !old.trim().is_empty()
                && git(top, &["merge-base", "--is-ancestor", &merged, old.trim()]).is_some() =>
        {
            old.trim().to_string()
        }
        _ => merged,
    }
}

/// What a repository gained since its base.
struct Added {
    /// Per file, the new line numbers.
    lines: HashMap<PathBuf, Vec<usize>>,
    untracked: Vec<PathBuf>,
    /// Files that did not exist at the base (added or renamed to).
    created: Vec<PathBuf>,
    /// Removed line hashes: a line that only moved is not new.
    removed: HashMap<u64, usize>,
}

fn added_since_base(root: &Path) -> Option<Added> {
    let top = PathBuf::from(git(root, &["rev-parse", "--show-toplevel"])?.trim());
    let base = diff_base(&top);
    let diff = git(
        &top,
        &[
            "diff",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            &base,
            "--",
        ],
    )
    .unwrap_or_default();
    let mut added = Added {
        lines: HashMap::new(),
        untracked: git(&top, &["ls-files", "--others", "--exclude-standard"])
            .unwrap_or_default()
            .lines()
            .map(|l| top.join(l))
            .collect(),
        removed: HashMap::new(),
        created: git(
            &top,
            &["diff", "--name-only", "--diff-filter=AR", "-M", &base, "--"],
        )
        .unwrap_or_default()
        .lines()
        .map(|l| top.join(l))
        .collect(),
    };
    let (mut file, mut next, mut in_hunk) = (None::<PathBuf>, 0usize, false);
    for line in diff.lines() {
        if line.starts_with("diff --git") {
            (file, in_hunk) = (None, false);
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            in_hunk = true;
            next = rest
                .split('+')
                .nth(1)
                .and_then(|r| r.split([',', ' ']).next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        } else if !in_hunk {
            if let Some(name) = line.strip_prefix("+++ b/") {
                file = Some(top.join(name));
            }
        } else if line.starts_with('+') {
            if let Some(f) = &file {
                added.lines.entry(f.clone()).or_default().push(next);
            }
            next += 1;
        } else if let Some(old) = line.strip_prefix('-') {
            *added.removed.entry(line_hash(old)).or_default() += 1;
        }
    }
    Some(added)
}

fn report(ctx: &Ctx, hit: &Hit, why: &str, out: &mut Vec<Violation>) {
    let what = if hit.line == 0 {
        "file or folder name"
    } else {
        "line"
    };
    out.push(finding(
        &RULE.explain,
        Severity::Error,
        ctx.display(&hit.path),
        hit.line.max(1),
        &hit.text,
        format!("Portuguese {what}; English is the default ({why})"),
    ));
}

fn tree_finding(ctx: &Ctx, severity: Severity, file: &Path, message: String) -> Violation {
    finding(&RULE.explain, severity, ctx.display(file), 1, "", message)
}

fn check_baselined(ctx: &Ctx, scope: &Scope, file: &Path, hits: &[Hit], out: &mut Vec<Violation>) {
    let Some(mut allowed) = read_baseline(file) else {
        out.push(tree_finding(
            ctx,
            Severity::Error,
            file,
            "the declared language baseline is missing: restore it (it is never recreated over lost debt)"
                .to_string(),
        ));
        return;
    };
    for hit in hits {
        match allowed.get_mut(&line_hash(&hit.text)) {
            Some(left) if *left > 0 => *left -= 1,
            _ => report(ctx, hit, "not in the baseline", out),
        }
    }
    let stale: usize = allowed.values().sum();
    if stale > 0 && ctx.target == scope.root {
        out.push(tree_finding(
            ctx,
            Severity::Error,
            file,
            format!(
                "the language ledger is stale by {stale} line(s) that no longer exist: `stenio language --prune --path {}`",
                scope.root.display()
            ),
        ));
    }
    // Under git a baseline may only lose entries once it has been committed.
    let tracked = git(
        &scope.root,
        &["ls-files", "--error-unmatch", &file.to_string_lossy()],
    );
    if tracked.is_some()
        && let Some(added) = added_since_base(&scope.root)
        && let Ok(real) = file.canonicalize()
        && added.lines.contains_key(&real)
        && git(
            &scope.root,
            &[
                "cat-file",
                "-e",
                &format!("HEAD:./{}", relative(&scope.root, file)),
            ],
        )
        .is_some()
    {
        out.push(tree_finding(
            ctx,
            Severity::Error,
            file,
            "the language baseline gained entries; it only shrinks (`stenio language --prune`)"
                .to_string(),
        ));
    }
}

pub(super) fn relative(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .into_owned()
}

fn check_diffed(ctx: &Ctx, scope: &Scope, hits: &[Hit], out: &mut Vec<Violation>) {
    if hits.is_empty() {
        return;
    }
    let Some(mut added) = added_since_base(&scope.root) else {
        // History that cannot be read says nothing about what is new: an enclosing ledger does.
        if let Some((file, mut allowed)) = inherited_baseline(&scope.root) {
            let why = format!("not in the inherited baseline {}", file.display());
            for hit in hits {
                match allowed.get_mut(&line_hash(&hit.text)) {
                    Some(left) if *left > 0 => *left -= 1,
                    _ => report(ctx, hit, &why, out),
                }
            }
            return;
        }
        for hit in hits {
            report(
                ctx,
                hit,
                "no baseline and no git history to compare with",
                out,
            );
        }
        return;
    };
    for hit in hits {
        let untracked = added.untracked.contains(&hit.path);
        let new = if hit.line == 0 {
            untracked || added.created.contains(&hit.path)
        } else {
            untracked
                || added
                    .lines
                    .get(&hit.path)
                    .is_some_and(|l| l.contains(&hit.line))
        };
        if !new {
            continue;
        }
        match added.removed.get_mut(&line_hash(&hit.text)) {
            Some(moved) if *moved > 0 => *moved -= 1,
            _ => report(ctx, hit, "added since the default branch", out),
        }
    }
}

/// The ledger of the nearest ancestor of `root` whose `[language]` table declares a readable one.
fn inherited_baseline(root: &Path) -> Option<(PathBuf, HashMap<u64, usize>)> {
    root.ancestors().skip(1).find_map(|dir| {
        if !dir.join("steniocheck.toml").is_file() {
            return None;
        }
        let file = dir.join(
            SteniocheckConfig::load_from_dir(dir)
                .ok()?
                .language?
                .baseline?,
        );
        let allowed = read_baseline(&file)?;
        Some((file, allowed))
    })
}

/// The Portuguese lines of a commit message or pull request text.
fn message_lines(text: &str) -> Vec<(usize, String)> {
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with('#') || l.starts_with("##"))
        .collect::<Vec<_>>()
        .join("\n");
    portuguese_lines(Path::new("message.md"), &body)
}

/// Commit messages the branch adds (and, in CI, the pull request title and body).
fn check_messages(root: &Path, out: &mut Vec<Violation>) {
    let mut texts: Vec<(String, String)> = Vec::new();
    if let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) {
        let top = PathBuf::from(top.trim());
        let range = format!("{}..HEAD", diff_base(&top));
        let since = format!("--since={EFFECTIVE}");
        let log = git(
            &top,
            &[
                "log",
                "--no-merges",
                &since,
                "--format=%h%x00%B%x01",
                &range,
            ],
        )
        .unwrap_or_default();
        for entry in log.split('\u{1}') {
            if let Some((sha, body)) = entry.trim().split_once('\0') {
                texts.push((format!("commit {sha}"), body.to_string()));
            }
        }
        let event = std::env::var("GITHUB_EVENT_PATH")
            .ok()
            .filter(|_| {
                std::env::var("GITHUB_WORKSPACE").is_ok_and(|w| Path::new(&w) == top.as_path())
            })
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        if let Some(pr) = event.as_ref().and_then(|e| e.get("pull_request")) {
            let field = |k: &str| pr.get(k).and_then(|v| v.as_str()).unwrap_or("");
            texts.push((
                "pull request".to_string(),
                format!("{}\n{}", field("title"), field("body")),
            ));
        }
    }
    for (origin, text) in texts {
        for (line, said) in message_lines(&text) {
            out.push(finding(
                &RULE.explain,
                Severity::Error,
                origin.clone(),
                line,
                &said,
                "Portuguese commit or pull request text; English is the default".to_string(),
            ));
        }
    }
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    for (scope, hits) in collect(ctx).values() {
        match &scope.baseline {
            Some(file) => check_baselined(ctx, scope, file, hits, out),
            None => check_diffed(ctx, scope, hits, out),
        }
        check_messages(&scope.root, out);
    }
}

/// `commit-msg` hook entry: exit 1 when the message (or PR text) file holds Portuguese.
pub(super) fn judge_message(file: &Path) -> i32 {
    let Ok(text) = fs::read_to_string(file) else {
        eprintln!("language: cannot read {}", file.display());
        return 2;
    };
    let found = message_lines(&text);
    for (line, said) in &found {
        eprintln!("ERROR [{}] {}:{line}: {said}", RULE.id, file.display());
    }
    i32::from(!found.is_empty())
}

const PT: &str = "Para instalar o servico, voce precisa rodar o script antes.\n";

fn count(name: &str, files: &[(&str, &str)], expected: usize) -> (String, bool) {
    let ok = super::probe(&RULE, name, files).is_some_and(|v| v.len() == expected);
    (format!("{} {name}", RULE.id), ok)
}

/// A repository with one committed legacy line, then `change` applied on top and, when
/// `message` is given, committed with it.
fn git_case(
    name: &str,
    change: &[(&str, &str)],
    message: Option<&str>,
    expected: usize,
) -> (String, bool) {
    let files = [("legacy.md".to_string(), PT.to_string())];
    let ok =
        crate::frappe::write_fixture(&format!("language-{name}"), &files).is_some_and(|root| {
            let mut built = git(&root, &["init", "-q"]).is_some()
                && git(&root, &["add", "."]).is_some()
                && commit(&root, "base", None)
                && git(&root, &["update-ref", "refs/remotes/origin/main", "HEAD"]).is_some()
                && change
                    .iter()
                    .all(|(p, t)| fs::write(root.join(p), t).is_ok());
            if let Some(text) = message {
                // The committer date must be on or after the first day of the rule.
                built = built && commit(&root, text, Some("2027-01-01T00:00:00Z"));
            }
            let mut found = Vec::new();
            check(&Ctx::fixture(&root), &mut found);
            let _ = fs::remove_dir_all(&root);
            built && found.len() == expected
        });
    (format!("{} {name}", RULE.id), ok)
}

/// An empty-or-staged commit in a fixture repository, optionally with a committer date.
fn commit(root: &Path, message: &str, date: Option<&str>) -> bool {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["-c", "user.email=t@example.invalid", "-c", "user.name=t"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(["commit", "--allow-empty", "-qm", message])
        .env_remove("GIT_DIR")
        .env_remove("GIT_INDEX_FILE");
    if let Some(date) = date {
        command.env("GIT_COMMITTER_DATE", date);
    }
    command.output().is_ok_and(|o| o.status.success())
}

/// A nested tree with a `.git` directory whose history cannot be read, under a ledger.
fn unreadable_history(
    name: &str,
    config: (&str, &str),
    base: (&str, &str),
    old: (&str, &str),
) -> Vec<(String, bool)> {
    let broken = ("nested/.git/HEAD", "not a repository\n");
    let known = ("nested/old.md", PT);
    vec![
        count(
            &format!("{name}-ledgered-silent"),
            &[config, base, old, broken, known],
            0,
        ),
        count(
            &format!("{name}-new-line-red"),
            &[
                config,
                base,
                old,
                broken,
                known,
                ("nested/new.md", "Isso não está pronto.\n"),
            ],
            1,
        ),
    ]
}

fn self_test() -> Vec<(String, bool)> {
    let config = (
        "steniocheck.toml",
        "[language]\nbaseline = \"base.txt\"\nallow = [{ path = \"deliverables/**\", reason = \"client deliverable\" }, { path = \"loose/**\", reason = \"\" }]\n",
    );
    let known = format!("{:016x} 1 docs/old.md\n", line_hash(PT.trim_end()));
    let base = ("base.txt", known.as_str());
    let old = ("docs/old.md", PT);
    let cited = (
        "docs/new.md",
        "The label is `Configurações` and the screen says \"Não foi possível\".\n```\nnão\n```\n> não\nThe Lei Geral de Proteção de Dados applies in São Paulo.\n",
    );
    let allowed = [("deliverables/offer.md", PT), ("app/locale/pt_BR.po", PT)];
    let one = |name: &str, path: &'static str, text: &str| {
        count(name, &[config, base, old, (path, text)], 1)
    };
    let mut cases = unreadable_history("inherited", config, base, old);
    cases.extend(vec![
        count(
            "allowed-and-cited-silent",
            &[config, base, old, cited, allowed[0], allowed[1]],
            0,
        ),
        one(
            "new-line",
            "docs/new.md",
            "# Title\nIsso não está pronto.\n",
        ),
        one(
            "no-diacritics",
            "docs/new.md",
            "Rode o teste antes de salvar.\n",
        ),
        one(
            "frontmatter",
            "docs/new.md",
            "---\ntitle: Guia para a equipe\n---\n",
        ),
        one(
            "table-cell",
            "docs/new.md",
            "| Step | Note |\n|---|---|\n| 1 | falta conferir |\n",
        ),
        one(
            "title-case-heading",
            "docs/new.md",
            "## Procedimento de Arquivamento\n",
        ),
        one("code-comment", "src/a.rs", "// apagar antes de enviar\n"),
        one(
            "output-string",
            "hooks/g.sh",
            "echo \"voce nao pode usar este comando\" >&2\n",
        ),
        one(
            "json-description",
            "a.json",
            "{\n  \"description\": \"Lista de tarefas da equipe\"\n}\n",
        ),
        one("file-name", "docs/relatorio-final.md", "Fine.\n"),
        one("reasonless-allow", "loose/x.md", PT),
        count("copied-debt", &[config, base, old, ("docs/copy.md", PT)], 1),
        count("baseline-missing", &[config, old], 1),
        count("stale-ledger", &[config, base], 1),
        count("no-baseline-no-git", &[old], 1),
        git_case("git-committed-debt-silent", &[], None, 0),
        git_case("git-new-file", &[("new.md", PT)], None, 1),
        git_case(
            "git-new-line",
            &[("legacy.md", &format!("{PT}Isso não está pronto.\n"))],
            None,
            1,
        ),
        git_case(
            "git-english-edit",
            &[("legacy.md", &format!("{PT}This is ready.\n"))],
            None,
            0,
        ),
        git_case(
            "commit-message-red",
            &[],
            Some("corrige o erro antes de enviar"),
            1,
        ),
        git_case(
            "commit-message-green",
            &[],
            Some("fix: the sender check"),
            0,
        ),
    ]);
    cases
}
