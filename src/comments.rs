//! Multi-language source code comment extraction and natural language audit.
//!
//! Enforces the canonical English-only policy across all programming languages
//! (Rust, TypeScript, JavaScript, Python, Shell/Bash, SQL, C/C++, HTML, CSS, TOML, YAML).

/// Extracts the comment content from a single line of code according to the file extension.
/// Handles single-line comments, block comment markers, and inline comments outside quotes.
pub fn extract_comment<'a>(ext: &str, line: &'a str) -> Option<&'a str> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Direct line-start comments
    match ext {
        "rs" | "ts" | "tsx" | "js" | "jsx" | "c" | "cpp" | "h" | "hpp" | "go" | "java" | "kt"
        | "swift" | "dart" | "zig" | "cs" | "php" | "css" | "scss" => {
            if let Some(rest) = trimmed.strip_prefix("///") {
                return Some(rest.trim());
            }
            if let Some(rest) = trimmed.strip_prefix("//!") {
                return Some(rest.trim());
            }
            if let Some(rest) = trimmed.strip_prefix("//") {
                return Some(rest.trim());
            }
            if let Some(rest) = trimmed.strip_prefix("/*") {
                let inner = rest.strip_suffix("*/").unwrap_or(rest);
                return Some(inner.trim());
            }
            if let Some(rest) = trimmed.strip_prefix('*') {
                let inner = rest.strip_suffix("*/").unwrap_or(rest);
                return Some(inner.trim());
            }
        }
        "sql" | "lua" | "hs" | "ada" => {
            if let Some(rest) = trimmed.strip_prefix("--") {
                return Some(rest.trim());
            }
        }
        "py" | "sh" | "bash" | "yaml" | "yml" | "toml" | "dockerfile" | "rb" | "r" | "pl" => {
            if trimmed.starts_with('#') && !trimmed.starts_with("#!") {
                return Some(trimmed[1..].trim());
            }
        }
        "html" | "xml" | "svg" => {
            if let Some(rest) = trimmed.strip_prefix("<!--") {
                let inner = rest.strip_suffix("-->").unwrap_or(rest);
                return Some(inner.trim());
            }
        }
        _ => {}
    }

    // 2. Trailing inline comments outside of string quotes
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            in_quote = Some(b);
            continue;
        }

        match ext {
            "rs" | "ts" | "tsx" | "js" | "jsx" | "c" | "cpp" | "h" | "hpp" | "go" | "java"
            | "kt" | "swift" | "dart" | "zig" | "cs" | "php" => {
                if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    return Some(line[i + 2..].trim());
                }
            }
            "sql" | "lua" | "hs" | "ada" => {
                if b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
                    return Some(line[i + 2..].trim());
                }
            }
            "py" | "sh" | "bash" | "toml" | "yaml" | "yml" => {
                if b == b'#' && (i == 0 || bytes[i - 1] != b'$') {
                    if !line[i..].starts_with("#!") {
                        return Some(line[i + 1..].trim());
                    }
                }
            }
            _ => {}
        }
    }

    None
}

/// Checks if a comment contains Portuguese natural language (the narrow, ERROR-grade detector:
/// every comment it flags was already flagged by 4.36.0).
pub fn is_portuguese_comment(comment: &str) -> bool {
    detect_portuguese(comment, false)
}

/// GB-282(a) wide detector: the narrow one plus a second tier of Portuguese function words and
/// prepositions. A comment only this one flags is reported as a WARNING, because stenio-check CI
/// downloads the latest engine and a new ERROR would turn every repository red at release time
/// (4.38.0 measurement: MNEMOCINE goes from 0 to 4 new findings on real Portuguese comments).
pub fn is_portuguese_comment_wide(comment: &str) -> bool {
    detect_portuguese(comment, true)
}

/// Severity of a comment under CODE-NO-PORTUGUESE-COMMENTS: ERROR for the narrow detector,
/// WARNING for a comment only the wide recall catches, `None` for English.
pub fn portuguese_severity(comment: &str) -> Option<crate::rule::Severity> {
    if is_portuguese_comment(comment) {
        Some(crate::rule::Severity::Error)
    } else if is_portuguese_comment_wide(comment) {
        Some(crate::rule::Severity::Warning)
    } else {
        None
    }
}

fn detect_portuguese(comment: &str, wide: bool) -> bool {
    // 1. Convert to lowercase and remove permitted brand names, technical abbreviations, and proper nouns
    let lower = comment.to_lowercase();
    let cleaned = lower
        .replace("sumænimá", "")
        .replace("sumaenima", "")
        .replace("stênio", "")
        .replace("stenio", "")
        .replace("mnemocine", "")
        .replace("pokémon", "")
        .replace("pokemon", "")
        .replace("sérgio", "");

    // 2. Portuguese accented words are evidence, not proof (GB-278): an English comment that only
    //    names a place or a person (`Timezone: Brasilia is UTC-3`) is not Portuguese. They count
    //    towards the sentence-level threshold below, with capitalised non-initial words (proper
    //    nouns) excluded.
    let accented_words = count_accented_pt_words(comment);

    // 3. Unambiguous Portuguese grammatical words & technical terms (unaccented forms)
    static UNAMBIGUOUS_PT_WORDS: &[&str] = &[
        "funcao",
        "funcoes",
        "padrao",
        "padroes",
        "configuracao",
        "configuracoes",
        "atencao",
        "observacao",
        "validacao",
        "validacoes",
        "requisicao",
        "requisicoes",
        "atualizacao",
        "autenticacao",
        "conexao",
        "conexoes",
        "criacao",
        "edicao",
        "alteracao",
        "resposta",
        "respostas",
        "leitora",
        "servidor",
        "mensagem",
        "mensagens",
        "resolvido",
        "resolvida",
        "exclusao",
        "permissao",
        "permissoes",
        "obrigatorio",
        "obrigatoria",
        "invalido",
        "invalida",
        "nao",
        "sao",
        "estao",
        "verificar",
        "garantir",
        "relatorio",
        "relatorios",
    ];

    // Strip backticked symbols before checking word tokens
    let mut cleaned_no_code = String::with_capacity(cleaned.len());
    let mut in_backtick = false;
    for ch in cleaned.chars() {
        if ch == '`' {
            in_backtick = !in_backtick;
        } else if !in_backtick {
            cleaned_no_code.push(ch);
        }
    }

    let words: Vec<&str> = cleaned_no_code
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .collect();

    for w in &words {
        if UNAMBIGUOUS_PT_WORDS.iter().any(|&pt| pt == *w) {
            return true;
        }
    }

    // 4. Sentence-level evidence: Portuguese function words plus accented lowercase words, at
    //    least two in the same comment. The word list is the pre-4.36.0 one on purpose: the
    //    detector only got narrower (every comment it flags now was flagged before), so a repo
    //    that was green on 4.35.0 never turns red on 4.36.0.
    //
    //    GB-282(a) widens the recall (`wide`): the second tier holds Portuguese function words
    //    that are not English words (a comment such as `// arquivo que contém os dados` carried
    //    one accented word and nothing else the old list knew). The threshold stays at two
    //    signals per comment, so a single borrowed word or a proper noun never fires.
    static PT_STOPWORDS: &[&str] = &[
        "para", "com", "como", "pelo", "pela", "pelos", "pelas", "este", "esta", "esse", "essa",
        "aquele", "aquela", "quando", "onde", "porque", "uma", "mais",
    ];
    static PT_STOPWORDS_WIDE: &[&str] = &[
        "que", "dos", "das", "seus", "suas", "mas", "sem", "sobre", "entre", "cada", "isso",
        "aqui", "pode", "podem", "deve", "devem", "fazer", "antes", "depois", "ainda", "apenas",
        "todos", "todas", "nosso", "nossa", "mesmo", "sempre", "nunca", "arquivo", "arquivos",
        "ele", "ela", "eles", "elas", "pois", "seja", "foram", "estava", "tambem", "entao", "voce",
        "sera",
    ];

    let sw_count = words
        .iter()
        .filter(|w| {
            PT_STOPWORDS.iter().any(|&sw| sw == **w)
                || (wide && PT_STOPWORDS_WIDE.iter().any(|&sw| sw == **w))
        })
        .count();

    // `de`, `da` and `em` are Portuguese prepositions but also appear in English as `de-dup`,
    // `em` (CSS) or a loanword: they count only as a standalone token followed by a lowercase
    // word of three or more letters (`de arquivos`, `em memória`).
    let tokens: Vec<&str> = cleaned_no_code
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| !c.is_alphanumeric()))
        .collect();
    let preposition_count = tokens
        .windows(2)
        .filter(|w| {
            wide && matches!(w[0], "de" | "da" | "em")
                && w[1].chars().count() >= 3
                && w[1].chars().all(char::is_alphabetic)
        })
        .count();

    sw_count + preposition_count + accented_words >= 2
}

/// Counts words with Portuguese accented letters, skipping brand names, URL/path-like tokens and
/// capitalised words that are not the first word of the comment (proper nouns such as a city name).
fn count_accented_pt_words(comment: &str) -> usize {
    const BRANDS: &[&str] = &["sumænimá", "stênio", "pokémon", "sérgio"];
    let mut count = 0;
    let mut first = true;
    for raw in comment.split_whitespace() {
        let is_first = first;
        first = false;
        let trimmed = raw.trim_matches(|c: char| !c.is_alphanumeric());
        if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('.') {
            continue;
        }
        for word in trimmed.split(|c: char| !c.is_alphanumeric() && c != '_') {
            let Some(initial) = word.chars().next() else {
                continue;
            };
            let lowered = word.to_lowercase();
            if BRANDS.iter().any(|b| lowered.contains(b)) {
                continue;
            }
            if initial.is_uppercase() && !is_first {
                continue;
            }
            if lowered.chars().any(|c| {
                matches!(
                    c,
                    'á' | 'à' | 'â' | 'ã' | 'é' | 'ê' | 'í' | 'ó' | 'ô' | 'õ' | 'ú' | 'ç'
                )
            }) {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_comment_c_style() {
        assert_eq!(extract_comment("rs", "// hello world"), Some("hello world"));
        assert_eq!(
            extract_comment("rs", "/// doc comment"),
            Some("doc comment")
        );
        assert_eq!(extract_comment("rs", "//! inner doc"), Some("inner doc"));
        assert_eq!(
            extract_comment("ts", "let x = 1; // inline comment"),
            Some("inline comment")
        );
        assert_eq!(
            extract_comment("js", "const url = \"https://foo.bar\";"),
            None
        );
        assert_eq!(
            extract_comment("rs", "/* block comment */"),
            Some("block comment")
        );
        assert_eq!(
            extract_comment("rs", " * list in block"),
            Some("list in block")
        );
    }

    #[test]
    fn test_extract_comment_sql() {
        assert_eq!(
            extract_comment("sql", "-- table schema"),
            Some("table schema")
        );
        assert_eq!(
            extract_comment("sql", "SELECT * FROM users; -- get all"),
            Some("get all")
        );
    }

    #[test]
    fn test_extract_comment_script() {
        assert_eq!(extract_comment("sh", "#!/usr/bin/env bash"), None);
        assert_eq!(
            extract_comment("sh", "# run backup now"),
            Some("run backup now")
        );
        assert_eq!(
            extract_comment("py", "def foo(): # python comment"),
            Some("python comment")
        );
    }

    #[test]
    fn test_is_portuguese_comment_detection() {
        // Accented Portuguese
        assert!(is_portuguese_comment("comentário com acentuação"));
        assert!(is_portuguese_comment("validação de dados do usuário"));
        assert!(is_portuguese_comment("esta função não pode falhar"));

        // Unaccented unambiguous Portuguese
        assert!(is_portuguese_comment("funcao de autenticacao"));
        assert!(is_portuguese_comment("verificar se o servidor respondeu"));
        assert!(is_portuguese_comment("resolvido no branch principal"));

        // Stopwords combination
        assert!(is_portuguese_comment("feito para rodar com docker"));

        // GB-278: sentence-level evidence, the rule's own --explain example stays red
        assert!(is_portuguese_comment(
            "função para validar o token do usuário"
        ));
        assert!(is_portuguese_comment(
            "Timezone: Brasília, mas a função não trata o fuso"
        ));

        // GB-278: an English comment with a proper noun or one accented word is not Portuguese
        assert!(!is_portuguese_comment(
            "Timezone: Brasília is UTC-3, handled by the caller."
        ));
        assert!(!is_portuguese_comment("Render the São Paulo office hours"));
        assert!(!is_portuguese_comment("Serve the café menu from cache"));

        // English comments (should pass)
        assert!(!is_portuguese_comment(
            "Initialize the database connection pool"
        ));
        assert!(!is_portuguese_comment("Handle incoming WebSocket frame"));
        assert!(!is_portuguese_comment("Returns status code 200 on success"));
        assert!(!is_portuguese_comment(
            "Query Scryfall for Pokémon card prices"
        ));
        assert!(!is_portuguese_comment(
            "Sumænimá Hub audio stream pipeline with Stênio kernel"
        ));
    }
}

/// GB-278 self-test cases for CODE-NO-PORTUGUESE-COMMENTS (wired into `--self-test`).
pub fn self_test_cases() -> Vec<(&'static str, bool)> {
    let pt = |line: &str| extract_comment("rs", line).is_some_and(is_portuguese_comment);
    let wide = |line: &str| extract_comment("rs", line).is_some_and(is_portuguese_comment_wide);
    vec![
        (
            "pt-comment: English comment with a proper noun is not Portuguese",
            !pt("// Timezone: Brasília is UTC-3, handled by the caller."),
        ),
        (
            "pt-comment: the --explain example stays red",
            pt("// função para validar o token do usuário"),
        ),
        (
            "pt-comment: GB-282 recall, function words without a single accent are red",
            wide("// arquivo que contém os dados de entrada")
                && wide("// isso deve ser feito antes de validar o token")
                && wide("// lê o arquivo e guarda em memória")
                && !pt("// arquivo que contém os dados de entrada"),
        ),
        (
            "pt-comment: GB-282 English with `em`, `de-dup` or one borrowed word stays green",
            !wide("// em dash and de-dup are handled by the formatter")
                && !wide("// Timezone Brasília handled by the caller; que is a variable here")
                && !wide("// Timezone: Brasília is UTC-3, handled by the caller.")
                && !wide("// Read the file and return the parsed rows"),
        ),
        (
            "pt-comment: GB-282 severity, narrow hit is ERROR, wide-only hit is WARNING, English is none",
            {
                use crate::rule::Severity::{Error, Warning};
                let sev = |line: &str| extract_comment("rs", line).and_then(portuguese_severity);
                sev("// função para validar o token do usuário") == Some(Error)
                    && sev("// arquivo que contém os dados de entrada") == Some(Warning)
                    && sev("// Timezone: Brasília is UTC-3, handled by the caller.").is_none()
            },
        ),
        (
            "pt-comment: mixed comment with 2+ Portuguese function words stays red",
            pt("// Timezone: Brasília, mas a função não trata o fuso"),
        ),
    ]
}
