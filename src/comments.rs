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
        "rs" | "ts" | "tsx" | "js" | "jsx" | "c" | "cpp" | "h" | "hpp" | "go" | "java"
        | "kt" | "swift" | "dart" | "zig" | "cs" | "php" | "css" | "scss" => {
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

/// Checks if a comment contains Portuguese natural language.
pub fn is_portuguese_comment(comment: &str) -> bool {
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

    // 2. Portuguese accented letters (strong, definitive indicator)
    for c in cleaned.chars() {
        if matches!(
            c,
            'á' | 'à' | 'â' | 'ã' | 'é' | 'ê' | 'í' | 'ó' | 'ô' | 'õ' | 'ú' | 'ç'
        ) {
            return true;
        }
    }

    // 3. Unambiguous Portuguese grammatical words & technical terms (unaccented forms)
    static UNAMBIGUOUS_PT_WORDS: &[&str] = &[
        "funcao", "funcoes", "padrao", "padroes", "configuracao", "configuracoes",
        "atencao", "observacao", "validacao", "validacoes", "requisicao", "requisicoes",
        "atualizacao", "autenticacao", "conexao", "conexoes", "criacao", "edicao",
        "alteracao", "resposta", "respostas", "leitora", "servidor", "mensagem", "mensagens",
        "resolvido", "resolvida", "exclusao", "permissao", "permissoes", "obrigatorio",
        "obrigatoria", "invalido", "invalida", "nao", "sao", "estao", "verificar", "garantir",
        "usuario", "usuarios", "relatorio", "relatorios", "tabela", "tabelas"
    ];

    let words: Vec<&str> = cleaned
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .collect();

    for w in &words {
        if UNAMBIGUOUS_PT_WORDS.iter().any(|&pt| pt == *w) {
            return true;
        }
    }

    // 4. Multiple Portuguese stop-words (>= 2)
    static PT_STOPWORDS: &[&str] = &[
        "para", "com", "como", "pelo", "pela", "pelos", "pelas", "este", "esta",
        "esse", "essa", "aquele", "aquela", "quando", "onde", "porque", "uma", "mais"
    ];

    let sw_count = words
        .iter()
        .filter(|w| PT_STOPWORDS.iter().any(|&sw| sw == **w))
        .count();

    sw_count >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_comment_c_style() {
        assert_eq!(extract_comment("rs", "// hello world"), Some("hello world"));
        assert_eq!(extract_comment("rs", "/// doc comment"), Some("doc comment"));
        assert_eq!(extract_comment("rs", "//! inner doc"), Some("inner doc"));
        assert_eq!(extract_comment("ts", "let x = 1; // inline comment"), Some("inline comment"));
        assert_eq!(extract_comment("js", "const url = \"https://foo.bar\";"), None);
        assert_eq!(extract_comment("rs", "/* block comment */"), Some("block comment"));
        assert_eq!(extract_comment("rs", " * list in block"), Some("list in block"));
    }

    #[test]
    fn test_extract_comment_sql() {
        assert_eq!(extract_comment("sql", "-- table schema"), Some("table schema"));
        assert_eq!(extract_comment("sql", "SELECT * FROM users; -- get all"), Some("get all"));
    }

    #[test]
    fn test_extract_comment_script() {
        assert_eq!(extract_comment("sh", "#!/usr/bin/env bash"), None);
        assert_eq!(extract_comment("sh", "# run backup now"), Some("run backup now"));
        assert_eq!(extract_comment("py", "def foo(): # python comment"), Some("python comment"));
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

        // English comments (should pass)
        assert!(!is_portuguese_comment("Initialize the database connection pool"));
        assert!(!is_portuguese_comment("Handle incoming WebSocket frame"));
        assert!(!is_portuguese_comment("Returns status code 200 on success"));
        assert!(!is_portuguese_comment("Query Scryfall for Pokémon card prices"));
        assert!(!is_portuguese_comment("Sumænimá Hub audio stream pipeline with Stênio kernel"));
    }
}
