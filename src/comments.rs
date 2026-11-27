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

/// The narrow detector (every comment it flags was already flagged by 4.36.0). It still decides
/// `DOC-LANGUAGE-EN` on Markdown prose; source comments are judged by the wide one.
pub fn is_portuguese_comment(comment: &str) -> bool {
    detect_portuguese(comment, false)
}

/// GB-282(a) wide detector: the narrow one plus a second tier of Portuguese function words and
/// prepositions (see `wide_signals`).
pub fn is_portuguese_comment_wide(comment: &str) -> bool {
    detect_portuguese(comment, true)
}

/// Severity of a comment under CODE-NO-PORTUGUESE-COMMENTS: ERROR for anything the wide detector
/// flags (GB-287, promoted from WARNING in 4.41.0), `None` for English.
pub fn portuguese_severity(comment: &str) -> Option<crate::rule::Severity> {
    is_portuguese_comment_wide(comment).then_some(crate::rule::Severity::Error)
}

/// First-tier Portuguese function words (unaccented).
static PT_STOPWORDS: &[&str] = &[
    "para", "com", "como", "pelo", "pela", "pelos", "pelas", "este", "esta", "esse", "essa",
    "aquele", "aquela", "quando", "onde", "porque", "uma", "mais",
];

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
    let cleaned_no_code = strip_backticked(&cleaned);

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
    //    GB-282(a) widens the recall (`wide`, see `wide_signals`): the second tier holds
    //    Portuguese function words (a comment such as `// arquivo que contém os dados` carried
    //    one accented word and nothing else the old list knew). The threshold stays at two
    //    signals per comment, so a single borrowed word or a proper noun never fires.
    let sw_count = words
        .iter()
        .filter(|w| PT_STOPWORDS.iter().any(|&sw| sw == **w))
        .count();

    let wide_count = if wide {
        wide_signals(&strip_backticked(comment))
    } else {
        0
    };

    sw_count + wide_count + accented_words >= 2
}

/// Drops the text between backticks (code symbols are not prose).
fn strip_backticked(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_backtick = false;
    for ch in text.chars() {
        if ch == '`' {
            in_backtick = !in_backtick;
        } else if !in_backtick {
            out.push(ch);
        }
    }
    out
}

/// A token can be a Portuguese function word only if its original case reads like prose: short
/// all-caps tokens (`DOS`, `DAS`, `ELE`) and capitalised tokens after the first word (surnames,
/// product names) are English identifiers or proper nouns (GB-287). An all-caps token of five or
/// more letters is emphasis (`SEMPRE`), not an acronym that collides with an English one.
pub(crate) fn is_prose_case(token: &str, is_initial: bool) -> bool {
    let mut chars = token.chars();
    let Some(initial) = chars.next() else {
        return false;
    };
    if !initial.is_uppercase() {
        return true;
    }
    let length = token.chars().count();
    if length > 1 && !token.chars().any(char::is_lowercase) {
        return length >= 5;
    }
    is_initial
}

/// One whitespace token of a comment, trimmed of punctuation.
struct Token<'a> {
    word: &'a str,
    /// Punctuation (or a symbol-only token such as a dash) separates it from the next word.
    ends_clause: bool,
}

fn clause_tokens(text: &str) -> Vec<Token<'_>> {
    let mut out: Vec<Token<'_>> = Vec::new();
    for raw in text.split_whitespace() {
        let word = raw.trim_matches(|c: char| !c.is_alphanumeric());
        if word.is_empty() {
            if let Some(last) = out.last_mut() {
                last.ends_clause = true;
            }
            continue;
        }
        if raw.starts_with(['(', '[', '{']) {
            if let Some(last) = out.last_mut() {
                last.ends_clause = true;
            }
        }
        out.push(Token {
            word,
            ends_clause: !raw.ends_with(|c: char| c.is_alphanumeric()),
        });
    }
    out
}

/// A `de`, `da` or `em` followed by a word, at token `index` of the comment.
struct Preposition {
    index: usize,
    word: &'static str,
    lowercase_follower: bool,
}

fn find_prepositions(tokens: &[Token<'_>]) -> Vec<Preposition> {
    // Brand names are never the noun that follows a preposition.
    static BRANDS: &[&str] = &[
        "sumænimá",
        "sumaenima",
        "stênio",
        "stenio",
        "mnemocine",
        "pokémon",
        "pokemon",
        "sérgio",
    ];
    // Latin and French loanwords English borrows together with `de`.
    static LOANWORDS: &[&str] = &["facto", "jure", "novo", "luxe", "rigueur"];

    let initial = tokens
        .iter()
        .position(|t| t.word.chars().any(char::is_alphabetic));
    let mut out = Vec::new();
    for (index, pair) in tokens.windows(2).enumerate() {
        let (head, next) = (pair[0].word, pair[1].word);
        let is_word = next.chars().count() >= 3 && next.chars().all(char::is_alphabetic);
        let lowered_next = next.to_lowercase();
        if !is_word
            || BRANDS.iter().any(|b| lowered_next.contains(b))
            || LOANWORDS.iter().any(|&l| l == lowered_next)
            || !is_prose_case(head, initial == Some(index))
        {
            continue;
        }
        let lowered = head.to_lowercase();
        if let Some(&word) = ["de", "da", "em"].iter().find(|&&p| p == lowered) {
            out.push(Preposition {
                index,
                word,
                lowercase_follower: !next.chars().any(char::is_uppercase),
            });
        }
    }
    out
}

/// The Portuguese `de X de Y` construction (`Filtro de Tipo de Carta`, `de laser de plasma`): two
/// prepositions at most two words apart inside one clause, at least one of them `de` or `da`
/// (`em` alone is the CSS unit).
fn has_preposition_chain(tokens: &[Token<'_>], prepositions: &[Preposition]) -> bool {
    prepositions.windows(2).any(|pair| {
        let (first, second) = (&pair[0], &pair[1]);
        (2..=3).contains(&(second.index - first.index))
            && (first.word != "em" || second.word != "em")
            && !tokens[first.index..second.index]
                .iter()
                .any(|t| t.ends_clause)
    })
}

/// The second-tier signals of the wide detector, judged on the original case (GB-287):
/// - each DISTINCT wide function word counts once (`pop que, push que` is one signal);
/// - each DISTINCT preposition (`de`, `da`, `em`) before a lowercase word counts once;
/// - before a capitalised word or an acronym (`em RAM`, `de Teclado`) it counts only when the
///   comment also holds a Portuguese function word, so `da Vinci` alone is not evidence;
/// - a `de X de Y` chain is two signals on its own.
fn wide_signals(text: &str) -> usize {
    static PT_STOPWORDS_WIDE: &[&str] = &[
        "que", "dos", "das", "seus", "suas", "mas", "sem", "sobre", "entre", "cada", "isso",
        "aqui", "pode", "podem", "deve", "devem", "fazer", "antes", "depois", "ainda", "apenas",
        "todos", "todas", "nosso", "nossa", "mesmo", "sempre", "nunca", "arquivo", "arquivos",
        "ele", "ela", "eles", "elas", "pois", "seja", "foram", "estava", "tambem", "entao", "voce",
        "sera",
    ];

    let mut found: std::collections::HashSet<&str> = std::collections::HashSet::new();

    let words = text
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.chars().any(char::is_alphabetic));
    for (index, word) in words.enumerate() {
        if !is_prose_case(word, index == 0) {
            continue;
        }
        let lowered = word.to_lowercase();
        if let Some(&sw) = PT_STOPWORDS_WIDE.iter().find(|&&sw| sw == lowered) {
            found.insert(sw);
        }
    }

    let tokens = clause_tokens(text);
    // A standalone first-tier word (the `com` of `example.com` is not one).
    let function_word = !found.is_empty()
        || tokens
            .iter()
            .any(|t| PT_STOPWORDS.iter().any(|&sw| sw == t.word.to_lowercase()));

    let prepositions = find_prepositions(&tokens);
    let counted: std::collections::HashSet<&str> = prepositions
        .iter()
        .filter(|p| p.lowercase_follower || function_word)
        .map(|p| p.word)
        .collect();
    let chain = if has_preposition_chain(&tokens, &prepositions) {
        2
    } else {
        0
    };

    found.len() + counted.len().max(chain)
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
    fn fixtures() {
        crate::testkit::assert_cases(
            super::self_test_cases()
                .into_iter()
                .map(|(name, ok)| (name.to_string(), ok))
                .collect(),
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
            "pt-comment: GB-287 English with acronyms, surnames or a repeated token stays green",
            [
                "// Convert DOS line endings, as DOS tools expect CRLF",
                "// MS-DOS 8.3 names: DOS reserves CON and NUL",
                "// acquire sem before the write, release sem after",
                "// DAS and NAS volumes: DAS is mounted first",
                "// ELA and ELE are the two register aliases",
                "// ELA register aliases sem in the table",
                "// Map each em value; the em square is 1000 units",
                "// Use de facto defaults, da Vinci layout",
                "// Mas and Dos are the author surnames",
                "// Que is short for queue: pop que, push que",
            ]
            .iter()
            .all(|line| !wide(line)),
        ),
        (
            "pt-comment: GB-287 two distinct wide words stay red, a capitalised first word counts",
            wide("// Isso pode quebrar o build")
                && wide("// o job roda sempre, nunca manualmente")
                && !pt("// Isso pode quebrar o build"),
        ),
        (
            "pt-comment: GB-287 two distinct prepositions before lowercase words stay red",
            wide("// backup de dados em disco")
                && wide("// Em caso de falha, reiniciar")
                && wide("// copia o dump antes da troca")
                && !pt("// backup de dados em disco"),
        ),
        (
            "pt-comment: GB-287 a preposition before a Title Case word or acronym counts next to a function word",
            [
                "// Deploy da API para o host",
                "// Atalhos de Teclado para desengatar",
                "// Agora enviar todos os chunks em RAM",
                "// Em Android retorna imediatamente sem popup",
                "// sem isto o bulk em JSONL falha",
            ]
            .iter()
            .all(|line| wide(line) && !pt(line)),
        ),
        (
            "pt-comment: GB-287 a `de X de Y` chain is red on its own",
            [
                "// Filtro de Tipo de Carta",
                "// Menus Contextuais de Metadados em Massa",
                "// Oscilador Puro da Camada de Shepard",
                "// Disparo de laser de plasma duplo",
                "// Instalador de Git Hooks de Alta Performance",
            ]
            .iter()
            .all(|line| wide(line) && !pt(line)),
        ),
        (
            "pt-comment: GB-287 a long all-caps word is emphasis and counts",
            wide("// o layout garante que a barra SEMPRE existe"),
        ),
        (
            "pt-comment: GB-287 English with names, loanwords, URLs and CSS units stays green",
            [
                "// The de Bruijn index, then the em Value table",
                "// Tour de France, de Gaulle terminal",
                "// Tour de France and Charles de Gaulle",
                "// Map em Value to em Square",
                "// Both de facto and de jure standards",
                "// See example.com for the Tour de France",
            ]
            .iter()
            .all(|line| !wide(line)),
        ),
        (
            "pt-comment: GB-287 severity, narrow and wide-only hits are ERROR, English is none",
            {
                use crate::rule::Severity::Error;
                let sev = |line: &str| extract_comment("rs", line).and_then(portuguese_severity);
                sev("// função para validar o token do usuário") == Some(Error)
                    && sev("// arquivo que contém os dados de entrada") == Some(Error)
                    && sev("// Timezone: Brasília is UTC-3, handled by the caller.").is_none()
            },
        ),
        (
            "pt-comment: mixed comment with 2+ Portuguese function words stays red",
            pt("// Timezone: Brasília, mas a função não trata o fuso"),
        ),
    ]
}
