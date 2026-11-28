//! Which lines of a Rust file are test code. An attribute covers only the item it annotates; a
//! file the lexer cannot read has no test lines, so every rule keeps judging it.

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// Inclusive 1-based line ranges.
#[derive(Default)]
pub struct TestLines(Vec<(usize, usize)>);

impl TestLines {
    pub fn contains(&self, line: usize) -> bool {
        self.0.iter().any(|(a, b)| (*a..=*b).contains(&line))
    }

    pub fn of(source: &str) -> Self {
        let mut found = Vec::new();
        if let Ok(stream) = source.parse::<TokenStream>() {
            walk(stream, &mut found);
        }
        Self(found)
    }
}

/// `test`, `<path>::test`, `cfg(test)` or `cfg(all(test, ..))`.
fn is_test_attribute(body: TokenStream) -> bool {
    let tokens: Vec<TokenTree> = body.into_iter().collect();
    match tokens.as_slice() {
        [TokenTree::Ident(name), TokenTree::Group(args)] if name == "cfg" => {
            is_test_predicate(args.stream())
        }
        _ => {
            let path: Vec<&TokenTree> = tokens
                .iter()
                .take_while(|t| !matches!(t, TokenTree::Group(_)))
                .collect();
            matches!(path.last(), Some(TokenTree::Ident(last)) if last == "test")
        }
    }
}

fn is_test_predicate(predicate: TokenStream) -> bool {
    let tokens: Vec<TokenTree> = predicate.into_iter().collect();
    match tokens.as_slice() {
        [TokenTree::Ident(only)] => only == "test",
        [TokenTree::Ident(all), TokenTree::Group(args)] if all == "all" => {
            let parts: Vec<TokenTree> = args.stream().into_iter().collect();
            parts
                .split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                .any(|part| matches!(part, [TokenTree::Ident(i)] if i == "test"))
        }
        _ => false,
    }
}

/// How the annotated item ends.
#[derive(Clone, Copy, PartialEq)]
enum End {
    /// `fn`, `mod`, `impl`..: a brace block or a semicolon.
    Block,
    /// `use`, `const`, `let`..: the semicolon, braces inside belong to the item.
    Semicolon,
    /// Fields, variants, arms, expressions: also a comma.
    Member,
}

fn end_kind(rest: &[TokenTree]) -> End {
    for token in rest.iter().take(6) {
        if let TokenTree::Ident(word) = token {
            match word.to_string().as_str() {
                "fn" | "mod" | "impl" | "struct" | "enum" | "trait" | "union" | "macro_rules" => {
                    return End::Block;
                }
                "use" | "static" | "type" | "let" => return End::Semicolon,
                _ => {}
            }
        }
    }
    match rest.first() {
        Some(TokenTree::Ident(word)) if word == "const" => End::Semicolon,
        _ => End::Member,
    }
}

fn walk(stream: TokenStream, found: &mut Vec<(usize, usize)>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < tokens.len() {
        if let TokenTree::Punct(hash) = &tokens[i] {
            if hash.as_char() == '#' {
                let inner =
                    matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                let at = i + 1 + usize::from(inner);
                if let Some(TokenTree::Group(g)) = tokens.get(at) {
                    if g.delimiter() == Delimiter::Bracket && is_test_attribute(g.stream()) {
                        let start = hash.span().start().line;
                        if inner {
                            // `#![cfg(test)]` covers the rest of the enclosing block or file.
                            let end = tokens.last().map_or(start, |t| t.span().end().line);
                            found.push((start, end));
                            return;
                        }
                        let rest = &tokens[at + 1..];
                        let (end, used) = item_end(rest, start);
                        found.push((start, end));
                        i = at + 1 + used;
                        continue;
                    }
                    i = at + 1;
                    continue;
                }
            }
        }
        if let TokenTree::Group(g) = &tokens[i] {
            walk(g.stream(), found);
        }
        i += 1;
    }
}

/// Last line of the item at the start of `rest` and the number of tokens it spans.
fn item_end(mut rest: &[TokenTree], start: usize) -> (usize, usize) {
    let mut skipped = 0;
    // Further attributes of the same item.
    while let [TokenTree::Punct(p), TokenTree::Group(g), tail @ ..] = rest {
        if p.as_char() != '#' || g.delimiter() != Delimiter::Bracket {
            break;
        }
        rest = tail;
        skipped += 2;
    }
    let kind = end_kind(rest);
    let mut last = start;
    for (n, token) in rest.iter().enumerate() {
        last = token.span().end().line;
        let done = match token {
            TokenTree::Punct(p) if p.as_char() == ';' => true,
            TokenTree::Punct(p) if p.as_char() == ',' => kind == End::Member,
            TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => kind != End::Semicolon,
            _ => false,
        };
        if done {
            return (last, skipped + n + 1);
        }
    }
    (last, skipped + rest.len())
}
