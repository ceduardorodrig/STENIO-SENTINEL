//! A small shell reader: enough to know which program each part of a command line runs, with
//! which arguments, redirections, here-documents and substitutions. It is not a shell: what it
//! cannot resolve stays as written.

/// A `$` that came from single quotes: it is text, not a variable.
pub const LITERAL_DOLLAR: char = '\u{1}';
/// The word text that stands for a substitution.
pub const SUBST: &str = "$(…)";

#[derive(Debug, Default, Clone)]
pub struct Simple {
    pub words: Vec<String>,
    /// `(operator, target)`; the operator keeps no descriptor number.
    pub redirects: Vec<(String, String)>,
    /// Here-document and here-string text fed to this command.
    pub input: String,
    /// The command texts of `$(...)`, backticks and `<(...)` found in its words.
    pub substitutions: Vec<String>,
    /// Its output goes to the next command.
    pub piped: bool,
}

struct Reader {
    chars: Vec<char>,
    at: usize,
}

impl Reader {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        self.at += 1;
        c
    }

    /// The text up to the parenthesis that closes one already consumed.
    fn balanced(&mut self) -> String {
        let (mut depth, mut out, mut quote) = (1, String::new(), None::<char>);
        while let Some(c) = self.bump() {
            match (quote, c) {
                (None, '\'' | '"') => quote = Some(c),
                (Some(q), c) if c == q => quote = None,
                (None, '(') => depth += 1,
                (None, ')') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                (_, '\\') if quote != Some('\'') => {
                    out.push(c);
                    if let Some(n) = self.bump() {
                        out.push(n);
                    }
                    continue;
                }
                _ => {}
            }
            out.push(c);
        }
        out
    }

    fn until(&mut self, end: char) -> String {
        let mut out = String::new();
        while let Some(c) = self.bump() {
            if c == end {
                break;
            }
            if c == '\\'
                && let Some(n) = self.bump()
            {
                out.push(n);
                continue;
            }
            out.push(c);
        }
        out
    }
}

#[derive(Default)]
struct State {
    done: Vec<Simple>,
    current: Simple,
    word: Option<String>,
    /// The redirection operator that waits for its target.
    redirect: Option<String>,
    /// Here-document delimiters waiting for the next line: `(command index, word, strip tabs)`.
    pending: Vec<(usize, String, bool)>,
}

impl State {
    fn push(&mut self, c: char) {
        self.word.get_or_insert_default().push(c);
    }

    fn end_word(&mut self) {
        let Some(word) = self.word.take() else {
            return;
        };
        match self.redirect.take() {
            Some(op) if op == "<<" || op == "<<-" => {
                self.pending.push((self.done.len(), word, op == "<<-"));
            }
            Some(op) if op == "<<<" => {
                self.current.input.push_str(&word);
                self.current.input.push('\n');
            }
            Some(op) => self.current.redirects.push((op, word)),
            None => self.current.words.push(word),
        }
    }

    fn end_command(&mut self, piped: bool) {
        self.end_word();
        let mut done = std::mem::take(&mut self.current);
        done.piped = piped;
        let empty = done.words.is_empty()
            && done.redirects.is_empty()
            && done.substitutions.is_empty()
            && !self.pending.iter().any(|p| p.0 == self.done.len());
        if !empty {
            self.done.push(done);
        }
    }
}

fn substitution(state: &mut State, text: String) {
    state.current.substitutions.push(text);
    state.word.get_or_insert_default().push_str(SUBST);
}

fn double_quoted(reader: &mut Reader, state: &mut State) {
    state.word.get_or_insert_default();
    while let Some(c) = reader.bump() {
        match c {
            '"' => break,
            '\\' => match reader.bump() {
                Some(n @ ('"' | '\\' | '`')) => state.push(n),
                Some('$') => state.push(LITERAL_DOLLAR),
                Some('\n') => {}
                Some(n) => {
                    state.push('\\');
                    state.push(n);
                }
                None => {}
            },
            '$' if reader.peek() == Some('(') => {
                reader.at += 1;
                let inner = reader.balanced();
                substitution(state, inner);
            }
            '`' => {
                let inner = reader.until('`');
                substitution(state, inner);
            }
            c => state.push(c),
        }
    }
}

fn here_bodies(reader: &mut Reader, state: &mut State) {
    for (index, word, strip) in std::mem::take(&mut state.pending) {
        let mut body = String::new();
        while reader.peek().is_some() {
            let line = reader.until_line();
            let seen = if strip {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            if seen == word {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        match state.done.get_mut(index) {
            Some(command) => command.input.push_str(&body),
            None => state.current.input.push_str(&body),
        }
    }
}

impl Reader {
    fn until_line(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.bump() {
            if c == '\n' {
                break;
            }
            out.push(c);
        }
        out
    }
}

fn redirect(reader: &mut Reader, state: &mut State, first: char) {
    // A word made of digits right before the operator is the descriptor.
    if state
        .word
        .as_ref()
        .is_some_and(|w| w.chars().all(|c| c.is_ascii_digit()))
    {
        state.word = None;
    }
    state.end_word();
    let mut op = first.to_string();
    while let Some(c) = reader.peek() {
        let more = match (op.as_str(), c) {
            (">", '>' | '|' | '&') | ("<", '<' | '>' | '&') | ("<<", '<' | '-') => true,
            (">>", '&') => true,
            _ => false,
        };
        if !more {
            break;
        }
        op.push(c);
        reader.at += 1;
    }
    state.redirect = Some(op);
}

/// Splits a command text into simple commands, in order.
pub fn parse(text: &str) -> Vec<Simple> {
    let mut reader = Reader {
        chars: text.chars().collect(),
        at: 0,
    };
    let mut state = State::default();
    while let Some(c) = reader.bump() {
        match c {
            '\\' => match reader.bump() {
                Some('\n') | None => {}
                Some('$') => state.push(LITERAL_DOLLAR),
                Some(n) => state.push(n),
            },
            '\'' => {
                state.word.get_or_insert_default();
                while let Some(n) = reader.bump() {
                    if n == '\'' {
                        break;
                    }
                    state.push(if n == '$' { LITERAL_DOLLAR } else { n });
                }
            }
            '"' => double_quoted(&mut reader, &mut state),
            '`' => {
                let inner = reader.until('`');
                substitution(&mut state, inner);
            }
            '$' if reader.peek() == Some('(') => {
                reader.at += 1;
                let inner = reader.balanced();
                substitution(&mut state, inner);
            }
            '$' if reader.peek() == Some('\'') => {}
            '<' | '>' if reader.peek() == Some('(') => {
                reader.at += 1;
                let inner = reader.balanced();
                substitution(&mut state, inner);
            }
            '#' if state.word.is_none() => {
                while reader.peek().is_some_and(|n| n != '\n') {
                    reader.at += 1;
                }
            }
            ' ' | '\t' | '\r' => state.end_word(),
            '\n' => {
                state.end_command(false);
                here_bodies(&mut reader, &mut state);
            }
            '&' if reader.peek() == Some('>') => {
                reader.at += 1;
                redirect(&mut reader, &mut state, '>');
            }
            ';' | '&' => {
                if reader.peek() == Some(c) {
                    reader.at += 1;
                }
                state.end_command(false);
            }
            '|' => {
                let or = reader.peek() == Some('|');
                if or || reader.peek() == Some('&') {
                    reader.at += 1;
                }
                state.end_command(!or);
            }
            '(' | ')' => state.end_command(false),
            '<' | '>' => redirect(&mut reader, &mut state, c),
            c => state.push(c),
        }
    }
    state.end_command(false);
    here_bodies(&mut reader, &mut state);
    state.done
}
