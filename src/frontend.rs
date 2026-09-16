use crate::baseline::Whitelist;
use crate::engine::Violation;
use crate::rule::Severity;
use std::path::Path;

pub fn audit_frontend_file(
    path: &Path,
    content: &str,
    whitelist: &Whitelist,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let path_str = path.to_string_lossy().to_string();
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

    // ── 1. FRONT-AUDIO: AudioWorklet Firefox Compatibility ──────────────
    if file_name == "worklet-processor.js" {
        if content.contains("globalThis.sampleRate") || content.contains("typeof sampleRate !== 'undefined'") {
            if !whitelist.is_ignored(&path_str, "FRONT-AUDIO", "globalThis.sampleRate") {
                violations.push(Violation {
                    rule_id: "FRONT-AUDIO".to_string(),
                    rule_name: "AudioWorklet Firefox Compatibility".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "globalThis.sampleRate".to_string(),
                    message: "AudioWorklet no Firefox quebra com globalThis.sampleRate; utilize this.sampleRate no construtor.".to_string(),
                    suggestion: Some("Substitua globalThis.sampleRate por this.sampleRate no constructor.".to_string()),
                });
            }
        }
        if !content.contains("this._sampleRate") {
            if !whitelist.is_ignored(&path_str, "FRONT-AUDIO", "this._sampleRate") {
                violations.push(Violation {
                    rule_id: "FRONT-AUDIO".to_string(),
                    rule_name: "AudioWorklet SampleRate Storage".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "this._sampleRate".to_string(),
                    message: "Armazene this.sampleRate em this._sampleRate no construtor para resiliência de captura.".to_string(),
                    suggestion: Some("Declare 'this._sampleRate = this.sampleRate;' no constructor do AudioWorkletProcessor.".to_string()),
                });
            }
        }
    }

    // ── 2. FRONT-CLEANUP: Higiene de Eventos e Timers ────────────────────
    if path_str.ends_with(".tsx") || path_str.ends_with(".ts") {
        if content.contains("addEventListener(") && !content.contains("removeEventListener(") {
            if !whitelist.is_ignored(&path_str, "FRONT-CLEANUP", "addEventListener") {
                violations.push(Violation {
                    rule_id: "FRONT-CLEANUP".to_string(),
                    rule_name: "EventListener sem Cleanup".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "addEventListener sem removeEventListener".to_string(),
                    message: "Componente adiciona event listener sem função de remoção no retorno do useEffect (vazamento de memória).".to_string(),
                    suggestion: Some("Retorne uma função de cleanup no useEffect chamando removeEventListener(evento, handler).".to_string()),
                });
            }
        }

        if content.contains("setInterval(") && !content.contains("clearInterval(") {
            if !whitelist.is_ignored(&path_str, "FRONT-CLEANUP", "setInterval") {
                violations.push(Violation {
                    rule_id: "FRONT-CLEANUP".to_string(),
                    rule_name: "Timer setInterval sem Cleanup".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "setInterval sem clearInterval".to_string(),
                    message: "Timer setInterval sem clearInterval correspondente na desmontagem do componente.".to_string(),
                    suggestion: Some("Guarde o ID do timer e retorne '() => clearInterval(timerId)' no cleanup do useEffect.".to_string()),
                });
            }
        }
    }

    // ── 3. FRONT-WAKELOCK: Liberação de WakeLock ─────────────────────────
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts")) && content.contains("navigator.wakeLock.request(") {
        if !content.contains(".release()") && !content.contains("wakeLock.release") {
            if !whitelist.is_ignored(&path_str, "FRONT-WAKELOCK", "wakeLock") {
                violations.push(Violation {
                    rule_id: "FRONT-WAKELOCK".to_string(),
                    rule_name: "Vazamento de WakeLock".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "wakeLock.request sem release()".to_string(),
                    message: "Requisição de wakeLock de tela deve liberar o lock no cleanup do hook.".to_string(),
                    suggestion: Some("Invoque 'wakeLock.release()' dentro da função de cleanup do hook para liberar a tela.".to_string()),
                });
            }
        }
    }

    // ── 4. FRONT-GLASSMORPHIC: Divisórias Soltas vs Caixas Glassmorphic ──
    if path_str.ends_with(".tsx") && (content.contains("<hr ") || content.contains("<hr/>")) {
        if !whitelist.is_ignored(&path_str, "FRONT-GLASSMORPHIC", "<hr") {
            violations.push(Violation {
                rule_id: "FRONT-GLASSMORPHIC".to_string(),
                rule_name: "Lei de Separação Glassmorphic".to_string(),
                severity: Severity::Warning,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "<hr /> avulso detectado".to_string(),
                message: "No DNA Sumænimá, evite linhas divisórias avulsas (<hr>); isole seções em cards .sm-glass.".to_string(),
                suggestion: Some("Remova a tag <hr /> e separe os blocos de conteúdo utilizando cartões com a classe .sm-glass.".to_string()),
            });
        }
    }

    // ── 5. FRONT-HEX: Cores Hexadecimais Arbitrárias no Tailwind (Lei 24) ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && !path_str.ends_with("styles.ts")
        && !path_str.contains("/themes/")
    {
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("bg-[#") || line.contains("text-[#") || line.contains("border-[#") {
                if !whitelist.is_ignored(&path_str, "FRONT-HEX", line) {
                    violations.push(Violation {
                        rule_id: "FRONT-HEX".to_string(),
                        rule_name: "Cor Hex Arbitrária no Tailwind".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "Lei 24 do AGENTS.md: Evite classes com hex arbitrário solto; utilize tokens de design system M3.".to_string(),
                        suggestion: Some("Substitua classes hex (ex: bg-[#...]) por tokens M3: bg-surface, text-primary, border-outline.".to_string()),
                    });
                }
            }
        }
    }

    violations
}
