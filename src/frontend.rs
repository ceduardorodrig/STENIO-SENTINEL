use crate::baseline::{is_common_ignored_path, Whitelist};
use crate::engine::Violation;
use crate::rule::Severity;
use std::path::Path;

pub fn audit_frontend_file(path: &Path, content: &str, whitelist: &Whitelist) -> Vec<Violation> {
    let mut violations = Vec::new();
    let path_str = path.to_string_lossy().to_string();
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

    // ── 1. FRONT-AUDIO: AudioWorklet Firefox Compatibility ──────────────
    if file_name == "worklet-processor.js" {
        if content.contains("globalThis.sampleRate")
            || content.contains("typeof sampleRate !== 'undefined'")
        {
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
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && content.contains("navigator.wakeLock.request(")
    {
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

    // ── 6. FRONT-TOKEN-PALETTE: Cores Cinzas Genéricas Proibidas ──────────
    if (path_str.contains("components/") || path_str.contains("pages/"))
        && (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
    {
        for (line_idx, line) in content.lines().enumerate() {
            let has_generic_gray = line.contains("bg-gray-")
                || line.contains("bg-slate-")
                || line.contains("bg-neutral-")
                || line.contains("text-gray-")
                || line.contains("text-slate-")
                || line.contains("text-neutral-")
                || line.contains("border-gray-")
                || line.contains("border-slate-")
                || line.contains("border-neutral-");

            if has_generic_gray && !whitelist.is_ignored(&path_str, "FRONT-TOKEN-PALETTE", line) {
                violations.push(Violation {
                    rule_id: "FRONT-TOKEN-PALETTE".to_string(),
                    rule_name: "Uso de Cinzas Genéricos do Tailwind".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "No Sumænimá Hub, evite cinzas genéricos (gray, slate, neutral). Utilize os tokens canônicos de superfície (bg-surface-950/900/800, text-on-surface, border-outline).".to_string(),
                    suggestion: Some("Substitua bg-gray/slate por bg-surface-950 (fundo), bg-surface-900 (cards), bg-surface-800 (hover) e text-on-surface.".to_string()),
                });
            }
        }
    }

    // ── 7. FRONT-NO-ANY: Proibição de 'any' em TypeScript ─────────────────
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && !path_str.ends_with(".d.ts")
        && !path_str.contains("vite-env.d.ts")
    {
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            let has_any = line.contains("as any")
                || line.contains(": any")
                || line.contains("<any>")
                || line.contains("Array<any>");

            if has_any && !whitelist.is_ignored(&path_str, "FRONT-NO-ANY", line) {
                violations.push(Violation {
                    rule_id: "FRONT-NO-ANY".to_string(),
                    rule_name: "Tipagem 'any' Proibida no Frontend".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: trimmed.to_string(),
                    message: "O uso de 'any' quebra a segurança estática entre o frontend e o backend Rust. Utilize tipos concretos de src/types/ ou execute 'stenio --typegen'.".to_string(),
                    suggestion: Some("Substitua 'any' por uma interface tipada concreta em src/types/ ou use 'unknown' com validação.".to_string()),
                });
            }
        }
    }

    // ── 8. FRONT-A11Y-BUTTON: Acessibilidade de Botões sem Texto ──────────
    if path_str.ends_with(".tsx") {
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("<button")
                && (line.contains("Icon") || line.contains("<svg"))
                && !line.contains("aria-label")
                && !line.contains("title=")
            {
                if !whitelist.is_ignored(&path_str, "FRONT-A11Y-BUTTON", line) {
                    violations.push(Violation {
                        rule_id: "FRONT-A11Y-BUTTON".to_string(),
                        rule_name: "Botão de Ícone sem aria-label".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "Botões de ação contendo apenas ícones necessitam de 'aria-label' ou 'title' para acessibilidade de leitores de tela.".to_string(),
                        suggestion: Some("Adicione a propriedade aria-label=\"Descrição da ação\" ou title=\"...\" na tag <button>.".to_string()),
                    });
                }
            }
        }
    }

    // ── 9. FRONT-AUDIO-WASM: Proibição de createScriptProcessor Obsoleto ───
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts") || path_str.ends_with(".js"))
        && content.contains("createScriptProcessor")
    {
        if !whitelist.is_ignored(&path_str, "FRONT-AUDIO-WASM", "createScriptProcessor") {
            violations.push(Violation {
                rule_id: "FRONT-AUDIO-WASM".to_string(),
                rule_name: "Uso de createScriptProcessor Obsoleto".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "createScriptProcessor detectado".to_string(),
                message: "createScriptProcessor executa processamento de áudio na thread principal de renderização. Utilize AudioWorkletNode e wasm-audio-dsp.".to_string(),
                suggestion: Some("Migre para AudioWorkletNode acoplado ao módulo WebAssembly em wasm-audio.".to_string()),
            });
        }
    }

    // ── 10. FRONT-COMPONENT-BUDGET: Alerta de Componentes Monolíticos (>400 Linhas) ──
    if path_str.ends_with(".tsx") && !path_str.ends_with("App.tsx") && !path_str.contains("data/") {
        let total_lines = content.lines().count();
        if total_lines > 400 && !whitelist.is_ignored(&path_str, "FRONT-COMPONENT-BUDGET", "") {
            violations.push(Violation {
                rule_id: "FRONT-COMPONENT-BUDGET".to_string(),
                rule_name: "Componente Monolítico Excessivo (>400 Linhas)".to_string(),
                severity: Severity::Warning,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: format!("Total de linhas: {}", total_lines),
                message: format!("O componente possui {} linhas, excedendo o limite recomendado de 400 linhas. Modelos de IA têm dificuldade de manter componentes monolíticos sem alucinar.", total_lines),
                suggestion: Some("Fatie este componente em submódulos atômicos (Header, Controls, List, Item) dentro de src/components/.".to_string()),
            });
        }
    }

    // ── 11. PERF-GPU-ZERO-REPAINT: Proibição de Transições de Paint em Containers 3D ──
    if path_str.ends_with(".css") || path_str.ends_with(".tsx") {
        for (line_idx, line) in content.lines().enumerate() {
            let has_paint_transition = (line.contains("transition:")
                || line.contains("transition "))
                && (line.contains("box-shadow") || line.contains("backdrop-filter"))
                && (line.contains("magic-card")
                    || line.contains("card-cell")
                    || line.contains("tilt"));

            let has_tsx_paint_anim = line.contains("magic-card-tilt-container")
                && (line.contains("transition-colors") || line.contains("transition-all"));

            if (has_paint_transition || has_tsx_paint_anim)
                && !whitelist.is_ignored(&path_str, "PERF-GPU-ZERO-REPAINT", line)
            {
                violations.push(Violation {
                    rule_id: "PERF-GPU-ZERO-REPAINT".to_string(),
                    rule_name: "Transição em Propriedades de Paint na GPU".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Transições em 'box-shadow', 'backdrop-filter' ou 'background-color' em elementos com tilt/3D forçam rasterização e repaint contínuo da GPU. Utilize pseudo-elementos (::after) com transição de opacidade (0ms CPU/GPU paint).".to_string(),
                    suggestion: Some("Anime a opacidade (opacity: 0 -> 1) de um pseudo-elemento ::after isolado no Compositor da GPU em vez de transicionar sombra/fundo diretamente.".to_string()),
                });
            }
        }
    }

    // ── 12. PERF-NO-LAYOUT-THRASH: Proibição de Leitura Síncrona de DOM em Eventos ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && (content.contains("handleMouseMove")
            || content.contains("onMouseMove")
            || content.contains("pointermove"))
    {
        for (line_idx, line) in content.lines().enumerate() {
            let calls_geometry = line.contains(".getBoundingClientRect()")
                || line.contains(".offsetWidth")
                || line.contains(".offsetHeight");

            // Permite se houver checagem de hover/cache explícita na mesma linha ou arquivo
            let is_cached = line.contains("boundsRef")
                || line.contains("isHoveredRef")
                || line.contains("rectCache")
                || content.contains("boundsRef.current")
                || content.contains("rectCacheRef");

            if calls_geometry
                && !is_cached
                && !whitelist.is_ignored(&path_str, "PERF-NO-LAYOUT-THRASH", line)
            {
                violations.push(Violation {
                    rule_id: "PERF-NO-LAYOUT-THRASH".to_string(),
                    rule_name: "Leitura Síncrona de Geometria em Event Loop".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Chamada a getBoundingClientRect() ou offset* diretamente no fluxo de mouse/pointer dispara Layout Thrashing (recalculo forçado de layout a 1000Hz).".to_string(),
                    suggestion: Some("Faça cache do rect em um useRef no onMouseEnter ou armazene coordenadas em buffer e consuma dentro de requestAnimationFrame.".to_string()),
                });
            }
        }
    }

    // ── 13. PERF-GPU-CONTAINMENT: Exigência de Wrapper .card-cell em Grades Arandu ──
    if path_str.contains("features/arandu/components/") && path_str.ends_with(".tsx") {
        if content.contains("<MagicCard")
            && (content.contains(".map(") || content.contains("cards.map"))
            && !content.contains("card-cell")
            && !content.contains("contain-content")
        {
            if !whitelist.is_ignored(&path_str, "PERF-GPU-CONTAINMENT", "<MagicCard") {
                violations.push(Violation {
                    rule_id: "PERF-GPU-CONTAINMENT".to_string(),
                    rule_name: "Grade de Cards sem Contenção CSS (.card-cell)".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "<MagicCard renderizado em loop sem wrapper card-cell".to_string(),
                    message: "Componente itera sobre coleções renderizando MagicCard sem wrapper '.card-cell'. A falta de contenção CSS força repaints em cascata em cards vizinhos durante hover/tilt 3D.".to_string(),
                    suggestion: Some("Envolva cada card iterado em um container <div className=\"card-cell\"><MagicCard ... /></div>.".to_string()),
                });
            }
        }
    }

    // ── 14. PERF-GPU-WILL-CHANGE: Proibição de will-change Estático em Múltiplos Elementos ──
    if path_str.ends_with(".css") {
        let mut prev_line = "";
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("will-change: transform") || line.contains("will-change: opacity") {
                let is_hover_scoped = prev_line.contains(":hover")
                    || prev_line.contains(".is-hovered")
                    || prev_line.contains(":focus")
                    || line.contains(":hover");

                if !is_hover_scoped
                    && !whitelist.is_ignored(&path_str, "PERF-GPU-WILL-CHANGE", line)
                {
                    violations.push(Violation {
                        rule_id: "PERF-GPU-WILL-CHANGE".to_string(),
                        rule_name: "will-change Estático em Repouso".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "'will-change' aplicado estaticamente consome buffers de textura de GPU desnecessariamente enquanto o elemento está ocioso.".to_string(),
                        suggestion: Some("Aplique 'will-change: transform' estritamente sob seletores de interação (:hover, .is-hovered) e remova-o quando o elemento estiver em repouso.".to_string()),
                    });
                }
            }
            if !line.trim().is_empty() {
                prev_line = line;
            }
        }
    }

    // ── 15. FRONT-MODULAR-HOOKS: Desacoplamento de Chamadas de Rede das Páginas ──
    if path_str.contains("pages/") && path_str.ends_with(".tsx") {
        for (line_idx, line) in content.lines().enumerate() {
            let has_raw_network = line.contains("fetch(")
                || line.contains("axios.")
                || line.contains("new WebSocket(");

            if has_raw_network && !whitelist.is_ignored(&path_str, "FRONT-MODULAR-HOOKS", line) {
                violations.push(Violation {
                    rule_id: "FRONT-MODULAR-HOOKS".to_string(),
                    rule_name: "Chamada Direta de API na Camada de Página".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Páginas (src/pages/*.tsx) são orquestradores puros de alto nível. Chamadas diretas de rede ou websockets violam o desacoplamento arquitetural.".to_string(),
                    suggestion: Some("Extraia a chamada de API e seu estado para um Custom Hook em 'src/features/<dominio>/hooks/'.".to_string()),
                });
            }
        }
    }

    // ── 16. FRONT-FEEDBACK-ON-ERROR: Erro Silenciado sem Feedback Visual ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && !path_str.ends_with(".test.ts")
        && !path_str.ends_with(".test.tsx")
        && (path_str.contains("components/")
            || path_str.contains("features/")
            || path_str.contains("pages/")
            || path_str.contains("hooks/"))
    {
        for (line_idx, line) in content.lines().enumerate() {
            let is_bare_console_error =
                line.contains("console.error(") || line.contains("console.warn(");
            if is_bare_console_error {
                // Checa se o arquivo ou o contexto próximo provê feedback visual
                let has_visual_feedback = content.contains("toast.")
                    || content.contains("setErr")
                    || content.contains("isErr")
                    || content.contains("notify(")
                    || content.contains("snackbar")
                    || content.contains("alert(");

                if !has_visual_feedback
                    && !whitelist.is_ignored(&path_str, "FRONT-FEEDBACK-ON-ERROR", line)
                {
                    violations.push(Violation {
                        rule_id: "FRONT-FEEDBACK-ON-ERROR".to_string(),
                        rule_name: "Erro em UI sem Feedback Visual ao Usuário".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "Ação de UI captura erro e emite apenas console.error sem notificação visual (toast, banner ou estado de erro). O usuário ficará sem resposta na interface se a operação falhar.".to_string(),
                        suggestion: Some("Adicione notificação visual com toast.error('Mensagem') ou atualize o estado de erro do componente.".to_string()),
                    });
                }
            }
        }
    }

    // ── 17. FRONT-NO-HARDCODED-HOST: Proibição de localhost Absoluto no Frontend ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts") || path_str.ends_with(".js"))
        && !path_str.contains("vite.config")
        && !path_str.contains("/test")
        && !path_str.contains(".test.")
        && !path_str.contains(".spec.")
        && !path_str.contains("/scripts/")
        && (path_str.contains("frontend") || path_str.contains("web") || path_str.contains("/app/"))
    {
        for (line_idx, line) in content.lines().enumerate() {
            let has_localhost = line.contains("http://localhost")
                || line.contains("http://127.0.0.1")
                || line.contains("https://localhost")
                || line.contains("ws://localhost")
                || line.contains("ws://127.0.0.1");

            if has_localhost && !whitelist.is_ignored(&path_str, "FRONT-NO-HARDCODED-HOST", line) {
                violations.push(Violation {
                    rule_id: "FRONT-NO-HARDCODED-HOST".to_string(),
                    rule_name: "URL de Localhost Hardcoded no Frontend".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "URL absoluta de localhost encontrada no frontend. Em produção atrás do Nginx, isso quebra imediatamente por CORS ou conexão recusada.".to_string(),
                    suggestion: Some("Utilize caminho relativo (/api/...) ou carregue a URL via 'import.meta.env.VITE_API_URL'.".to_string()),
                });
            }
        }
    }

    // ── 18. SEO-INDEX-METADATA: Strict Document Head SEO Compliance ──────────
    if file_name == "index.html"
        && !is_common_ignored_path(&path_str)
        && (path_str.contains("frontend") || path_str.contains("web") || path_str.contains("/app/"))
    {
        // 18.1 Required <title> tag
        if !content.contains("<title>") || !content.contains("</title>") {
            if !whitelist.is_ignored(&path_str, "SEO-INDEX-METADATA", "<title>") {
                violations.push(Violation {
                    rule_id: "SEO-INDEX-METADATA".to_string(),
                    rule_name: "Missing Page Title Tag".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "<title> tag missing".to_string(),
                    message: "The document is missing an essential <title> tag. Search engines require a descriptive document title to index and rank the page.".to_string(),
                    suggestion: Some("Add a descriptive <title>Your Brand — Page Summary</title> inside <head>.".to_string()),
                });
            }
        }

        // 18.2 Required meta description
        let has_meta_description = content.contains("name=\"description\"")
            || content.contains("name='description'");
        if !has_meta_description {
            if !whitelist.is_ignored(&path_str, "SEO-INDEX-METADATA", "meta description") {
                violations.push(Violation {
                    rule_id: "SEO-INDEX-METADATA".to_string(),
                    rule_name: "Missing Meta Description Tag".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "meta name=\"description\" missing".to_string(),
                    message: "The document is missing a <meta name=\"description\"> tag. Search engines rely on this snippet to present page summaries in search results.".to_string(),
                    suggestion: Some("Add <meta name=\"description\" content=\"...\"> (120-160 characters) inside <head>.".to_string()),
                });
            }
        }

        // 18.3 Canonical URL tag
        let has_canonical = content.contains("rel=\"canonical\"")
            || content.contains("rel='canonical'");
        if !has_canonical && !whitelist.is_ignored(&path_str, "SEO-INDEX-METADATA", "canonical") {
            violations.push(Violation {
                rule_id: "SEO-INDEX-METADATA".to_string(),
                rule_name: "Missing Canonical Link Tag".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "link rel=\"canonical\" missing".to_string(),
                message: "Missing <link rel=\"canonical\" href=\"...\"> in <head>. Without a canonical tag, search engines may split ranking authority across URL variations.".to_string(),
                suggestion: Some("Add <link rel=\"canonical\" href=\"https://...\"> pointing to the official primary domain URL.".to_string()),
            });
        }

        // 18.4 Social Graph Open Graph & Twitter Cards
        let has_og_title = content.contains("property=\"og:title\"")
            || content.contains("property='og:title'");
        let has_og_desc = content.contains("property=\"og:description\"")
            || content.contains("property='og:description'");
        let has_og_image = content.contains("property=\"og:image\"")
            || content.contains("property='og:image'");
        let has_twitter_card = content.contains("name=\"twitter:card\"")
            || content.contains("name='twitter:card'");

        if (!has_og_title || !has_og_desc || !has_og_image || !has_twitter_card)
            && !whitelist.is_ignored(&path_str, "SEO-SOCIAL-GRAPH", "social graph")
        {
            violations.push(Violation {
                rule_id: "SEO-SOCIAL-GRAPH".to_string(),
                rule_name: "Missing Social Graph & Twitter Card Tags".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "Incomplete Open Graph / Twitter Card tags".to_string(),
                message: "Missing essential Social Graph tags (og:title, og:description, og:image or twitter:card). Shared links in WhatsApp, LinkedIn, and X will render without rich card previews.".to_string(),
                suggestion: Some("Declare og:title, og:description, og:image (1200x630) and twitter:card meta tags inside <head>.".to_string()),
            });
        }

        // 18.5 Google Search Multi-Resolution Favicon Spec
        let has_48px_favicon = content.contains("sizes=\"48x48\"")
            || content.contains("favicon.ico")
            || content.contains("sizes='48x48'");
        if !has_48px_favicon && !whitelist.is_ignored(&path_str, "SEO-FAVICON-SPEC", "favicon") {
            violations.push(Violation {
                rule_id: "SEO-FAVICON-SPEC".to_string(),
                rule_name: "Missing Multi-Resolution / 48px Favicon Specification".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "Missing 48x48 favicon or favicon.ico link".to_string(),
                message: "Google Search guidelines mandate that favicons must be multiples of 48px square (e.g. 48x48) or a valid multi-layer .ico to be rendered in search snippets.".to_string(),
                suggestion: Some("Add <link rel=\"icon\" type=\"image/png\" sizes=\"48x48\" href=\"/favicon-48x48.png\"> and link to /favicon.ico in <head>.".to_string()),
            });
        }

        // 18.6 Schema.org JSON-LD Structured Data
        let has_json_ld = content.contains("application/ld+json") && content.contains("schema.org");
        if !has_json_ld && !whitelist.is_ignored(&path_str, "SEO-SCHEMA-JSONLD", "json-ld") {
            violations.push(Violation {
                rule_id: "SEO-SCHEMA-JSONLD".to_string(),
                rule_name: "Missing Schema.org JSON-LD Structured Data".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "application/ld+json missing".to_string(),
                message: "Missing Schema.org JSON-LD structured data in index.html. Rich snippets and entity Knowledge Graph ingestion require structured machine-readable metadata.".to_string(),
                suggestion: Some("Add a <script type=\"application/ld+json\"> block defining Organization or WebSite metadata.".to_string()),
            });
        }
    }

    // ── 19. SEO-ROBOTS-SITEMAP: Compliance for Web Crawling Assets ───────────
    if file_name == "robots.txt" && !is_common_ignored_path(&path_str) {
        let has_user_agent = content.contains("User-agent:") || content.contains("User-Agent:");
        let has_sitemap_directive = content.contains("Sitemap:") || content.contains("sitemap:");
        if (!has_user_agent || !has_sitemap_directive)
            && !whitelist.is_ignored(&path_str, "SEO-ROBOTS-SITEMAP", "robots.txt")
        {
            violations.push(Violation {
                rule_id: "SEO-ROBOTS-SITEMAP".to_string(),
                rule_name: "Incomplete robots.txt Configuration".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "robots.txt missing User-agent or Sitemap directive".to_string(),
                message: "The robots.txt file must declare 'User-agent: *' and a 'Sitemap: https://...' directive pointing to the canonical XML sitemap.".to_string(),
                suggestion: Some("Ensure 'User-agent: *' and 'Sitemap: https://<domain>/sitemap.xml' are present.".to_string()),
            });
        }
    }

    if file_name == "sitemap.xml" && !is_common_ignored_path(&path_str) {
        let has_urlset = content.contains("<urlset") && content.contains("</urlset>");
        let has_loc = content.contains("<loc>") && content.contains("</loc>");
        if (!has_urlset || !has_loc)
            && !whitelist.is_ignored(&path_str, "SEO-ROBOTS-SITEMAP", "sitemap.xml")
        {
            violations.push(Violation {
                rule_id: "SEO-ROBOTS-SITEMAP".to_string(),
                rule_name: "Malformed sitemap.xml Structure".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "sitemap.xml missing urlset or loc tags".to_string(),
                message: "The sitemap.xml file must be valid XML containing <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"> and at least one <loc> entry.".to_string(),
                suggestion: Some("Structure sitemap.xml according to the sitemaps.org 0.9 schema standard.".to_string()),
            });
        }
    }

    // ── 20. SEO-IMG-ALT: Mandatory Image Alt Attribute for Search & A11y ────
    if (path_str.ends_with(".tsx") || path_str.ends_with(".jsx") || path_str.ends_with(".html"))
        && !is_common_ignored_path(&path_str)
        && !path_str.contains("/test")
        && !path_str.contains(".test.")
        && !path_str.contains(".spec.")
    {
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("<img") {
                // If img is multi-line, check adjacent lines up to closure '>'
                let mut full_tag = line.to_string();
                if !line.contains('>') {
                    let subsequent_lines: Vec<&str> = content.lines().skip(line_idx + 1).take(5).collect();
                    for sub in subsequent_lines {
                        full_tag.push(' ');
                        full_tag.push_str(sub);
                        if sub.contains('>') {
                            break;
                        }
                    }
                }

                let tag_has_alt = full_tag.contains("alt=") || full_tag.contains("alt =");
                let tag_is_aria_hidden = full_tag.contains("aria-hidden=\"true\"")
                    || full_tag.contains("aria-hidden='true'")
                    || full_tag.contains("aria-hidden={true}");

                if (!tag_has_alt && !tag_is_aria_hidden)
                    && !whitelist.is_ignored(&path_str, "SEO-IMG-ALT", line)
                {
                    violations.push(Violation {
                        rule_id: "SEO-IMG-ALT".to_string(),
                        rule_name: "Image Tag Missing Descriptive Alt Attribute".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "All <img> tags must declare a descriptive 'alt' attribute for Google Images search indexing and screen reader accessibility.".to_string(),
                        suggestion: Some("Add alt=\"Descriptive image context\" (or aria-hidden=\"true\" for purely decorative graphics).".to_string()),
                    });
                }
            }
        }
    }

    violations
}
