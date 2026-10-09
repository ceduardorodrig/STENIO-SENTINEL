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
                    message: "AudioWorklet on Firefox breaks with globalThis.sampleRate; use this.sampleRate in the constructor.".to_string(),
                    suggestion: Some("Replace globalThis.sampleRate with this.sampleRate in the constructor.".to_string()),
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
                    message: "Store this.sampleRate into this._sampleRate in constructor for capture resilience.".to_string(),
                    suggestion: Some("Declare 'this._sampleRate = this.sampleRate;' in AudioWorkletProcessor constructor.".to_string()),
                });
            }
        }
    }

    // ── 2. FRONT-CLEANUP: Event and Timer Hygiene ────────────────────────
    if path_str.ends_with(".tsx") || path_str.ends_with(".ts") {
        if content.contains("addEventListener(") && !content.contains("removeEventListener(") {
            if !whitelist.is_ignored(&path_str, "FRONT-CLEANUP", "addEventListener") {
                violations.push(Violation {
                    rule_id: "FRONT-CLEANUP".to_string(),
                    rule_name: "EventListener Missing Cleanup".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "addEventListener without removeEventListener".to_string(),
                    message: "Component attaches event listener without cleanup return in useEffect (memory leak risk).".to_string(),
                    suggestion: Some("Return a cleanup function in useEffect calling removeEventListener(event, handler).".to_string()),
                });
            }
        }

        if content.contains("setInterval(") && !content.contains("clearInterval(") {
            if !whitelist.is_ignored(&path_str, "FRONT-CLEANUP", "setInterval") {
                violations.push(Violation {
                    rule_id: "FRONT-CLEANUP".to_string(),
                    rule_name: "setInterval Timer Missing Cleanup".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "setInterval without clearInterval".to_string(),
                    message: "Timer setInterval lacks matching clearInterval on component unmount.".to_string(),
                    suggestion: Some("Store the timer ID and return '() => clearInterval(timerId)' in useEffect cleanup.".to_string()),
                });
            }
        }
    }

    // ── 3. FRONT-WAKELOCK: Screen WakeLock Release ───────────────────────
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && content.contains("navigator.wakeLock.request(")
    {
        if !content.contains(".release()") && !content.contains("wakeLock.release") {
            if !whitelist.is_ignored(&path_str, "FRONT-WAKELOCK", "wakeLock") {
                violations.push(Violation {
                    rule_id: "FRONT-WAKELOCK".to_string(),
                    rule_name: "Screen WakeLock Leak".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "wakeLock.request without release()".to_string(),
                    message: "Screen wakeLock request must release lock in hook cleanup.".to_string(),
                    suggestion: Some("Invoke 'wakeLock.release()' inside hook cleanup function to release the screen lock.".to_string()),
                });
            }
        }
    }

    // ── 4. FRONT-GLASSMORPHIC: Section Separation vs Glassmorphic Cards ──
    if path_str.ends_with(".tsx") && (content.contains("<hr ") || content.contains("<hr/>")) {
        if !whitelist.is_ignored(&path_str, "FRONT-GLASSMORPHIC", "<hr") {
            violations.push(Violation {
                rule_id: "FRONT-GLASSMORPHIC".to_string(),
                rule_name: "Glassmorphic Card Separation Law".to_string(),
                severity: Severity::Warning,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "Loose <hr /> element detected".to_string(),
                message: "In Sumænimá design principles, avoid loose dividing lines (<hr>); isolate sections inside .sm-glass cards.".to_string(),
                suggestion: Some("Remove <hr /> and separate content blocks using cards with the .sm-glass class.".to_string()),
            });
        }
    }

    // ── 5. FRONT-HEX: Arbitrary Hex Colors in Tailwind (Rule 24) ─────────
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && !path_str.ends_with("styles.ts")
        && !path_str.contains("/themes/")
    {
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("bg-[#") || line.contains("text-[#") || line.contains("border-[#") {
                if !whitelist.is_ignored(&path_str, "FRONT-HEX", line) {
                    violations.push(Violation {
                        rule_id: "FRONT-HEX".to_string(),
                        rule_name: "Arbitrary Hex Colors in Tailwind".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "Rule 24 of AGENTS.md: Avoid loose arbitrary hex classes; use design system M3 surface and primary tokens.".to_string(),
                        suggestion: Some("Replace raw hex classes (e.g. bg-[#...]) with M3 tokens: bg-surface, text-primary, border-outline.".to_string()),
                    });
                }
            }
        }
    }

    // ── 6. FRONT-TOKEN-PALETTE: Forbidden Generic Grays ──────────────────
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
                    rule_name: "Forbidden Generic Tailwind Grays".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "In Sumænimá Hub, avoid generic grays (gray, slate, neutral). Use canonical surface tokens (bg-surface-950/900/800, text-on-surface, border-outline).".to_string(),
                    suggestion: Some("Replace bg-gray/slate with bg-surface-950 (background), bg-surface-900 (cards), bg-surface-800 (hover), and text-on-surface.".to_string()),
                });
            }
        }
    }

    // ── 7. FRONT-NO-ANY: Strict Typing Enforcement in TypeScript ─────────
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
                    rule_name: "Forbidden 'any' Type in Frontend".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: trimmed.to_string(),
                    message: "Usage of 'any' undermines type safety between frontend and Rust backend. Use concrete interfaces from src/types/ or run 'stenio --typegen'.".to_string(),
                    suggestion: Some("Replace 'any' with a concrete typed interface in src/types/ or use 'unknown' with type guards.".to_string()),
                });
            }
        }
    }

    // ── 8. FRONT-A11Y-BUTTON: Icon Button Accessibility ──────────────────
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
                        rule_name: "Icon Button Missing aria-label".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "Action buttons containing only icons require 'aria-label' or 'title' for screen reader accessibility.".to_string(),
                        suggestion: Some("Add aria-label=\"Action description\" or title=\"...\" attribute to <button> tag.".to_string()),
                    });
                }
            }
        }
    }

    // ── 9. FRONT-AUDIO-WASM: Prohibition of Obsolete createScriptProcessor ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts") || path_str.ends_with(".js"))
        && content.contains("createScriptProcessor")
    {
        if !whitelist.is_ignored(&path_str, "FRONT-AUDIO-WASM", "createScriptProcessor") {
            violations.push(Violation {
                rule_id: "FRONT-AUDIO-WASM".to_string(),
                rule_name: "Obsolete createScriptProcessor Usage".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: "createScriptProcessor detected".to_string(),
                message: "createScriptProcessor executes audio processing on the browser main rendering thread. Migrate to AudioWorkletNode and wasm-audio-dsp.".to_string(),
                suggestion: Some("Migrate to AudioWorkletNode backed by the Rust WebAssembly module in wasm-audio.".to_string()),
            });
        }
    }

    // ── 10. FRONT-COMPONENT-BUDGET: Monolithic Component Budget (>400 Lines) ──
    if path_str.ends_with(".tsx") && !path_str.ends_with("App.tsx") && !path_str.contains("data/") {
        let total_lines = content.lines().count();
        if total_lines > 400 && !whitelist.is_ignored(&path_str, "FRONT-COMPONENT-BUDGET", "") {
            violations.push(Violation {
                rule_id: "FRONT-COMPONENT-BUDGET".to_string(),
                rule_name: "Excessive Monolithic Component (>400 Lines)".to_string(),
                severity: Severity::Warning,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: format!("Total lines: {}", total_lines),
                message: format!("Component contains {} lines, exceeding the 400-line budget. Large monolithic files increase AI hallucination risk and maintenance debt.", total_lines),
                suggestion: Some("Decompose this component into atomic submodules (Header, Controls, List, Item) inside src/components/.".to_string()),
            });
        }
    }

    // ── 11. PERF-GPU-ZERO-REPAINT: Prohibition of Paint Transitions on 3D Elements ──
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
                    rule_name: "GPU Paint Property Transition Violation".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Transitions on 'box-shadow', 'backdrop-filter', or 'background-color' on 3D/tilt elements force rasterization and continuous GPU repaints. Use pseudo-elements (::after) with opacity transitions (0ms CPU/GPU paint).".to_string(),
                    suggestion: Some("Animate opacity (opacity: 0 -> 1) on an isolated ::after pseudo-element on the GPU Compositor instead of transitioning box-shadow/color directly.".to_string()),
                });
            }
        }
    }

    // ── 12. PERF-NO-LAYOUT-THRASH: Prohibition of Synchronous DOM Geometry Reads ──
    if (path_str.ends_with(".tsx") || path_str.ends_with(".ts"))
        && (content.contains("handleMouseMove")
            || content.contains("onMouseMove")
            || content.contains("pointermove"))
    {
        for (line_idx, line) in content.lines().enumerate() {
            let calls_geometry = line.contains(".getBoundingClientRect()")
                || line.contains(".offsetWidth")
                || line.contains(".offsetHeight");

            // Permitted if explicit hover/cache check exists on same line or in file
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
                    rule_name: "Synchronous DOM Geometry Read in Event Loop".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Calling getBoundingClientRect() or offset* directly inside pointer/mouse event streams triggers layout thrashing (forced synchronous layout at 1000Hz).".to_string(),
                    suggestion: Some("Cache rect in a useRef during onMouseEnter or buffer coordinates in useRef consumed inside requestAnimationFrame.".to_string()),
                });
            }
        }
    }

    // ── 13. PERF-GPU-CONTAINMENT: CSS Containment in Dense Card Grids ───
    if path_str.contains("features/arandu/components/") && path_str.ends_with(".tsx") {
        if content.contains("<MagicCard")
            && (content.contains(".map(") || content.contains("cards.map"))
            && !content.contains("card-cell")
            && !content.contains("contain-content")
        {
            if !whitelist.is_ignored(&path_str, "PERF-GPU-CONTAINMENT", "<MagicCard") {
                violations.push(Violation {
                    rule_id: "PERF-GPU-CONTAINMENT".to_string(),
                    rule_name: "Card Grid Missing CSS Containment (.card-cell)".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: "<MagicCard rendered in loop without card-cell wrapper".to_string(),
                    message: "Component iterates over card collections without a '.card-cell' wrapper. Missing CSS containment triggers cascading repaints across neighbor cards during 3D tilt/hover.".to_string(),
                    suggestion: Some("Wrap each card inside <div className=\"card-cell\"><MagicCard ... /></div>.".to_string()),
                });
            }
        }
    }

    // ── 14. PERF-GPU-WILL-CHANGE: Dynamic will-change vs Static Allocation ───
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
                        rule_name: "Static will-change at Rest".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "'will-change' applied statically allocates GPU texture buffers unnecessarily while the element is idle.".to_string(),
                        suggestion: Some("Apply 'will-change: transform' strictly under interaction selectors (:hover, .is-hovered) and release it when idle.".to_string()),
                    });
                }
            }
            if !line.trim().is_empty() {
                prev_line = line;
            }
        }
    }

    // ── 15. FRONT-MODULAR-HOOKS: Decoupling Network Calls from Pages ───────
    if path_str.contains("pages/") && path_str.ends_with(".tsx") {
        for (line_idx, line) in content.lines().enumerate() {
            let has_raw_network = line.contains("fetch(")
                || line.contains("axios.")
                || line.contains("new WebSocket(");

            if has_raw_network && !whitelist.is_ignored(&path_str, "FRONT-MODULAR-HOOKS", line) {
                violations.push(Violation {
                    rule_id: "FRONT-MODULAR-HOOKS".to_string(),
                    rule_name: "Direct API Network Call in Page Layer".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Page components (src/pages/*.tsx) are pure high-level orchestrators. Direct fetch/axios/websocket network calls violate architectural separation.".to_string(),
                    suggestion: Some("Extract API calls and state management into a Custom Hook in 'src/features/<domain>/hooks/'.".to_string()),
                });
            }
        }
    }

    // ── 16. FRONT-FEEDBACK-ON-ERROR: Visual Error Feedback in UI ──────────
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
                // Checks whether the file or proximate context provides visual feedback
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
                        rule_name: "Silent UI Error Without Visual User Feedback".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: line_idx + 1,
                        snippet: line.trim().to_string(),
                        message: "UI action catches error and only emits console.error/warn without visual notification (toast, alert, banner, or error state). The user is left with no feedback if the operation fails.".to_string(),
                        suggestion: Some("Add visual user feedback via toast.error('Message') or update component error state.".to_string()),
                    });
                }
            }
        }
    }

    // ── 17. FRONT-NO-HARDCODED-HOST: Prohibition of Absolute Localhost in Frontend ──
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
                    rule_name: "Hardcoded Localhost URL in Frontend".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: line_idx + 1,
                    snippet: line.trim().to_string(),
                    message: "Absolute localhost URL found in frontend. In production behind reverse proxy (Nginx), this fails immediately with CORS or connection refused.".to_string(),
                    suggestion: Some("Use relative paths (/api/...) or read the URL from 'import.meta.env.VITE_API_URL'.".to_string()),
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
