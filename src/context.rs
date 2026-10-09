use std::path::Path;

pub fn generate_llm_context(_root: &Path) {
    let context_markdown = r#"# Canonical Governance & Architecture Context (StenioSentinel v4.0)

This context synthesizes in high density all laws, architecture, and infrastructure of the SUMÆNIMÁ and Mnemocine Homelab ecosystem. Treat as canonical source of truth.

## 👤 Identity & Service Provider
- **Name:** Carlos Eduardo Rodrigues (SUMÆNIMÁ / MEI)
- **CNPJ:** 62.447.037/0001-10
- **Email/PIX:** ceduardorodrig@gmail.com
- **Workspace:** Obsidian Vault at `/mnt/NVME_PCI/agentic-ai` (Synchronized via Syncthing).
- **Backend & Platform:** `/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub` (Rust Axum + React/Vite).

## ⚡ Hardware & Local Acceleration (psicopompo)
- **GPU:** NVIDIA GeForce RTX 5050 (Driver 615.71.09, Blackwell Architecture).
- **VRAM:** 8,151 MiB total (~6,300 MiB free dedicated to inference).
- **Local AI/ASR:** Whisper GGML Q8_0 at `/mnt/NVME_PCI/homelab/sumaenimahub/llm_model_cache/whisper-ggml/` executing in Rust with CUDA support.
- **Storage:** NVMe PCI 2TB `/mnt/NVME_PCI` + NAS ZFS/Btrfs `/mnt/BACKUP`.

## 🌐 Tailscale Mesh Network (Mnemocine Homelab)
| Host | Tailscale IP | Canonical Role |
|---|---|---|
| **psicopompo** | `100.82.51.112` | Dev + GPU Workers + NAS NFSv4 |
| **ybyra** | `100.66.224.34` | Primary Cloud Edge / Nginx Reverse Proxy / SPA |
| **kuaray** | `100.94.209.99` | Multimedia / Home Assistant / Media Server |
| **ybytu** | `100.115.253.109` | Cloud Exit Node / Primary AdGuard DNS |
| **kavure** | `100.124.146.77` | Dedicated Services Server (Docker / Zomboid / Sumænimá) |

## 🛑 Absolute Governance Laws
1. **Mandatory Rust Terminal Tools:** Never use legacy GNU tools. Use `bat` instead of `cat`, `eza` instead of `ls`, `rg` instead of `grep`, `fd` instead of `find`, `sd` instead of `sed`, `dust` instead of `du`, `xh` instead of `curl`.
2. **Mandatory NFS Soft Mounts:** Client NFS mounts over Tailscale MUST NEVER use `hard`. Always: `rw,soft,timeo=30,retrans=2,_netdev,x-systemd.automount,nofail`.
3. **SOPS/Age Secret Guard:** Zero plaintext credentials or keys committed to git or NAS. Everything encrypted via SOPS with Age keys.
4. **Administrative Privileges:** Use sudoers NOPASSWD rule (`sudo <cmd>`) or inject credentials via `.env`/SOPS. Avoid interactive passwords or forcing `pkexec` on headless servers.
5. **Pre-Delivery Quality Gate (`stenio --gate`):** The model MUST execute `stenio --gate` before concluding any task. Zero blocking errors permitted.

## 🎨 Sumænimá Hub Frontend Cheat Sheet (React + Vite + Tailwind + Zustand)
- **Canonical Palette (Generic grays gray/zinc/slate forbidden):**
  - Application main background: `bg-surface-950` (`#09090b`)
  - Cards and containers: `bg-surface-900` (`#18181b`) or `.sm-glass` class (20px blur)
  - Hover and elevated surfaces: `bg-surface-800` (`#27272a`)
  - High-contrast text: `text-on-surface` (`#e4e4e7`)
  - Borders and dividers: `border-outline` (`rgba(255, 255, 255, 0.06)`)
- **Zustand Store:**
  - Always import `useShallow` from `'zustand/react/shallow'` when selecting multiple store properties:
    `const { stateA, stateB } = useStore(useShallow(s => ({ stateA: s.a, stateB: s.b })));`
- **Audio & DSP:**
  - Real-time audio processing runs in the WebAssembly module `wasm-audio-dsp` coupled to `AudioWorkletNode`. Forbidden to use `createScriptProcessor`.
- **Strict Typing:**
  - Forbidden use of `any` (`: any`, `as any`). Use concrete types from `src/types/` or synchronize with `stenio --typegen`.

## 🧩 Absolute DRY Principle (Zero Code Duplication)
- **Fundamental Law:** AI models are strictly prohibited from copying and pasting logic blocks (>6 identical lines).
- **Decoupling:** All repeated logic (filters, pagination, collections, mutations) MUST be extracted into Custom Hooks (`features/<domain>/hooks/`), atomic components (`features/<domain>/components/`), or pure utilities.
- **Automated Detection:** Stenio audits the repository with Rolling Block Hash and fails the Quality Gate upon detecting cloned blocks.

## 🚀 GPU Performance & Arandu Standards (Zero-Repaint & 60/120 FPS)
- **Zero-Repaint on Hovers & 3D Tilt:**
  - NEVER animate `box-shadow`, `backdrop-filter`, or `background-color` directly on the container upon hover. This forces heavy GPU repaints on every frame.
  - Always use pseudo-elements (`::after`) with pre-rendered shadow and transition exclusively `opacity: 0 -> 1` with `transform: translateZ(0)` (operates at 0ms on the GPU Compositor).
- **Event Buffering (Zero Layout Thrashing):**
  - NEVER invoke `getBoundingClientRect()`, `offsetWidth`, or `offsetHeight` inside mouse loops or handlers (`onMouseMove`, `pointermove`).
  - Cache rect on `onMouseEnter` / `isHoveredRef` or buffer coordinates in `useRef` consumed inside `requestAnimationFrame` (per canonical pattern in `use3DTilt.ts`).
- **CSS Grid Containment:**
  - In dense card grids (Arandu Binder, Catalog, Decks, Wishlist), wrap each card in a `.card-cell` container with `position: relative; overflow: visible`.
  - This isolates the 3D stacking context of each card, preventing the GPU from recalculating layout of neighbor cards.
- **Dynamic will-change:**
  - NEVER apply static `will-change: transform` on rest classes. Apply strictly under `:hover` or active `.is-hovered`.
- **Pure Page Orchestration:**
  - Files in `src/pages/*.tsx` are high-level orchestrators (<400 lines). API calls (`fetch`, `axios`) and websockets MUST reside in Custom Hooks in `features/<domain>/hooks/`.

## 🦀 Sumænimá Hub Backend Cheat Sheet (Axum + Tokio + SQLx)
- **Async I/O:** Never use synchronous `std::fs` in route handlers. Use `tokio::fs` with `.await`.
- **Zero Panic in Production:** Forbidden unwrap, expect, `assert!()`, or `panic!()` in server code. Return `Result<..., AppError>` or map to `StatusCode`.
- **Parameterized Queries:** Always use SQLx binds `$1`, `$2`. Never format strings directly into SQL queries.
"#;

    println!("{}", context_markdown);
}
