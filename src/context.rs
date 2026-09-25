use std::path::Path;

pub fn generate_llm_context(_root: &Path) {
    let context_markdown = r#"# Contexto Canônico de Governança & Arquitetura (StenioSentinel v3.0)

Este contexto sintetiza em alta densidade todas as leis, arquitetura e infraestrutura do ecossistema SUMÆNIMÁ e Homelab Mnemocine. Consuma como fonte da verdade absoluta.

## 👤 Identidade & Prestador
- **Nome:** Carlos Eduardo Rodrigues (SUMÆNIMÁ / MEI)
- **CNPJ:** 62.447.037/0001-10
- **Email/PIX:** ceduardorodrig@gmail.com
- **Espaço de Trabalho:** Vault Obsidian em `/mnt/NVME_PCI/agentic-ai` (Sincronizado via Syncthing).
- **Backend & Plataforma:** `/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub` (Rust Axum + React/Vite).

## ⚡ Hardware & Aceleração Local (psicopompo)
- **GPU:** NVIDIA GeForce RTX 5050 (Driver 615.71.09, Arquitetura Blackwell).
- **VRAM:** 8.151 MiB total (~6.300 MiB livres dedicados a inferência).
- **IA/ASR Local:** Whisper GGML Q8_0 em `/mnt/NVME_PCI/homelab/sumaenimahub/llm_model_cache/whisper-ggml/` executando no Rust com suporte CUDA.
- **Storage:** NVMe PCI 2TB `/mnt/NVME_PCI` + NAS ZFS/Btrfs `/mnt/BACKUP`.

## 🌐 Malha Tailscale (Mnemocine Homelab)
| Host | IP Tailscale | Papel Canônico |
|---|---|---|
| **psicopompo** | `100.82.51.112` | Dev + GPU Workers + NAS NFSv4 |
| **ybyra** | `100.66.224.34` | Borda Cloud Primária / Nginx Reverse Proxy / SPA |
| **kuaray** | `100.94.209.99` | Multimídia / Home Assistant / Media Server |
| **ybytu** | `100.115.253.109` | Exit Node Cloud / DNS Primário AdGuard |
| **kavure** | `100.124.146.77` | Servidor de Serviços Dedicado (Docker / Zomboid / Sumænimá) |

## 🛑 Leis Absolutas de Governança
1. **Ferramentas Rust Obrigatórias no Terminal:** Nunca usar ferramentas GNU legadas. Usar `bat` em vez de `cat`, `eza` em vez de `ls`, `rg` em vez de `grep`, `fd` em vez de `find`, `sd` em vez de `sed`, `dust` em vez de `du`, `xh` em vez de `curl`.
2. **NFS Soft Mount Obrigatório:** Montagens NFS clientes via Tailscale NUNCA devem usar `hard`. Sempre: `rw,soft,timeo=30,retrans=2,_netdev,x-systemd.automount,nofail`.
3. **Guarda SOPS/Age:** Nenhum segredo ou chave sobe desprotegido para git ou NAS. Tudo cifrado via SOPS com chaves Age.
4. **Privilégios Administrativos:** Use regra NOPASSWD no sudoers (`sudo <cmd>`) ou injete variáveis via `.env`/SOPS. Evite senhas interativas ou forçar `pkexec` em servidores headless.
5. **Quality Gate Pré-Entrega (`stenio --gate`):** O modelo DEVE executar `stenio --gate` antes de finalizar qualquer tarefa. Zero erros impeditivos permitidos.

## 🎨 Sumænimá Hub Frontend Cheat Sheet (React + Vite + Tailwind + Zustand)
- **Paleta Canônica (Proibido cinzas genéricos gray/zinc/slate):**
  - Fundo principal da aplicação: `bg-surface-950` (`#09090b`)
  - Cards e containers: `bg-surface-900` (`#18181b`) ou classe `.sm-glass` (blur 20px)
  - Hover e superfícies elevadas: `bg-surface-800` (`#27272a`)
  - Texto de alto contraste: `text-on-surface` (`#e4e4e7`)
  - Bordas e divisores: `border-outline` (`rgba(255, 255, 255, 0.06)`)
- **Zustand Store:**
  - Sempre importe `useShallow` de `'zustand/react/shallow'` ao selecionar mais de uma propriedade da store:
    `const { stateA, stateB } = useStore(useShallow(s => ({ stateA: s.a, stateB: s.b })));`
- **Áudio & DSP:**
  - O processamento de áudio em tempo real roda no módulo WebAssembly `wasm-audio-dsp` acoplado ao `AudioWorkletNode`. É proibido usar `createScriptProcessor`.
- **Tipagem Estrita:**
  - Proibido o uso de `any` (`: any`, `as any`). Utilize os tipos em `src/types/` ou sincronize com `stenio --typegen`.

## 🧩 Princípio DRY Absoluto (Zero Duplicação de Código)
- **Regra Fundamental:** Modelos de IA são terminantemente proibidos de copiar e colar blocos de lógica (>6 linhas idênticas).
- **Desacoplamento:** Toda lógica repetida de filtros, paginação, coleções ou mutações DEVE ser extraída para Custom Hooks (`features/<dominio>/hooks/`), componentes atômicos (`features/<dominio>/components/`) ou utilitários puros.
- **Detecção Automática:** O Stenio audita o repositório com Rolling Block Hash e falha no Quality Gate se detectar blocos clonados.

## 🚀 Padrões de Performance GPU & Arandu (Zero-Repaint & 60/120 FPS)
- **Zero-Repaint em Hovers & 3D Tilt:**
  - NUNCA anime `box-shadow`, `backdrop-filter` ou `background-color` diretamente no container em hover. Isso força repaints pesados de GPU a cada frame.
  - Sempre utilize pseudo-elementos (`::after`) com pré-renderização da sombra e transicione exclusivamente `opacity: 0 -> 1` com `transform: translateZ(0)` (opera a 0ms no Compositor da GPU).
- **Event Buffering (Zero Layout Thrashing):**
  - NUNCA invoque `getBoundingClientRect()`, `offsetWidth` ou `offsetHeight` dentro de loops ou handlers de mouse (`onMouseMove`, `pointermove`).
  - Faça cache do rect no evento `onMouseEnter` / `isHoveredRef` ou armazene coordenadas em buffer (`useRef`) consumido no loop de `requestAnimationFrame` (conforme padrão canônico em `use3DTilt.ts`).
- **Contenção CSS de Grade:**
  - Em grades densas de cards (Arandu Binder, Catálogo, Decks, Wishlist), envolva cada carta em um container `.card-cell` com `position: relative; overflow: visible`.
  - Isso isola o stacking context 3D de cada carta, impedindo que a GPU recalcule o layout de cards vizinhos.
- **will-change Dinâmico:**
  - NUNCA aplique `will-change: transform` estático em classes de repouso. Aplique estritamente em `:hover` ou sob a classe ativa `.is-hovered`.
- **Orquestração Pura de Páginas:**
  - Arquivos em `src/pages/*.tsx` são orquestradores de alto nível (<400 linhas). Chamadas de API (`fetch`, `axios`) e websockets DEVEM residir em Custom Hooks em `features/<dominio>/hooks/`.

## 🦀 Sumænimá Hub Backend Cheat Sheet (Axum + Tokio + SQLx)
- **E/S Assíncrona:** Nunca use `std::fs` síncrono em handlers de rota. Utilize `tokio::fs` com `.await`.
- **Zero Panic em Produção:** Proibido unwrap, expect, `assert!()` ou `panic!()` em código do servidor. Retorne `Result<..., AppError>` ou mapeie em `StatusCode`.
- **Queries Parametrizadas:** Use sempre binds `$1`, `$2` do SQLx. Nunca formate strings diretamente em queries SQL.
"#;

    println!("{}", context_markdown);
}
