use std::path::Path;

pub fn generate_llm_context(_root: &Path) {
    let context_markdown = format!(
        r#"# Contexto Canônico de Governança & Arquitetura (StenioSentinel v3.0)

Este contexto sintetiza em alta densidade todas as leis, arquitetura e infraestrutura do ecossistema SUMÆNIMÁ e Homelab Mnemocine. Consuma como fonte da verdade absoluta.

## 👤 Identidade & Prestador
- **Nome:** Carlos Eduardo Rodrigues (SUMÆNIMÁ / MEI)
- **CNPJ:** 62.447.037/0001-10
- **Email/PIX:** ceduardorodrig@gmail.com
- **Espaço de Trabalho:** Monorepo/Vault Obsidian em `/mnt/NVME_PCI/agentic-ai` (Sincronizado via Syncthing).
- **Backend & Plataforma:** `/mnt/NVME_PCI/sumaenimahub/SUMAENIMA-HUB` (Rust Axum + React/Vite).

## ⚡ Hardware & Aceleração Local (psicopompo)
- **GPU:** NVIDIA GeForce RTX 5050 (Driver 615.71.09, Arquitetura Blackwell).
- **VRAM:** 8.151 MiB total (~6.300 MiB livres dedicados a inferência).
- **IA/ASR Local:** Whisper GGML Q8_0 em `/mnt/NVME_PCI/sumaenimahub/llm_model_cache/whisper-ggml/` executando no Rust com suporte CUDA.
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
1. **Ferramentas Rust Obrigatórias no Terminal:** Nunca usar ferramentas GNU legadas. Usar `bat` em vez de `cat`, `eza` em vez de `ls`, `rg` em vez de `grep`, `fd` em vez de `find`, `sd` em vez de `sed`, `dust` em vez de `du`.
2. **NFS Soft Mount Obrigatório:** Montagens NFS clientes via Tailscale NUNCA devem usar `hard`. Sempre: `rw,soft,timeo=30,retrans=2,_netdev,x-systemd.automount,nofail`.
3. **Guarda SOPS/Age:** Nenhum segredo ou chave sobe desprotegido para git ou NAS. Tudo cifrado via SOPS com chaves Age.
4. **Arquitetura de Frontend & DRY:** Páginas React em `src/pages/*.tsx` têm limite estrito de 400 linhas. Hooks em `features/*/hooks/`, componentes em `features/*/components/`.
5. **Auditoria Pré-Commit:** Nenhuma alteração é commitada sem validação com zero erros via `stenio`.
"#
    );

    println!("{}", context_markdown);
}
