# StenioSentinel (v3.0.0) — Sistema Universal de Governança & Homelab em Rust

O **StenioSentinel** é o motor unificado e de alto desempenho para auditoria de boas práticas, fiscalização estática, autocorreção e monitoramento holístico do Homelab Mnemocine, Vault Obsidian e Sumænimá Hub.

## 🚀 Capacidades & Superpoderes

### 1. Auditoria Assíncrona da Malha Tailscale (`--mesh`)
Dispara sondagens paralelas TCP/WireGuard via runtime Tokio para todos os nós da Tailnet (`psicopompo`, `ybyra`, `kuaray`, `ybytu`, `kavure`).
- Retorna o status de toda a malha em menos de **30 a 100 milissegundos**.
- Integrado também na visão completa de diagnóstico via `--health`.

```bash
stenio --mesh
stenio --health
```

### 2. Guarda de Segredos SOPS/Age (`SEC-SOPS-UNENCRYPTED`)
Garante que nenhum arquivo com extensão `.enc.*` ou contendo atribuição de credenciais (`PASSWORD`, `SECRET`, `API_KEY`) seja commitado ou espelhado sem a criptografia armada do SOPS/Age.

### 3. Validação Estática de Infraestrutura (`INFRA-COMPOSE-*`, `INFRA-SYSTEMD-*`)
- Parser sintático ultra-rápido de arquivos `compose.yml` e `docker-compose.yml`.
- Fiscalização de políticas de restart (`restart: unless-stopped`).
- Validação estrutural de units do Systemd (`.service`, `.timer`).

### 4. Typegen Automático Rust → TypeScript (`--typegen`)
Gera automaticamente interfaces TypeScript espelhadas dos structs de DTO em Rust para o frontend Vite/React em [`app/frontend-v2/src/types/generated/stenio.ts`](../../sumaenimahub/sumaenima-hub/app/frontend-v2/src/types/generated/stenio.ts).
- Garante **Zero Débito Técnico** e paridade total entre backend e frontend.

```bash
stenio --typegen
```

---

## 🛠️ Modos de Uso & Comandos

| Comando | Descrição |
|---|---|
| `stenio` | Auditoria contextual automática baseada na pasta atual |
| `stenio --scope homelab` | Auditoria especializada de notas, tags e regras de infraestrutura |
| `stenio --scope hub` | Auditoria do monorepo Sumænimá Hub (leis, skills, ADRs, código) |
| `stenio --scope vault` | Auditoria do Vault Obsidian (taxonomia de tags e frontmatter) |
| `stenio --scope all` | Auditoria holística de todo o ecossistema |
| `stenio --mesh` | Sondagem assíncrona da malha Tailscale dos nós do Homelab |
| `stenio --health` | Raio-X completo de NVMe, RAM, GPU RTX 5050 e serviços |
| `stenio --typegen` | Sincronização automática de tipos Rust para TypeScript |
| `stenio --fix` | Aplicação cirúrgica de correções automáticas (auto-fix) |
| `stenio --self-test` | Bateria de auto-testes sintéticos das regras do motor |
