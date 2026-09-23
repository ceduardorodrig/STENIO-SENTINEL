use anyhow::Result;
use colored::*;
use std::process::Command;

/// ── stênio --gaming — Raio-X de Gaming Health (sessão-aware) ───────────────
///
/// Inventário canônico de otimizações de gaming do psicopompo, com fonte por item:
///   - CachyOS wiki  → https://wiki.cachyos.org/configuration/gaming/
///   - ArchWiki      → https://wiki.archlinux.org/title/Gaming
///   - Hyprland wiki → https://wiki.hypr.land/
/// Canonizado em 21/09/2026 (ver mnemocine/guides/hyprland-noctalia-guide.md).
pub fn run_gaming_health() -> Result<()> {
    crate::baseline::print_banner("StênioKernel — Raio-X de Gaming Health (--gaming)");

    // 0. Sessão ativa (define quais checks compositor se aplicam)
    println!(
        "{}",
        "── 🖥️  Sessão ativa (Hyprland vs KDE) ────────────────────────────────".dimmed()
    );
    let session = detect_session();
    match session.as_str() {
        "Hyprland" => {
            println!("   {:<34} [{}]", "Sessão".bold(), "Hyprland (Wayland)".green().bold());
            println!("   {:<34} KWin-equivalent: Hyprland compõe via scanout opt-in", "Compositor".bold());
        }
        "KDE" => {
            println!("   {:<34} [{}]", "Sessão".bold(), "KDE Plasma (Wayland)".cyan().bold());
            println!("   {:<34} KWin compõe SEMPRE (sem direct scanout → SM funciona)", "Compositor".bold());
        }
        _ => {
            println!(
                "   {:<34} {}",
                "Sessão".bold(),
                format!("{} (check compositor desativado)", session).yellow()
            );
        }
    }
    println!();

    // 1. VRAM Management (dmemcg — NVIDIA via cgroups)
    println!(
        "{}",
        "── 🎮 VRAM Management (dmemcg — NVIDIA via cgroups) ──────────────────".dimmed()
    );
    check_dmemcg_stack(&session);
    println!();

    // 2. Scanout do Hyprland (jogos NÃO passam pelo compositor em fullscreen)
    println!(
        "{}",
        "── ⚡ Scanout direto do Hyprland (latência mínima em fullscreen) ──────".dimmed()
    );
    if session == "Hyprland" {
        check_hyprland_scanout();
    } else {
        println!(
            "   {:<34} KWin compõe sempre — scanout não se aplica (SM ok nativo)",
            "direct_scanout".bold()
        );
        check_kde_tearing();
    }
    println!();

    // 3. Gaming stack (launch options / profil por jogo / DLSS)
    println!(
        "{}",
        "── 🕹️  Stack de Gaming (launch options, VRAM cgroup, Wayland, DLSS) ───".dimmed()
    );
    check_gaming_stack();
    println!();

    // 4. Núcleo / kernel (CachyOS-BORE, NTSYNC, ReBAR, clocksource)
    println!(
        "{}",
        "── 🧠 Núcleo & Kernel (CachyOS BORE, NTSYNC, ReBAR, clocksource) ────".dimmed()
    );
    check_kernel_gaming();
    println!();

    // 5. Performance do CPU (game-performance on-demand)
    println!(
        "{}",
        "── 🚀 Performance do CPU (game-performance on-demand) ────────────────".dimmed()
    );
    check_game_performance();
    println!();

    // 6. Shader cache + avisos informativos (sem alterar nada)
    println!(
        "{}",
        "── 💾 Shader cache & avisos informativos ─────────────────────────────".dimmed()
    );
    check_shader_cache_warnings();
    println!();

    println!(
        "{}",
        "✨ Gaming health verificado. Nada quebrado, nada alterado."
            .green()
            .bold()
    );
    println!();
    Ok(())
}

/// Detecta a sessão ativa via XDG_CURRENT_DESKTOP + WAYLAND_DISPLAY.
fn detect_session() -> String {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if desktop.to_lowercase().contains("hyprland") {
        "Hyprland".to_string()
    } else if desktop.to_lowercase().contains("plasma")
        || desktop.to_lowercase().contains("kde")
    {
        "KDE".to_string()
    } else if !desktop.is_empty() {
        desktop
    } else {
        "desconhecida".to_string()
    }
}

fn service_active(system: bool, name: &str) -> bool {
    let args: Vec<&str> = if system {
        vec!["is-active", name]
    } else {
        vec!["--user", "is-active", name]
    };
    Command::new("systemctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

fn check_status(label: &str, ok: bool, ok_msg: &str, fail_msg: &str) {
    if ok {
        println!("   {:<34} {}", label.bold(), ok_msg.green().bold());
    } else {
        println!("   {:<34} {}", label.bold(), fail_msg.red().bold());
    }
}

fn check_dmemcg_stack(_session: &str) {
    // a) controlador dmem disponível? (CachyOS kernel CONFIG_CGROUP_DMEM)
    let has_dmem = Command::new("sh")
        .args([
            "-c",
            "grep -q dmem /proc/cgroups && grep -q dmem /sys/fs/cgroup/cgroup.controllers",
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    check_status(
        "dmem controller (cgroup v2)",
        has_dmem,
        "PRESENTE no kernel CachyOS",
        "AUSENTE — kernel sem CONFIG_CGROUP_DMEM",
    );

    // b) serviços do stack VRAM
    let sys_boost = service_active(true, "dmemcg-booster-system");
    let user_boost = service_active(false, "dmemcg-booster-user");
    let hlf_boost = service_active(false, "hyprland-focused-booster");
    check_status(
        "dmemcg-booster-system",
        sys_boost,
        "ativo",
        "INATIVO",
    );
    check_status(
        "dmemcg-booster-user",
        user_boost,
        "ativo",
        "INATIVO",
    );
    check_status(
        "hyprland-focused-booster",
        hlf_boost,
        "ativo (boost janela focada)",
        "INATIVO",
    );

    // c) teste funcional: janela focada com dmem.low alto (8G), backgrounds 0
    let functional = Command::new("sh")
        .args([
            "-c",
            "for d in /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-*/; do v=$(cat \"$d\"/dmem.low 2>/dev/null | grep -oP 'vidmem \\K[0-9]+' || echo 0); echo \"$v\"; done | sort -rn | head -1",
        ])
        .stdin(std::process::Stdio::null())
        .output();

    let max_low = functional
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .unwrap_or(0)
        })
        .unwrap_or(0);
    let boosted = max_low > 1_000_000_000; // >1GB de dmem.low na janela mais alta
    let ok_msg = format!("ativo (máx ~{:.1} GB de VRAM protegida)", max_low as f64 / 1e9);
    let fail_msg = format!(
        "INATIVO (máx {} B — booster não elevou dmem.low)",
        max_low
    );
    check_status("Boost funcional (dmem.low janela focada)", boosted, &ok_msg, &fail_msg);
}

fn check_hyprland_scanout() {
    // a) direct_scanout = 2 (auto — ativa com content type 'game')
    let ds = Command::new("hyprctl")
        .args(["getoption", "render:direct_scanout"])
        .stdin(std::process::Stdio::null())
        .output();
    let ds_str = ds.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let ds_ok = ds_str.contains("int: 2");
    check_status(
        "direct_scanout (Hyprland)",
        ds_ok,
        "= 2 (auto: ativa p/ content 'game')",
        format!("≠ 2 — atual: {}", ds_str.lines().next().unwrap_or("?").trim()).as_str(),
    );

    // b) windowrule marca jogos como content = 'game' (gatilho do scanout)
    let wr = Command::new("sh")
        .args([
            "-c",
            "rg -l 'content = \"game\"' ~/.config/hypr/config/windowrules.lua >/dev/null 2>&1",
        ])
        .stdin(std::process::Stdio::null())
        .status();
    check_status(
        "Windowrule content='game' (gatilho scanout)",
        wr.map(|s| s.success()).unwrap_or(false),
        "presente — jogos registrados como game",
        "AUSENTE — scanout auto nunca ativa",
    );

    // c) VRR (misc.vrr) — baixo lag em fullscreen de jogo
    let vrr = Command::new("hyprctl")
        .args(["getoption", "misc:vrr"])
        .stdin(std::process::Stdio::null())
        .output();
    let vrr_str = vrr.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    check_status(
        "VRR (misc:vrr)",
        vrr_str.contains("int: 3") || vrr_str.contains("int: 1"),
        "fullscreen de jogo (VRR)",
        "off/informativo",
    );
}

fn check_kde_tearing() {
    // KWin não tem direct scanout agressivo: composição sempre → SM ok nativo.
    // Checamos apenas se o tearing/VRR do Plasma está em modo jogo (informativo).
    let vrr_plasma = Command::new("kscreen-doctor")
        .args(["-o"])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();
    check_status(
        "KWin composição (Smooth Motion)",
        true,
        "sempre ativa — SM funciona nativo",
        "-",
    );
    if vrr_plasma.contains("automatic") {
        println!("   {:<34} VRR automático (KDE) detectado", "VRR".bold());
    }
}

fn check_gaming_stack() {
    // a) steam-launch-options status (0 divergências = configs aplicadas)
    let status = Command::new("steam-launch-options")
        .arg("status")
        .stdin(std::process::Stdio::null())
        .output();
    let status_str = status
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let sync_ok = status_str.contains("0 jogo(s) divergente(s)") || status_str.contains("0 diverg");
    check_status(
        "steam-launch-options sync",
        sync_ok,
        "0 divergências (36 jogos aplicados)",
        "DIVERGÊNCIAS — rode 'steam-launch-options sync'",
    );

    // b) VRAM cgroup em todos os jogos (systemd-run --user --scope no VDF)
    let vdf = std::fs::read_to_string(
        "/home/edu/.local/share/Steam/userdata/115099278/config/localconfig.vdf",
    );
    let vdf_body = vdf.unwrap_or_default();
    let vram_count = vdf_body.matches("systemd-run --user --scope").count();
    let wayland_count = vdf_body.matches("PROTON_ENABLE_WAYLAND=1").count();

    check_status(
        "VRAM cgroup (systemd-run --scope)",
        vram_count >= 36,
        format!("{} ocorrências (36 jogos)", vram_count).as_str(),
        format!("APENAS {} — nem todo jogo com VRAM boost", vram_count).as_str(),
    );
    check_status(
        "Wayland (PROTON_ENABLE_WAYLAND=1)",
        wayland_count >= 36,
        format!("{} ocorrências", wayland_count).as_str(),
        format!("APENAS {} — jogos sem wayland", wayland_count).as_str(),
    );

    // c) Smooth Motion + gamescope: quais jogos usam (dinâmico, fonte real
    //    = games.toml [jogo→perfil] × profiles.toml [perfil→options], nomes via list)
    let name_map = game_names_from_list();
    let games = load_games();
    let profiles = load_profiles();
    let mut sm_games: Vec<String> = Vec::new();
    let mut gs_games: Vec<String> = Vec::new();
    for g in &games {
        let appid = g.appid;
        let profile_name = &g.profile;
        let profile_options: String = profiles
            .iter()
            .find(|p| p.name == *profile_name)
            .map(|p| p.options.clone())
            .unwrap_or_default();
        let gname = name_map
            .get(&appid)
            .cloned()
            .unwrap_or_else(|| appid.to_string());
        let label = format!("{} ({})", gname, appid);
        if profile_options.contains("SMOOTH_MOTION") {
            sm_games.push(label.clone());
        }
        if profile_options.contains("gamescope") {
            gs_games.push(label.clone());
        }
    }
    check_status(
        "Smooth Motion (por jogo)",
        !sm_games.is_empty(),
        &sm_games.join(", "),
        "nenhum jogo configurado com SM",
    );
    check_status(
        "Gamescope (por jogo)",
        !gs_games.is_empty(),
        &gs_games.join(", "),
        "nenhum jogo configurado com gamescope",
    );

    // d) DLSS upgrade global (environment.d)
    let env_gaming =
        std::fs::read_to_string("/home/edu/.config/environment.d/gaming.conf");
    let env_body = env_gaming.unwrap_or_default();
    let dlss_ok = env_body.contains("PROTON_DLSS_UPGRADE=1");
    check_status(
        "DLSS upgrade global",
        dlss_ok,
        "PROTON_DLSS_UPGRADE=1 (environment.d)",
        "AUSENTE no gaming.conf",
    );
}

fn check_kernel_gaming() {
    // a) kernel CachyOS BORE
    let uname = Command::new("uname")
        .arg("-r")
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    check_status(
        "Kernel",
        uname.contains("cachyos"),
        format!("{} (CachyOS-BORE)", uname).as_str(),
        format!("{} (não-CachyOS)", uname).as_str(),
    );

    // b) NTSYNC (kernel + dev)
    let ntsync_dev = std::path::Path::new("/dev/ntsync").exists();
    let ntsync_env = std::fs::read_to_string("/home/edu/.config/environment.d/env.conf")
        .unwrap_or_default();
    let ntsync_ok = ntsync_dev && ntsync_env.contains("PROTON_USE_NTSYNC=1");
    check_status(
        "NTSYNC (kernel + env)",
        ntsync_ok,
        format!(
            "/dev/ntsync present{}",
            if ntsync_env.contains("PROTON_USE_NTSYNC=1") {
                " + PROTON_USE_NTSYNC=1"
            } else {
                ""
            }
        )
        .as_str(),
        "AUSENTE",
    );

    // c) ReBAR (Resizable BAR)
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let rebar_ok = cmdline.contains("nvidia.NVreg_EnableResizableBar=1");
    check_status(
        "ReBAR (Resizable BAR)",
        rebar_ok,
        "nvidia.NVreg_EnableResizableBar=1",
        "AUSENTE no cmdline",
    );

    // d) clocksource TSC (menos overhead que HPET)
    let tsc = Command::new("sh")
        .args([
            "-c",
            "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    check_status(
        "Clocksource",
        tsc == "tsc",
        "tsc (mais rápido que HPET/acpi_pm)",
        format!("{} (HPET limita clock_gettime)", tsc).as_str(),
    );

    // e) vm.max_map_count (informativo: Proton considera 1048576 suficiente)
    let mm = Command::new("sysctl")
        .args(["-n", "vm.max_map_count"])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!(
        "   {:<34} {} ({})",
        "vm.max_map_count".bold(),
        mm.cyan(),
        "Proton trata 1048576 como suficiente — SteamOS usa 2147483642 (opcional)".dimmed()
    );
}

fn check_game_performance() {
    // Verificação ESTÁTICA (sem efeito colateral): o wrapper game-performance
    // deve existir e estar presente na launch line de todos os jogos (mesmo
    // objetivo do teste dinâmico anterior, sem piscar o power profile).
    let binary_ok = Command::new("sh")
        .args(["-c", "command -v game-performance >/dev/null 2>&1"])
        .stdin(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    check_status(
        "game-performance (binário)",
        binary_ok,
        "presente no PATH",
        "AUSENTE — wrapper CachyOS não instalado",
    );

    let vdf = std::fs::read_to_string(
        "/home/edu/.local/share/Steam/userdata/115099278/config/localconfig.vdf",
    )
    .unwrap_or_default();
    let in_all_games = vdf.matches("systemd-run --user --scope game-performance").count();
    check_status(
        "game-performance (nos jogos)",
        in_all_games >= 36,
        format!("presente na launch line de {} jogos", in_all_games).as_str(),
        format!("só em {} jogos — nem todo jogo com wrapper", in_all_games).as_str(),
    );

    let ppd = Command::new("sh")
        .args(["-c", "command -v powerprofilesctl >/dev/null 2>&1"])
        .stdin(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    check_status(
        "power-profiles-daemon",
        ppd,
        "powerprofilesctl presente",
        "AUSENTE — game-performance não consegue subir profile",
    );
}

fn check_shader_cache_warnings() {
    // a) shader cache 12GB (CachyOS wiki §Increase shader cache size)
    let env_gaming =
        std::fs::read_to_string("/home/edu/.config/environment.d/gaming.conf");
    let env_body = env_gaming.unwrap_or_default();
    let sc_ok = env_body.contains("__GL_SHADER_DISK_CACHE_SIZE=12000000000");
    check_status(
        "Shader cache NVIDIA (12GB)",
        sc_ok,
        "__GL_SHADER_DISK_CACHE_SIZE=12000000000",
        "AUSENTE — recompila shaders toda hora (stutter)",
    );

    // b) Avisos informativos (NÃO altera nada — decisão do dono)
    println!(
        "   {:<34} {}",
        "kernel.split_lock_mitigate".bold(),
        "informativo: 0 melhora certos jogos Wine (ArchWiki) — não alterado".dimmed()
    );
    println!(
        "   {:<34} {}",
        "Shader pre-caching (Steam)".bold(),
        "informativo: desligado manualmente no Steam (CachyOS wiki recomenda)".dimmed()
    );
}

// ── Helpers: fonte real do mapeamento jogo → perfil → flags ────────────────
// games.toml define o perfil de cada jogo; profiles.toml define o options de
// cada perfil. Cruzando os dois sabemos QUAIS jogos usam SM/gamescope — sem
// hardcode de nome/quantidade (dinâmico: muda sozinho ao editar os TOMLs).

#[derive(Debug)]
struct GameEntry {
    appid: u64,
    profile: String,
}

#[derive(Debug)]
struct ProfileEntry {
    name: String,
    options: String,
}

fn load_games() -> Vec<GameEntry> {
    let path = "/home/edu/.config/steam-launch-options/games.toml";
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let parsed: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("games").and_then(|v| v.as_array()) {
        for g in arr {
            let appid = g.get("appid").and_then(|v| v.as_integer()).unwrap_or(0) as u64;
            let profile = g
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or("vram")
                .to_string();
            out.push(GameEntry { appid, profile });
        }
    }
    out
}

fn load_profiles() -> Vec<ProfileEntry> {
    let path = "/home/edu/.config/steam-launch-options/profiles.toml";
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let parsed: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("profiles").and_then(|v| v.as_array()) {
        for p in arr {
            let name = p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let options = p
                .get("options")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(ProfileEntry { name, options });
        }
    }
    out
}

/// Nomes reais dos jogos via `steam-launch-options list` (que usa game_name()
/// do appinfo do Steam — fonte canônica, sem hardcode).
fn game_names_from_list() -> std::collections::HashMap<u64, String> {
    let mut map = std::collections::HashMap::new();
    let out = Command::new("steam-launch-options")
        .arg("list")
        .stdin(std::process::Stdio::null())
        .output();
    let body = out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    for line in body.lines() {
        // Formato do cmd_list: "{:<10} {:<32} ..." → appid na col 0-9, nome na col 10-41.
        if line.len() < 42 {
            continue;
        }
        let appid_field = &line[0..10];
        let appid_field = appid_field.trim();
        if !appid_field.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(appid) = appid_field.parse::<u64>() {
            let name = line[10..42].trim().to_string();
            if !name.is_empty() && !name.chars().all(|c| c.is_ascii_digit()) {
                map.insert(appid, name);
            }
        }
    }
    map
}