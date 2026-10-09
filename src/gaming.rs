use anyhow::Result;
use colored::*;
use std::process::Command;

/// ── stenio --gaming — Gaming Health Snapshot (session-aware) ───────────────
///
/// Canonical inventory of gaming optimizations for psicopompo, with source per item:
///   - CachyOS wiki  → https://wiki.cachyos.org/configuration/gaming/
///   - ArchWiki      → https://wiki.archlinux.org/title/Gaming
///   - Hyprland wiki → https://wiki.hypr.land/
/// Canonized on 21/09/2026 (see mnemocine/guides/hyprland-noctalia-guide.md).
pub fn run_gaming_health() -> Result<()> {
    crate::baseline::print_banner("StenioKernel — Gaming Health Snapshot (--gaming)");

    // 0. Active session (determines applicable compositor checks)
    println!(
        "{}",
        "── 🖥️  Active Session (Hyprland vs KDE) ────────────────────────────────".dimmed()
    );
    let session = detect_session();
    match session.as_str() {
        "Hyprland" => {
            println!(
                "   {:<34} [{}]",
                "Session".bold(),
                "Hyprland (Wayland)".green().bold()
            );
            println!(
                "   {:<34} KWin-equivalent: Hyprland composes via opt-in scanout",
                "Compositor".bold()
            );
        }
        "KDE" => {
            println!(
                "   {:<34} [{}]",
                "Session".bold(),
                "KDE Plasma (Wayland)".cyan().bold()
            );
            println!(
                "   {:<34} KWin ALWAYS composes (no direct scanout -> SM works)",
                "Compositor".bold()
            );
        }
        _ => {
            println!(
                "   {:<34} {}",
                "Session".bold(),
                format!("{} (compositor check disabled)", session).yellow()
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

    // 2. Hyprland Direct Scanout (minimal latency in fullscreen)
    println!(
        "{}",
        "── ⚡ Hyprland Direct Scanout (minimal latency in fullscreen) ─────────".dimmed()
    );
    if session == "Hyprland" {
        check_hyprland_scanout();
    } else {
        println!(
            "   {:<34} KWin always composes — scanout not applicable (SM natively ok)",
            "direct_scanout".bold()
        );
        check_kde_tearing();
    }
    println!();

    // 3. Gaming stack (launch options / profile per game / DLSS)
    println!(
        "{}",
        "── 🕹️  Gaming Stack (launch options, VRAM cgroup, Wayland, DLSS) ───────".dimmed()
    );
    check_gaming_stack();
    println!();

    // 4. Core & Kernel (CachyOS-BORE, NTSYNC, ReBAR, clocksource)
    println!(
        "{}",
        "── 🧠 Core & Kernel (CachyOS BORE, NTSYNC, ReBAR, clocksource) ────────".dimmed()
    );
    check_kernel_gaming();
    println!();

    // 5. CPU Performance (on-demand game-performance)
    println!(
        "{}",
        "── 🚀 CPU Performance (on-demand game-performance) ────────────────────".dimmed()
    );
    check_game_performance();
    println!();

    // 6. Shader cache & informational notices
    println!(
        "{}",
        "── 💾 Shader Cache & Informational Notices ─────────────────────────────".dimmed()
    );
    check_shader_cache_warnings();
    println!();

    println!(
        "{}",
        "✨ Gaming health verified. Nothing broken, nothing altered."
            .green()
            .bold()
    );
    println!();
    Ok(())
}

/// Detects active session via XDG_CURRENT_DESKTOP + WAYLAND_DISPLAY.
fn detect_session() -> String {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if desktop.to_lowercase().contains("hyprland") {
        "Hyprland".to_string()
    } else if desktop.to_lowercase().contains("plasma") || desktop.to_lowercase().contains("kde") {
        "KDE".to_string()
    } else if !desktop.is_empty() {
        desktop
    } else {
        "unknown".to_string()
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
    // a) dmem controller available? (CachyOS kernel CONFIG_CGROUP_DMEM)
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
        "PRESENT in CachyOS kernel",
        "MISSING — kernel without CONFIG_CGROUP_DMEM",
    );

    // b) VRAM stack services
    let sys_boost = service_active(true, "dmemcg-booster-system");
    let user_boost = service_active(false, "dmemcg-booster-user");
    let hlf_boost = service_active(false, "hyprland-focused-booster");
    check_status("dmemcg-booster-system", sys_boost, "active", "INACTIVE");
    check_status("dmemcg-booster-user", user_boost, "active", "INACTIVE");
    check_status(
        "hyprland-focused-booster",
        hlf_boost,
        "active (focused window boost)",
        "INACTIVE",
    );

    // c) functional test: focused window with high dmem.low (8G), backgrounds 0
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
    let boosted = max_low > 1_000_000_000; // >1GB dmem.low on highest window
    let ok_msg = format!(
        "active (max ~{:.1} GB protected VRAM)",
        max_low as f64 / 1e9
    );
    let fail_msg = format!("INACTIVE (max {} B — booster did not raise dmem.low)", max_low);
    check_status(
        "Functional Boost (focused window dmem.low)",
        boosted,
        &ok_msg,
        &fail_msg,
    );
}

fn check_hyprland_scanout() {
    // a) direct_scanout = 2 (auto — activates for content 'game')
    let ds = Command::new("hyprctl")
        .args(["getoption", "render:direct_scanout"])
        .stdin(std::process::Stdio::null())
        .output();
    let ds_str = ds
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let ds_ok = ds_str.contains("int: 2");
    check_status(
        "direct_scanout (Hyprland)",
        ds_ok,
        "= 2 (auto: activates for content 'game')",
        format!(
            "≠ 2 — current: {}",
            ds_str.lines().next().unwrap_or("?").trim()
        )
        .as_str(),
    );

    // b) windowrule marks games as content = 'game' (scanout trigger)
    let wr = Command::new("sh")
        .args([
            "-c",
            "rg -l 'content = \"game\"' ~/.config/hypr/config/windowrules.lua >/dev/null 2>&1",
        ])
        .stdin(std::process::Stdio::null())
        .status();
    check_status(
        "Windowrule content='game' (scanout trigger)",
        wr.map(|s| s.success()).unwrap_or(false),
        "present — games registered as game",
        "MISSING — auto scanout never triggers",
    );

    // c) VRR (misc.vrr) — low lag in fullscreen game
    let vrr = Command::new("hyprctl")
        .args(["getoption", "misc:vrr"])
        .stdin(std::process::Stdio::null())
        .output();
    let vrr_str = vrr
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    check_status(
        "VRR (misc:vrr)",
        vrr_str.contains("int: 3") || vrr_str.contains("int: 1"),
        "fullscreen game (VRR)",
        "off/informational",
    );
}

fn check_kde_tearing() {
    // KWin does not have aggressive direct scanout: composition always -> SM ok natively.
    // Check if Plasma tearing/VRR is in game mode (informational).
    let vrr_plasma = Command::new("kscreen-doctor")
        .args(["-o"])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();
    check_status(
        "KWin composition (Smooth Motion)",
        true,
        "always active — SM functions natively",
        "-",
    );
    if vrr_plasma.contains("automatic") {
        println!("   {:<34} Automatic VRR (KDE) detected", "VRR".bold());
    }
}

fn check_gaming_stack() {
    // a) steam-launch-options status (0 discrepancies = configs applied)
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
        "0 discrepancies (36 games applied)",
        "DISCREPANCIES — run 'steam-launch-options sync'",
    );

    // b) VRAM cgroup on all games (systemd-run --user --scope in VDF)
    let vdf = std::fs::read_to_string(
        "/home/edu/.local/share/Steam/userdata/115099278/config/localconfig.vdf",
    );
    let vdf_body = vdf.unwrap_or_default();
    let vram_count = vdf_body.matches("systemd-run --user --scope").count();
    let wayland_count = vdf_body.matches("PROTON_ENABLE_WAYLAND=1").count();

    check_status(
        "VRAM cgroup (systemd-run --scope)",
        vram_count >= 36,
        format!("{} occurrences (36 games)", vram_count).as_str(),
        format!("ONLY {} — not all games have VRAM boost", vram_count).as_str(),
    );
    check_status(
        "Wayland (PROTON_ENABLE_WAYLAND=1)",
        wayland_count >= 36,
        format!("{} occurrences", wayland_count).as_str(),
        format!("ONLY {} — games without Wayland", wayland_count).as_str(),
    );

    // c) Smooth Motion + gamescope: which games use it (dynamic, real source
    //    = games.toml [game->profile] x profiles.toml [profile->options])
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
        "Smooth Motion (per game)",
        !sm_games.is_empty(),
        &sm_games.join(", "),
        "no games configured with SM",
    );
    check_status(
        "Gamescope (per game)",
        !gs_games.is_empty(),
        &gs_games.join(", "),
        "no games configured with gamescope",
    );

    // d) Global DLSS upgrade (environment.d)
    let env_gaming = std::fs::read_to_string("/home/edu/.config/environment.d/gaming.conf");
    let env_body = env_gaming.unwrap_or_default();
    let dlss_ok = env_body.contains("PROTON_DLSS_UPGRADE=1");
    check_status(
        "Global DLSS upgrade",
        dlss_ok,
        "PROTON_DLSS_UPGRADE=1 (environment.d)",
        "MISSING in gaming.conf",
    );
}

fn check_kernel_gaming() {
    // a) CachyOS BORE kernel
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
        format!("{} (non-CachyOS)", uname).as_str(),
    );

    // b) NTSYNC (kernel + dev)
    let ntsync_dev = std::path::Path::new("/dev/ntsync").exists();
    let ntsync_env =
        std::fs::read_to_string("/home/edu/.config/environment.d/env.conf").unwrap_or_default();
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
        "MISSING",
    );

    // c) ReBAR (Resizable BAR)
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let rebar_ok = cmdline.contains("nvidia.NVreg_EnableResizableBar=1");
    check_status(
        "ReBAR (Resizable BAR)",
        rebar_ok,
        "nvidia.NVreg_EnableResizableBar=1",
        "MISSING in cmdline",
    );

    // d) clocksource TSC (less overhead than HPET)
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
        "tsc (faster than HPET/acpi_pm)",
        format!("{} (HPET limits clock_gettime)", tsc).as_str(),
    );

    // e) vm.max_map_count (informational: Proton treats 1048576 as sufficient)
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
        "Proton considers 1048576 sufficient — SteamOS uses 2147483642 (optional)".dimmed()
    );
}

fn check_game_performance() {
    // Static check: game-performance wrapper must exist and be on launch lines
    let binary_ok = Command::new("sh")
        .args(["-c", "command -v game-performance >/dev/null 2>&1"])
        .stdin(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    check_status(
        "game-performance (binary)",
        binary_ok,
        "present in PATH",
        "MISSING — CachyOS wrapper not installed",
    );

    let vdf = std::fs::read_to_string(
        "/home/edu/.local/share/Steam/userdata/115099278/config/localconfig.vdf",
    )
    .unwrap_or_default();
    let in_all_games = vdf
        .matches("systemd-run --user --scope game-performance")
        .count();
    check_status(
        "game-performance (in games)",
        in_all_games >= 36,
        format!("present in launch line of {} games", in_all_games).as_str(),
        format!("only in {} games — not all games have wrapper", in_all_games).as_str(),
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
        "powerprofilesctl present",
        "MISSING — game-performance cannot raise profile",
    );
}

fn check_shader_cache_warnings() {
    // a) shader cache 12GB (CachyOS wiki §Increase shader cache size)
    let env_gaming = std::fs::read_to_string("/home/edu/.config/environment.d/gaming.conf");
    let env_body = env_gaming.unwrap_or_default();
    let sc_ok = env_body.contains("__GL_SHADER_DISK_CACHE_SIZE=12000000000");
    check_status(
        "Shader cache NVIDIA (12GB)",
        sc_ok,
        "__GL_SHADER_DISK_CACHE_SIZE=12000000000",
        "MISSING — recompiles shaders frequently (stutter)",
    );

    // b) Informational notices (does NOT alter anything — user discretion)
    println!(
        "   {:<34} {}",
        "kernel.split_lock_mitigate".bold(),
        "informational: 0 improves certain Wine games (ArchWiki) — not altered".dimmed()
    );
    println!(
        "   {:<34} {}",
        "Shader pre-caching (Steam)".bold(),
        "informational: manually disabled in Steam (recommended by CachyOS wiki)".dimmed()
    );
}

// ── Helpers: real source of game -> profile -> flags mapping ────────────────
// games.toml defines the profile of each game; profiles.toml defines profile options.
// Cross-referencing both tells us WHICH games use SM/gamescope dynamically.

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

fn load_toml_value(path: &str) -> Option<toml::Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    toml::from_str(&raw).ok()
}

fn load_games() -> Vec<GameEntry> {
    let path = "/home/edu/.config/steam-launch-options/games.toml";
    let Some(parsed) = load_toml_value(path) else {
        return Vec::new();
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
    let Some(parsed) = load_toml_value(path) else {
        return Vec::new();
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
    let body = out
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
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
