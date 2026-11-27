//! Transport security of the HTTP MCP server, exercised against the real binary.
//! MCP 2026-07-28, Streamable HTTP, "Security & Endpoint": validate `Origin` (403), bind to
//! loopback, authenticate. https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "test-only-token-0123456789abcdef0123456789";
const BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or_default()
}

fn command(port: u16, extra: &[&str], env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_stenio"));
    c.args(["--mcp-sse", "--mcp-port", &port.to_string()])
        .args(extra)
        .env_remove("STENIO_MCP_TOKEN")
        .env_remove("STENIO_MCP_ALLOWED_HOSTS")
        .env_remove("STENIO_MCP_ALLOWED_ORIGINS")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    c
}

fn start(extra: &[&str], env: &[(&str, &str)]) -> Option<Server> {
    let port = free_port();
    let child = command(port, extra, env)
        .stdout(Stdio::null())
        .spawn()
        .ok()?;
    let server = Server { child, port };
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Sends one raw request and returns the lower-cased response head and body.
fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> String {
    let body = if method == "POST" { BODY } else { "" };
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers.iter().any(|(k, _)| *k == "Host") {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    let mut out = String::new();
    if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        if s.write_all(req.as_bytes()).is_ok() {
            let _ = s.read_to_string(&mut out);
        }
    }
    out.to_lowercase()
}

fn status(response: &str) -> &str {
    response.split_whitespace().nth(1).unwrap_or("none")
}

#[test]
fn unparseable_bind_is_a_startup_error() {
    for host in ["nonsense", "100.64.0.999", ""] {
        let child = command(free_port(), &["--mcp-host", host], &[]).spawn();
        assert!(child.is_ok());
        let Ok(mut child) = child else { return };
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut exit = None;
        while exit.is_none() && Instant::now() < deadline {
            exit = child.try_wait().ok().flatten();
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(exit.map(|e| e.success()), Some(false), "bind '{host}'");
    }
}

#[test]
fn default_bind_is_loopback() {
    let port = free_port();
    let child = command(port, &[], &[]).spawn();
    assert!(child.is_ok());
    let Ok(mut child) = child else { return };
    let mut seen = String::new();
    if let Some(mut out) = child.stdout.take() {
        let mut buf = [0u8; 512];
        while !seen.contains("/health") {
            match out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(seen.contains(&format!("127.0.0.1:{port}")), "{seen}");
    assert!(!seen.contains("0.0.0.0"), "{seen}");
}

#[test]
fn foreign_origin_is_forbidden_and_no_cors_is_granted() {
    let server = start(&[], &[]);
    assert!(server.is_some());
    let Some(s) = server else { return };
    let evil = [("Origin", "http://evil.example")];
    for (method, path) in [("POST", "/message"), ("GET", "/sse"), ("GET", "/health")] {
        let r = send(s.port, method, path, &evil);
        assert_eq!(status(&r), "403", "{method} {path}");
        assert!(!r.contains("access-control-allow"), "{r}");
    }
    let preflight = send(s.port, "OPTIONS", "/message", &evil);
    assert!(!preflight.contains("access-control-allow"), "{preflight}");
    let plain = send(s.port, "POST", "/message", &[]);
    assert_eq!(status(&plain), "200");
    assert!(plain.contains("stenio_scan"));
    assert!(!plain.contains("access-control-allow"), "{plain}");
}

#[test]
fn listed_origin_is_served() {
    let server = start(&[], &[("STENIO_MCP_ALLOWED_ORIGINS", "http://app.example")]);
    assert!(server.is_some());
    let Some(s) = server else { return };
    let r = send(
        s.port,
        "POST",
        "/message",
        &[("Origin", "http://app.example")],
    );
    assert_eq!(status(&r), "200");
}

#[test]
fn foreign_host_is_forbidden_and_listed_host_is_served() {
    let server = start(&[], &[("STENIO_MCP_ALLOWED_HOSTS", "kuaray, 100.64.0.1")]);
    assert!(server.is_some());
    let Some(s) = server else { return };
    let bad = send(s.port, "POST", "/message", &[("Host", "evil.example:9099")]);
    assert_eq!(status(&bad), "403");
    for host in ["kuaray:9099", "100.64.0.1", "localhost:9099", "[::1]:9099"] {
        let r = send(s.port, "POST", "/message", &[("Host", host)]);
        assert_eq!(status(&r), "200", "{host}");
    }
}

#[test]
fn configured_token_is_required_except_on_health() {
    let server = start(&[], &[("STENIO_MCP_TOKEN", TOKEN)]);
    assert!(server.is_some());
    let Some(s) = server else { return };
    for (method, path) in [("POST", "/message"), ("GET", "/sse")] {
        let r = send(s.port, method, path, &[]);
        assert_eq!(status(&r), "401", "{method} {path}");
        assert!(r.contains("www-authenticate: bearer"), "{r}");
    }
    let wrong = format!("Bearer {TOKEN}x");
    let r = send(s.port, "POST", "/message", &[("Authorization", &wrong)]);
    assert_eq!(status(&r), "401");
    let good = format!("Bearer {TOKEN}");
    let r = send(s.port, "POST", "/message", &[("Authorization", &good)]);
    assert_eq!(status(&r), "200");
    assert_eq!(status(&send(s.port, "GET", "/health", &[])), "200");
}

#[test]
fn short_or_empty_token_is_a_startup_error() {
    for token in ["", "short"] {
        let out = command(free_port(), &[], &[("STENIO_MCP_TOKEN", token)]).spawn();
        assert!(out.is_ok());
        let Ok(mut child) = out else { return };
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut exit = None;
        while exit.is_none() && Instant::now() < deadline {
            exit = child.try_wait().ok().flatten();
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(exit.map(|e| e.success()), Some(false), "token '{token}'");
    }
}
