//! Transport security of the HTTP MCP server: bind address, `Host` and `Origin` validation and
//! bearer token. MCP 2026-07-28, Streamable HTTP, "Security & Endpoint":
//! <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>

use anyhow::{Context, Result, bail};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

const HOSTS_ENV: &str = "STENIO_MCP_ALLOWED_HOSTS";
const ORIGINS_ENV: &str = "STENIO_MCP_ALLOWED_ORIGINS";
const TOKEN_ENV: &str = "STENIO_MCP_TOKEN";
const MIN_TOKEN_LEN: usize = 32;

pub struct HttpPolicy {
    hosts: Vec<String>,
    origins: Vec<String>,
    token: Option<[u8; 32]>,
}

/// Parses an IP literal. Anything else is an error: there is no fallback address.
pub fn parse_bind(host: &str) -> Result<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .with_context(|| format!("--mcp-host '{host}' is not an IP address"))
}

fn list(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn host_form(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The `Host` header without its port, keeping the brackets of an IPv6 literal.
fn host_name(value: &str) -> &str {
    if value.starts_with('[') {
        return value.find(']').map_or(value, |end| &value[..=end]);
    }
    value.rsplit_once(':').map_or(value, |(name, _)| name)
}

impl HttpPolicy {
    pub fn from_env(bind: IpAddr) -> Result<Self> {
        let token = match std::env::var(TOKEN_ENV) {
            Ok(t) => Some(t),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => bail!("{TOKEN_ENV} is unreadable: {e}"),
        };
        Self::new(
            bind,
            std::env::var(HOSTS_ENV).ok(),
            std::env::var(ORIGINS_ENV).ok(),
            token,
        )
    }

    fn new(
        bind: IpAddr,
        hosts: Option<String>,
        origins: Option<String>,
        token: Option<String>,
    ) -> Result<Self> {
        let mut allowed = list(hosts);
        allowed.extend(["localhost", "127.0.0.1", "[::1]"].map(String::from));
        if !bind.is_unspecified() {
            allowed.push(host_form(bind));
        }
        // A token that is set but unusable must never degrade to "no authentication".
        let token = match token {
            Some(t) if t.trim().len() < MIN_TOKEN_LEN => {
                bail!("{TOKEN_ENV} is set but shorter than {MIN_TOKEN_LEN} characters")
            }
            Some(t) => Some(Sha256::digest(t.trim().as_bytes()).into()),
            None => None,
        };
        Ok(Self {
            hosts: allowed,
            origins: list(origins),
            token,
        })
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn check(&self, path: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
            .ok_or(StatusCode::FORBIDDEN)?;
        if !self.hosts.iter().any(|h| h == host_name(&host)) {
            return Err(StatusCode::FORBIDDEN);
        }
        // Non-browser MCP clients send no Origin; a present one must be listed.
        for origin in headers.get_all(header::ORIGIN) {
            let origin = origin.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
            if !self.origins.iter().any(|o| o.eq_ignore_ascii_case(origin)) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        let Some(expected) = &self.token else {
            return Ok(());
        };
        if path == "/health" {
            return Ok(());
        }
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, t)| Sha256::digest(t.trim().as_bytes()))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        // Compares fixed-size digests without an early exit.
        let diff = expected
            .iter()
            .zip(presented.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff == 0 {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

pub async fn enforce(
    State(policy): State<Arc<HttpPolicy>>,
    request: Request,
    next: Next,
) -> Response {
    match policy.check(request.uri().path(), request.headers()) {
        Ok(()) => next.run(request).await,
        Err(StatusCode::UNAUTHORIZED) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response(),
        Err(status) => status.into_response(),
    }
}
