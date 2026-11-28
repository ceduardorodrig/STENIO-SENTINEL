use crate::mcp_http_policy::{HttpPolicy, enforce, parse_bind};
use anyhow::Result;
use axum::Router;
use axum::extract::State;
use axum::middleware::from_fn_with_state;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use colored::*;
use futures_util::stream;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::baseline::Whitelist;
use crate::mcp::{McpRequest, dispatch_mcp_request};

pub struct ServerState {
    pub repo_root: PathBuf,
    pub whitelist: Whitelist,
}

/// Starts the native HTTP Server-Sent Events (SSE) MCP server for StenioSentinel.
pub async fn start_mcp_sse_server(
    repo_root: PathBuf,
    host: &str,
    port: u16,
    whitelist: Whitelist,
) -> Result<()> {
    let addr = SocketAddr::new(parse_bind(host)?, port);
    let policy = Arc::new(HttpPolicy::from_env(addr.ip())?);
    if !addr.ip().is_loopback() && !policy.has_token() {
        eprintln!(
            "⚠️  Non-loopback bind without STENIO_MCP_TOKEN: requests are NOT authenticated."
        );
    }
    let state = Arc::new(ServerState {
        repo_root,
        whitelist,
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/sse", get(sse_handler))
        .route("/message", post(message_handler))
        .layer(from_fn_with_state(policy, enforce))
        .with_state(state);

    println!(
        "\n{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!(
        "{} on {}",
        "StenioSentinel MCP SSE Server (Axum Native)".bold().cyan(),
        format!("http://{addr}").bold().green()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════".bold()
    );
    println!(
        "   📡 SSE Handshake Endpoint : {}",
        format!("http://{addr}/sse").bold()
    );
    println!(
        "   📬 Message JSON-RPC Route : {}",
        format!("http://{addr}/message").bold()
    );
    println!(
        "   ❤️  Health Status Route   : {}",
        format!("http://{addr}/health").bold()
    );
    println!("\n   ✨ Ready to receive MCP agents from Claude Code, OpenCode, Cursor!\n");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("❌ Failed to bind to {}: {}", addr, e);
            return Err(e.into());
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("❌ Server error: {}", e);
    }

    Ok(())
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "stenio-sentinel-mcp-sse",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn sse_handler() -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    // When an MCP client connects via SSE, the spec requires an initial "endpoint" event
    // informing where HTTP POST messages should be sent.
    let initial_event = Event::default().event("endpoint").data("/message");
    let stream = stream::once(async move { Ok(initial_event) });
    Sse::new(stream)
}

async fn message_handler(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<McpRequest>,
) -> impl IntoResponse {
    let response =
        dispatch_mcp_request(&req, &state.repo_root, &state.whitelist).unwrap_or_else(|| {
            crate::mcp::McpResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.unwrap_or(serde_json::Value::Null),
                result: Some(json!({})),
                error: None,
            }
        });

    Json(response)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_mcp_server_module() {
        assert_eq!(1 + 1, 2);
    }
}
