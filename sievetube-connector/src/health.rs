use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::Encoder;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct ConnectorHealth {
    inner: Arc<RwLock<HealthInner>>,
}

#[derive(Debug)]
struct HealthInner {
    draining: bool,
    edges: BTreeMap<String, EdgeState>,
}

#[derive(Debug, Clone)]
struct EdgeState {
    status: &'static str,
    changed_at: u64,
    last_error: Option<String>,
}

impl ConnectorHealth {
    pub fn new(servers: &[String]) -> Self {
        let changed_at = unix_time();
        let edges = servers
            .iter()
            .map(|server| {
                (
                    server.clone(),
                    EdgeState {
                        status: "starting",
                        changed_at,
                        last_error: None,
                    },
                )
            })
            .collect();
        Self {
            inner: Arc::new(RwLock::new(HealthInner {
                draining: false,
                edges,
            })),
        }
    }

    pub fn connecting(&self, server: &str) {
        self.update(server, "connecting", None);
    }

    pub fn connected(&self, server: &str) {
        self.update(server, "connected", None);
    }

    pub fn disconnected(&self, server: &str, error: impl std::fmt::Display) {
        self.update(server, "disconnected", Some(error.to_string()));
    }

    pub fn set_draining(&self) {
        self.inner.write().expect("health lock poisoned").draining = true;
    }

    pub fn connected_edges(&self) -> Vec<String> {
        self.inner
            .read()
            .expect("health lock poisoned")
            .edges
            .iter()
            .filter(|(_, state)| state.status == "connected")
            .map(|(server, _)| server.clone())
            .collect()
    }

    pub fn is_ready(&self) -> bool {
        let inner = self.inner.read().expect("health lock poisoned");
        !inner.draining
            && inner
                .edges
                .values()
                .any(|state| state.status == "connected")
    }

    fn update(&self, server: &str, status: &'static str, last_error: Option<String>) {
        self.inner
            .write()
            .expect("health lock poisoned")
            .edges
            .insert(
                server.to_string(),
                EdgeState {
                    status,
                    changed_at: unix_time(),
                    last_error,
                },
            );
    }

    fn json(&self) -> Vec<u8> {
        let inner = self.inner.read().expect("health lock poisoned");
        let connected = inner
            .edges
            .values()
            .filter(|state| state.status == "connected")
            .count();
        let edges: Vec<_> = inner
            .edges
            .iter()
            .map(|(server, state)| {
                json!({
                    "server": server,
                    "status": state.status,
                    "changed_at": state.changed_at,
                    "last_error": state.last_error,
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "status": if inner.draining { "draining" } else if connected > 0 { "ready" } else { "not_ready" },
            "draining": inner.draining,
            "connected_edges": connected,
            "configured_edges": inner.edges.len(),
            "edges": edges,
        }))
        .expect("health response is serializable")
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn serve(
    listener: TcpListener,
    state: ConnectorHealth,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!(addr = %listener.local_addr()?, "health/metrics server listening");

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.wait_for(|stop| *stop) => return Ok(()),
        };
        let (stream, _) = accepted?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |request| handle(request, state.clone()));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(error = %e, "health connection error");
            }
        });
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    state: ConnectorHealth,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/healthz" => Ok(json_response(StatusCode::OK, state.json())),
        "/readyz" => {
            let status = if state.is_ready() {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            Ok(json_response(status, state.json()))
        }
        "/metrics" => {
            let encoder = prometheus::TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut output = Vec::new();
            encoder
                .encode(&metric_families, &mut output)
                .unwrap_or_default();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Full::new(Bytes::from(output)))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .unwrap()),
    }
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_a_connected_edge_and_stops_while_draining() {
        let health = ConnectorHealth::new(&["edge-a:4433".to_string()]);
        assert!(!health.is_ready());
        health.connected("edge-a:4433");
        assert!(health.is_ready());
        assert_eq!(health.connected_edges(), ["edge-a:4433"]);
        health.set_draining();
        assert!(!health.is_ready());
    }
}
