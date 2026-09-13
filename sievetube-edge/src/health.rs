use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::Encoder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::connector_registry::ConnectorRegistry;

/// Returns reasons why the Edge is not fully ready (empty when ready).
pub type ReadinessProbe = Box<dyn Fn() -> Vec<String> + Send + Sync>;

pub struct HealthState {
    pub registry: ConnectorRegistry,
    pub probes: Vec<ReadinessProbe>,
}

impl HealthState {
    fn readiness_issues(&self) -> Vec<String> {
        self.probes.iter().flat_map(|probe| probe()).collect()
    }
}

pub async fn serve(listener: TcpListener, state: Arc<HealthState>, shutdown: CancellationToken) {
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(addr = %addr, "health/metrics server listening");
    }

    loop {
        let stream = tokio::select! {
            _ = shutdown.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::debug!(error = %e, "health accept failed");
                    // Errors such as fd exhaustion persist; retrying at once would spin.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { handle(req, &state) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(error = %e, "health connection error");
            }
        });
    }
}

fn json_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response is valid")
}

fn handle(
    req: Request<hyper::body::Incoming>,
    state: &HealthState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/healthz" => {
            let body = format!(
                r#"{{"status":"ok","active_connectors":{}}}"#,
                state.registry.len()
            );
            Ok(json_response(StatusCode::OK, body))
        }
        "/readyz" => {
            let issues = state.readiness_issues();
            if issues.is_empty() {
                Ok(json_response(
                    StatusCode::OK,
                    r#"{"status":"ready"}"#.to_string(),
                ))
            } else {
                let body = serde_json::json!({ "status": "degraded", "reasons": issues });
                Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    body.to_string(),
                ))
            }
        }
        "/metrics" => {
            let encoder = prometheus::TextEncoder::new();
            let families = prometheus::gather();
            let mut out = Vec::new();
            encoder.encode(&families, &mut out).unwrap_or_default();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Full::new(Bytes::from(out)))
                .expect("static response is valid"))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .expect("static response is valid")),
    }
}
