use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::Encoder;
use tokio::net::TcpListener;

use crate::connector_registry::ConnectorRegistry;

pub async fn serve(listen_addr: &str, registry: ConnectorRegistry) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = listen_addr, "health/metrics server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let registry = registry.clone();

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let count = registry.len();
                handle(req, count)
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

async fn handle(
    req: Request<hyper::body::Incoming>,
    active_connectors: usize,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/healthz" => {
            let body = format!(
                r#"{{"status":"ok","active_connectors":{active_connectors}}}"#
            );
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
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
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .unwrap()),
    }
}
