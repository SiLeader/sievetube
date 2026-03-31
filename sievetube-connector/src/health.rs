use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::Encoder;
use tokio::net::TcpListener;

pub async fn serve(listen_addr: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = listen_addr, "health/metrics server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let svc = hyper::service::service_fn(handle);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(error = %e, "health connection error");
            }
        });
    }
}

async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/healthz" => {
            let body = Full::new(Bytes::from("ok\n"));
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(body)
                .unwrap())
        }
        "/metrics" => {
            let encoder = prometheus::TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut output = Vec::new();
            encoder.encode(&metric_families, &mut output).unwrap_or_default();

            let body = Full::new(Bytes::from(output));
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(body)
                .unwrap())
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("not found\n")))
                .unwrap())
        }
    }
}
