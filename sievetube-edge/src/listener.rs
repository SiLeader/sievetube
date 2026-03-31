use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{TcpListener, UdpSocket};

use sievetube_common::config::Protocol;

use crate::connector_registry::ConnectorRegistry;
use crate::router;
use crate::tunnel;

/// Listen for plain HTTP connections and tunnel them.
pub async fn serve_http(
    listen_addr: &str,
    registry: ConnectorRegistry,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = listen_addr, "HTTP listener started");

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let registry = registry.clone();

        tokio::spawn(async move {
            handle_http_connection(stream, client_addr, registry).await;
        });
    }
}

async fn handle_http_connection(
    stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    registry: ConnectorRegistry,
) {
    // Peek at the HTTP request to extract the Host header
    let mut buf = [0u8; 4096];
    let mut stream = stream;
    let n = match stream.peek(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let hostname = match extract_host_header(&buf[..n]) {
        Some(h) => h,
        None => {
            tracing::debug!(client_addr = %client_addr, "no Host header, rejecting");
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            let _ = stream.shutdown().await;
            return;
        }
    };

    let connector = match router::route(&registry, &hostname, Protocol::Http) {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!(client_addr = %client_addr, hostname = %hostname, "no connector found");
            // Drain the request before closing to avoid sending RST
            let mut drain = vec![0u8; 8192];
            let _ = stream.read(&mut drain).await;
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
            return;
        }
    };

    let (read_half, write_half) = tokio::io::split(stream);
    if let Err(e) = tunnel::forward_tcp(
        read_half,
        write_half,
        connector,
        hostname,
        Protocol::Http,
        client_addr,
    )
    .await
    {
        tracing::debug!(error = %e, "HTTP tunnel error");
    }
}

/// Listen for TLS connections and tunnel them (SNI-based routing).
pub async fn serve_https(
    listen_addr: &str,
    registry: ConnectorRegistry,
    tls_resolver: Arc<crate::tls::BYOCCertResolver>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = listen_addr, "HTTPS listener started");

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(tls_resolver);
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let registry = registry.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            handle_https_connection(stream, client_addr, registry, acceptor).await;
        });
    }
}

async fn handle_https_connection(
    stream: tokio::net::TcpStream,
    client_addr: SocketAddr,
    registry: ConnectorRegistry,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(client_addr = %client_addr, error = %e, "TLS handshake failed");
            return;
        }
    };

    // Extract SNI hostname from the TLS connection
    let hostname = tls_stream
        .get_ref()
        .1
        .server_name()
        .unwrap_or("")
        .to_string();

    if hostname.is_empty() {
        tracing::debug!(client_addr = %client_addr, "no SNI, rejecting");
        return;
    }

    let connector = match router::route(&registry, &hostname, Protocol::Http) {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!(client_addr = %client_addr, hostname = %hostname, "no connector for SNI");
            return;
        }
    };

    let (read_half, write_half) = tokio::io::split(tls_stream);
    if let Err(e) = tunnel::forward_tcp(
        read_half,
        write_half,
        connector,
        hostname,
        Protocol::Http,
        client_addr,
    )
    .await
    {
        tracing::debug!(error = %e, "HTTPS tunnel error");
    }
}

/// Listen for raw TCP connections (non-HTTP) on a dedicated port.
///
/// Since there is no protocol-level hostname signal in raw TCP, routing is
/// done by a configured hostname associated with this listen port.
pub async fn serve_raw_tcp(
    listen_addr: &str,
    hostname: String,
    registry: ConnectorRegistry,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = listen_addr, hostname = %hostname, "raw TCP listener started");

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let registry = registry.clone();
        let hostname = hostname.clone();

        tokio::spawn(async move {
            let connector = match router::route(&registry, &hostname, Protocol::Tcp) {
                Ok(c) => c,
                Err(_) => {
                    tracing::debug!(client_addr = %client_addr, "no connector for TCP");
                    return;
                }
            };
            let (read_half, write_half) = tokio::io::split(stream);
            if let Err(e) = tunnel::forward_tcp(
                read_half, write_half, connector, hostname, Protocol::Tcp, client_addr,
            )
            .await
            {
                tracing::debug!(error = %e, "TCP tunnel error");
            }
        });
    }
}

/// Listen for UDP datagrams and forward them via QUIC datagrams.
pub async fn serve_udp(
    listen_addr: &str,
    hostname: String,
    registry: ConnectorRegistry,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    tracing::info!(addr = listen_addr, hostname = %hostname, "UDP listener started");

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let payload = Bytes::copy_from_slice(&buf[..n]);
        let registry = registry.clone();
        let hostname = hostname.clone();
        let socket = socket.clone();

        tokio::spawn(async move {
            let connector = match router::route(&registry, &hostname, Protocol::Udp) {
                Ok(c) => c,
                Err(_) => return,
            };
            let udp_reply_map = connector.udp_reply_map.clone();
            if let Err(e) = tunnel::forward_udp_datagram(
                payload, connector, hostname, client_addr, socket, udp_reply_map,
            )
            .await
            {
                tracing::debug!(error = %e, "UDP tunnel error");
            }
        });
    }
}

/// Extract the value of the `Host` header from a raw HTTP request buffer.
fn extract_host_header(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim().to_string();
            // Strip port number if present
            let hostname = host.split(':').next().unwrap_or(&host).to_string();
            return Some(hostname);
        }
    }
    None
}
