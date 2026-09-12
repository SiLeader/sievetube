//! Helpers shared by unit tests.

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Two ends of a real QUIC connection over loopback.
pub struct QuicPair {
    pub server: quinn::Connection,
    /// Kept so the connection stays open for the lifetime of the pair
    #[allow(dead_code)]
    pub client: quinn::Connection,
    _server_endpoint: quinn::Endpoint,
    _client_endpoint: quinn::Endpoint,
}

pub async fn quic_pair() -> QuicPair {
    install_crypto();
    let (certs, key) = crate::tls::generate_self_signed().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).unwrap(),
    )));

    let addr = server_endpoint.local_addr().unwrap();
    let (server, client) = tokio::join!(
        async { server_endpoint.accept().await.unwrap().await.unwrap() },
        async {
            client_endpoint
                .connect(addr, "sievetube-edge")
                .unwrap()
                .await
                .unwrap()
        }
    );
    QuicPair {
        server,
        client,
        _server_endpoint: server_endpoint,
        _client_endpoint: client_endpoint,
    }
}
