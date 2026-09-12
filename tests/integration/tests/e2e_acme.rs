//! ACME certificate management (A2).
//!
//! Tests that talk to a real ACME server need Pebble:
//!   SIEVETUBE_PEBBLE_BIN=/path/to/pebble
//!   SIEVETUBE_CHALLTESTSRV_BIN=/path/to/pebble-challtestsrv
//!   SIEVETUBE_PEBBLE_DIR=/path/to/pebble/source   (for test/certs)
//! They are skipped when these are not set.

mod helpers;

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

const DOMAIN: &str = "acme.test";

struct Pebble {
    _challtestsrv: Child,
    _pebble: Child,
    directory_url: String,
    minica_pem: PathBuf,
    management_port: u16,
}

fn pebble_env() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let pebble = std::env::var_os("SIEVETUBE_PEBBLE_BIN")?;
    let challtestsrv = std::env::var_os("SIEVETUBE_CHALLTESTSRV_BIN")?;
    let dir = std::env::var_os("SIEVETUBE_PEBBLE_DIR")?;
    Some((pebble.into(), challtestsrv.into(), dir.into()))
}

async fn start_pebble(http_port: u16, validity_secs: u64) -> Option<Pebble> {
    let Some((pebble_bin, challtestsrv_bin, pebble_dir)) = pebble_env() else {
        eprintln!("skipping: SIEVETUBE_PEBBLE_BIN / SIEVETUBE_CHALLTESTSRV_BIN / SIEVETUBE_PEBBLE_DIR not set");
        return None;
    };
    let dns_port = helpers::find_free_port();
    let challtestsrv_mgmt = helpers::find_free_port();
    let acme_port = helpers::find_free_port();
    let management_port = helpers::find_free_port();

    let challtestsrv = Command::new(challtestsrv_bin)
        .args(["-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""])
        .args(["-dnsserver", &format!("127.0.0.1:{dns_port}")])
        .args(["-management", &format!("127.0.0.1:{challtestsrv_mgmt}")])
        .args(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn pebble-challtestsrv");

    let certs = pebble_dir.join("test/certs");
    let config = serde_like_config(acme_port, management_port, http_port, &certs, validity_secs);
    let config_path = helpers::temp_dir("pebble").join("pebble.json");
    std::fs::write(&config_path, config).unwrap();

    let pebble = Command::new(pebble_bin)
        .arg("-config")
        .arg(&config_path)
        .args(["-dnsserver", &format!("127.0.0.1:{dns_port}")])
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .env("PEBBLE_AUTHZREUSE", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn pebble");

    let ready = helpers::eventually(Duration::from_secs(10), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", acme_port))
            .await
            .ok()
            .map(|_| ())
    })
    .await;
    assert!(ready.is_some(), "pebble did not start");

    Some(Pebble {
        _challtestsrv: challtestsrv,
        _pebble: pebble,
        directory_url: format!("https://localhost:{acme_port}/dir"),
        minica_pem: certs.join("pebble.minica.pem"),
        management_port,
    })
}

fn serde_like_config(
    acme_port: u16,
    management_port: u16,
    http_port: u16,
    certs: &std::path::Path,
    validity_secs: u64,
) -> String {
    format!(
        r#"{{
  "pebble": {{
    "listenAddress": "127.0.0.1:{acme_port}",
    "managementListenAddress": "127.0.0.1:{management_port}",
    "certificate": "{cert}",
    "privateKey": "{key}",
    "httpPort": {http_port},
    "tlsPort": {tls_port},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": {{ "authz": 1, "order": 1 }},
    "keyAlgorithm": "ecdsa",
    "profiles": {{ "default": {{ "description": "test", "validityPeriod": {validity_secs} }} }}
  }}
}}"#,
        cert = certs.join("localhost/cert.pem").display(),
        key = certs.join("localhost/key.pem").display(),
        tls_port = helpers::find_free_port(),
    )
}

impl Pebble {
    /// The root that signs issued certificates (generated at Pebble start).
    async fn issuing_root(&self) -> String {
        let ca = std::fs::read_to_string(&self.minica_pem).unwrap();
        let mut tls = helpers::tls_connect(self.management_port, "localhost", &ca, &[b"http/1.1"])
            .await
            .expect("connect to pebble management API");
        tls.write_all(b"GET /roots/0 HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        let text = String::from_utf8_lossy(&response);
        text.split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string()
    }
}

fn acme_section(
    pebble: &Pebble,
    state_dir: &std::path::Path,
    renew_before_fraction: f64,
) -> String {
    format!(
        r#"
[tls.acme]
enabled = true
directory_url = "{directory}"
terms_of_service_agreed = true
contact_email = "ops@acme.test"
domains = ["{DOMAIN}"]
state_dir = "{state}"
ca_root_pem = "{root}"
renew_before_fraction = {renew_before_fraction}
retry_initial_secs = 1
retry_max_secs = 5
order_timeout_secs = 30
"#,
        directory = pebble.directory_url,
        state = state_dir.display(),
        root = pebble.minica_pem.display(),
    )
}

/// SHA-256-free fingerprint: the leaf certificate DER bytes.
async fn served_leaf(port: u16, root: &str) -> Option<Vec<u8>> {
    let tls = helpers::tls_connect(port, DOMAIN, root, &[b"http/1.1"])
        .await
        .ok()?;
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()?
        .first()?
        .as_ref()
        .to_vec();
    Some(leaf)
}

#[tokio::test]
async fn http01_issuance_renewal_keeps_existing_connections() {
    let mut edge = helpers::EdgeTestConfig::new("secret-acme");
    let Some(pebble) = start_pebble(edge.http_port, 30).await else {
        return;
    };
    let state_dir = helpers::temp_dir("acme-state");
    edge.extra = acme_section(&pebble, &state_dir, 0.7);

    let (backend_port, _) = helpers::start_backend().await;
    let target = format!("127.0.0.1:{backend_port}");
    let (_cfg, _edge, _connector) = helpers::start_tunnel(
        &edge,
        "tenant-acme",
        &[DOMAIN],
        &[(DOMAIN, "http", &target)],
    )
    .await;

    let root = pebble.issuing_root().await;
    let first = helpers::eventually(Duration::from_secs(30), || {
        served_leaf(edge.https_port, &root)
    })
    .await
    .expect("certificate was not issued");

    // A connection established with the first certificate.
    let tls = helpers::tls_connect(edge.https_port, DOMAIN, &root, &[b"http/1.1"])
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let request = || {
        Request::builder()
            .uri("/acme")
            .header("host", DOMAIN)
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let (status, body) =
        helpers::read_response(sender.send_request(request()).await.unwrap()).await;
    assert_eq!(
        (status, body.as_ref()),
        (200, &b"hello from backend /acme"[..])
    );

    // Renewal is due after 30% of the 30s lifetime; new handshakes see a new certificate.
    let renewed = helpers::eventually(Duration::from_secs(40), || async {
        served_leaf(edge.https_port, &root)
            .await
            .filter(|leaf| *leaf != first)
    })
    .await;
    assert!(renewed.is_some(), "certificate was not renewed");

    // The connection established before the renewal is still usable.
    sender.ready().await.unwrap();
    let (status, _) = helpers::read_response(sender.send_request(request()).await.unwrap()).await;
    assert_eq!(status, 200);

    let (status, _) = helpers::health_get(edge.health_port, "/readyz")
        .await
        .unwrap();
    assert_eq!(status, 200);
}

#[tokio::test]
async fn restart_reuses_the_stored_certificate() {
    let mut edge = helpers::EdgeTestConfig::new("secret-acme-restart");
    let Some(pebble) = start_pebble(edge.http_port, 3600).await else {
        return;
    };
    let state_dir = helpers::temp_dir("acme-restart");
    edge.extra = acme_section(&pebble, &state_dir, 0.33);
    let config = edge.write();
    let root = pebble.issuing_root().await;

    let first_edge = helpers::start_edge(&config).await;
    helpers::wait_for_health(edge.health_port).await;
    let issued = helpers::eventually(Duration::from_secs(30), || {
        served_leaf(edge.https_port, &root)
    })
    .await
    .expect("certificate was not issued");
    drop(first_edge);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let _second_edge = helpers::start_edge(&config).await;
    helpers::wait_for_health(edge.health_port).await;
    let served = helpers::eventually(Duration::from_secs(10), || {
        served_leaf(edge.https_port, &root)
    })
    .await
    .expect("stored certificate was not served after restart");
    assert_eq!(
        served, issued,
        "a new certificate was ordered instead of reusing the stored one"
    );
}

#[tokio::test]
async fn unreachable_ca_backs_off_and_degrades_readiness() {
    let state_dir = helpers::temp_dir("acme-outage");
    let mut edge = helpers::EdgeTestConfig::new("secret-acme-outage");
    edge.extra = format!(
        r#"
[tls.acme]
enabled = true
directory_url = "https://127.0.0.1:1/dir"
terms_of_service_agreed = true
domains = ["{DOMAIN}"]
state_dir = "{}"
retry_initial_secs = 2
retry_max_secs = 60
"#,
        state_dir.display()
    );
    let config = edge.write();
    let _edge = helpers::start_edge(&config).await;
    helpers::wait_for_health(edge.health_port).await;

    tokio::time::sleep(Duration::from_secs(5)).await;
    let metrics = helpers::metrics(edge.health_port).await;
    let failures: u64 = metrics
        .lines()
        .find(|l| l.starts_with("sievetube_acme_orders_total") && l.contains("result=\"failure\""))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        (1..=3).contains(&failures),
        "unexpected number of attempts: {failures}\n{metrics}"
    );

    let (status, body) = helpers::health_get(edge.health_port, "/readyz")
        .await
        .unwrap();
    assert_eq!(status, 503);
    assert!(
        body.contains("no valid ACME certificate for acme.test"),
        "{body}"
    );
}

#[tokio::test]
async fn challenge_path_is_answered_only_for_managed_domains() {
    let state_dir = helpers::temp_dir("acme-challenge-path");
    let env = helpers::start_http_tunnel("secret-acme-path", "tenant-acme-path", &["tenant.test"], |cfg| {
        cfg.extra = format!(
            "[tls.acme]\nenabled = true\ndirectory_url = \"https://127.0.0.1:1/dir\"\nterms_of_service_agreed = true\ndomains = [\"{DOMAIN}\"]\nstate_dir = \"{}\"\nretry_initial_secs = 3600\n",
            state_dir.display()
        );
    })
    .await;
    let port = env.edge.http_port;

    // Managed domain, no connector: the edge answers, unknown tokens are 404.
    let response = helpers::http_get(port, DOMAIN, "/.well-known/acme-challenge/unknown-token")
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.0 404"), "{response}");
    let response = helpers::raw_request(port, b"POST /.well-known/acme-challenge/x HTTP/1.1\r\nHost: acme.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    assert!(response.starts_with("HTTP/1.1 405"), "{response}");

    // Other paths on the managed domain are routed normally (no connector → 502).
    let response = helpers::http_get(port, DOMAIN, "/").await.unwrap();
    assert!(response.contains(" 502 "), "{response}");

    // Unmanaged domains get no special treatment: the tenant's backend answers.
    let response = helpers::http_get(port, "tenant.test", "/.well-known/acme-challenge/anything")
        .await
        .unwrap();
    assert!(
        response.contains("hello from backend /.well-known/acme-challenge/anything"),
        "{response}"
    );
}
