//! Built-in traffic policy (B2/B3): CIDR blocks, rate limits, trusted proxies,
//! monitor mode, reload, and TCP/UDP limits.

mod helpers;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or_default()
}

#[tokio::test]
async fn blocked_and_rate_limited_requests_never_reach_the_backend() {
    let hosts = ["open.test", "blocked.test", "limited.test"];
    let env = helpers::start_http_tunnel("secret-policy", "tenant-policy", &hosts, |cfg| {
        cfg.extra = r#"
[policy]
enabled = true

[[policy.domains]]
hostname = "blocked.test"
blocked_cidrs = ["127.0.0.0/8"]

[[policy.domains]]
hostname = "limited.test"
requests_per_second = 0.2
burst = 2
"#
        .to_string();
    })
    .await;
    let port = env.edge.http_port;

    let blocked = helpers::http_get(port, "blocked.test", "/").await.unwrap();
    assert_eq!(status(&blocked), 403, "{blocked}");

    for _ in 0..2 {
        let ok = helpers::http_get(port, "limited.test", "/").await.unwrap();
        assert_eq!(status(&ok), 200, "{ok}");
    }
    let limited = helpers::http_get(port, "limited.test", "/").await.unwrap();
    assert_eq!(status(&limited), 429, "{limited}");
    assert!(
        limited.to_lowercase().contains("retry-after: "),
        "{limited}"
    );

    // open.test is unaffected; the backend saw exactly 2 + 1 (+ this /count) requests.
    let count = helpers::http_get(port, "open.test", "/count")
        .await
        .unwrap();
    assert_eq!(body(&count), "3", "{count}");

    let metrics = helpers::metrics(env.edge.health_port).await;
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("sievetube_policy_decisions_total")
                && l.contains("decision=\"rate_limited\"")
                && l.contains("reason=\"rate_limit\"")),
        "{metrics}"
    );
    assert!(
        !metrics.contains("limited.test"),
        "hostnames must not be metric labels"
    );
}

#[tokio::test]
async fn monitor_mode_records_without_rejecting() {
    let env =
        helpers::start_http_tunnel("secret-monitor", "tenant-monitor", &["watch.test"], |cfg| {
            cfg.extra =
                "[policy]\nenabled = true\nmode = \"monitor\"\nblocked_cidrs = [\"127.0.0.1\"]\n"
                    .to_string();
        })
        .await;

    let response = helpers::http_get(env.edge.http_port, "watch.test", "/")
        .await
        .unwrap();
    assert_eq!(status(&response), 200, "{response}");

    let metrics = helpers::metrics(env.edge.health_port).await;
    assert!(
        metrics.lines().any(|l| l.contains("decision=\"deny\"")
            && l.contains("mode=\"monitor\"")
            && l.contains("reason=\"blocked_cidr\"")),
        "{metrics}"
    );
}

#[tokio::test]
async fn forwarded_for_is_trusted_only_from_configured_proxies_and_reload_is_validated() {
    let env = helpers::start_http_tunnel("secret-xff", "tenant-xff", &["xff.test"], |cfg| {
        cfg.extra = "[policy]\nenabled = true\nblocked_cidrs = [\"198.51.100.0/24\"]\n".to_string();
    })
    .await;
    let port = env.edge.http_port;
    let spoofed = b"GET /headers HTTP/1.1\r\nHost: xff.test\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n";

    // Not a trusted proxy: the header is ignored for policy and replaced upstream.
    let response = helpers::raw_request(port, spoofed).await.unwrap();
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        body(&response).contains("x-forwarded-for: 127.0.0.1\n"),
        "{response}"
    );

    // Rewrite the edge's config file with a trusted proxy and reload it.
    let mut trusted = helpers::EdgeTestConfig::new("secret-xff");
    trusted.quic_port = env.edge.quic_port;
    trusted.http_port = env.edge.http_port;
    trusted.https_port = env.edge.https_port;
    trusted.health_port = env.edge.health_port;
    trusted.extra = "[policy]\nenabled = true\ntrusted_proxies = [\"127.0.0.1\"]\nblocked_cidrs = [\"198.51.100.0/24\"]\n".to_string();
    let path = edge_config_path(&env);
    trusted.write_to(&path);
    env.edge_process.signal("HUP");

    let reloaded = helpers::eventually(Duration::from_secs(5), || async {
        let response = helpers::raw_request(port, spoofed).await.ok()?;
        (status(&response) == 403).then_some(())
    })
    .await;
    assert!(
        reloaded.is_some(),
        "policy with trusted proxy was not applied"
    );

    let response = helpers::raw_request(
        port,
        b"GET /headers HTTP/1.1\r\nHost: xff.test\r\nX-Forwarded-For: 192.0.2.1\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        body(&response).contains("x-forwarded-for: 192.0.2.1, 127.0.0.1\n"),
        "{response}"
    );

    // An invalid configuration is rejected as a whole and the current policy stays.
    std::fs::write(&path, "this is not toml [").unwrap();
    env.edge_process.signal("HUP");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let response = helpers::raw_request(port, spoofed).await.unwrap();
    assert_eq!(status(&response), 403, "{response}");
}

/// The config file path of an edge started by `start_http_tunnel` (found via /proc).
fn edge_config_path(env: &helpers::HttpTunnel) -> std::path::PathBuf {
    let pid = env.edge_process.pid().expect("edge pid");
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).expect("read cmdline");
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    std::path::PathBuf::from(String::from_utf8_lossy(args[1]).into_owned())
}

/// A minimal ABI v1 plugin returning a constant or trapping.
fn plugin_module(evaluate_body: &str) -> String {
    format!(
        r#"(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "sievetube_abi_version") (result i32) (i32.const 1))
  (func (export "sievetube_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $ptr))
  (func (export "sievetube_evaluate") (param $ptr i32) (param $len i32) (result i32) {evaluate_body}))"#
    )
}

fn write_plugin(dir: &std::path::Path, name: &str, source: &str) -> String {
    let path = dir.join(format!("{name}.wat"));
    std::fs::write(&path, source).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, source.as_bytes());
    let sha256: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("\n[[policy.plugins]]\nname = \"{name}\"\npath = \"{}\"\nsha256 = \"{sha256}\"\napplies_to = [\"{name}.test\"]\n", path.display())
}

#[tokio::test]
async fn wasm_plugins_deny_or_fail_closed() {
    let dir = helpers::temp_dir("plugins");
    let deny = write_plugin(&dir, "deny", &plugin_module("(i32.const 1)"));
    let broken = write_plugin(&dir, "broken", &plugin_module("(unreachable)"));
    let hosts = ["deny.test", "broken.test", "ok.test"];
    let env = helpers::start_http_tunnel("secret-plugins", "tenant-plugins", &hosts, |cfg| {
        cfg.extra = format!("[policy]\nenabled = true\n{deny}{broken}");
    })
    .await;
    let port = env.edge.http_port;

    let denied = helpers::http_get(port, "deny.test", "/").await.unwrap();
    assert_eq!(status(&denied), 403, "{denied}");
    let failed = helpers::http_get(port, "broken.test", "/").await.unwrap();
    assert_eq!(status(&failed), 503, "{failed}");
    let allowed = helpers::http_get(port, "ok.test", "/").await.unwrap();
    assert_eq!(status(&allowed), 200, "{allowed}");

    let metrics = helpers::metrics(env.edge.health_port).await;
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("sievetube_policy_plugin_failures_total")
                && l.contains("plugin=\"broken\"")
                && l.contains("failure=\"trap\"")),
        "{metrics}"
    );
}

#[tokio::test]
async fn tcp_concurrency_limit_releases_slots() {
    let echo_port = helpers::start_tcp_echo_server().await;
    let tcp_port = helpers::find_free_port();
    let mut edge = helpers::EdgeTestConfig::new("secret-tcp-policy");
    edge.tcp_listeners = vec![(tcp_port, "echo-policy.test".to_string())];
    edge.extra =
        "[policy]\nenabled = true\n\n[policy.tcp]\nmax_concurrent_per_ip = 1\n".to_string();
    let target = format!("127.0.0.1:{echo_port}");
    let (_cfg, _edge, _connector) = helpers::start_tunnel(
        &edge,
        "tenant-tcp-policy",
        &["echo-policy.test"],
        &[("echo-policy.test", "tcp", &target)],
    )
    .await;
    let addr = format!("127.0.0.1:{tcp_port}");

    async fn echo(stream: &mut TcpStream, message: &[u8]) -> bool {
        if stream.write_all(message).await.is_err() {
            return false;
        }
        let mut buf = vec![0u8; message.len()];
        matches!(
            timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await,
            Ok(Ok(_))
        ) && buf == message
    }

    let mut first = TcpStream::connect(&addr).await.unwrap();
    assert!(echo(&mut first, b"first").await);

    // The second concurrent connection from the same IP is closed without being tunneled.
    let mut second = TcpStream::connect(&addr).await.unwrap();
    assert!(!echo(&mut second, b"second").await);

    // Closing the first connection releases its slot.
    drop(first);
    let recovered = helpers::eventually(Duration::from_secs(5), || async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        echo(&mut stream, b"third").await.then_some(())
    })
    .await;
    assert!(recovered.is_some(), "slot was not released");
}

#[tokio::test]
async fn udp_tunnel_and_packet_limit() {
    let echo_port = helpers::start_udp_echo_server().await;
    let udp_port = helpers::find_free_port();
    let mut edge = helpers::EdgeTestConfig::new("secret-udp-policy");
    edge.udp_listeners = vec![(udp_port, "game.test".to_string())];
    edge.extra =
        "[policy]\nenabled = true\n\n[policy.udp]\npackets_per_second = 0.1\npacket_burst = 3\n"
            .to_string();
    let target = format!("127.0.0.1:{echo_port}");
    let (_cfg, _edge, _connector) = helpers::start_tunnel(
        &edge,
        "tenant-udp",
        &["game.test"],
        &[("game.test", "udp", &target)],
    )
    .await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .connect(format!("127.0.0.1:{udp_port}"))
        .await
        .unwrap();

    let mut replies = 0;
    for i in 0..6 {
        let message = format!("packet-{i}");
        socket.send(message.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(700), socket.recv(&mut buf)).await {
            assert_eq!(&buf[..n], message.as_bytes());
            replies += 1;
        }
    }
    assert_eq!(replies, 3, "only the burst should pass");

    let metrics = helpers::metrics(edge.health_port).await;
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("sievetube_udp_dropped_total")
                && l.contains("reason=\"policy\"")
                && l.ends_with(" 3")),
        "{metrics}"
    );
}
