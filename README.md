# Sieve Tube

[日本語](README_ja.md)

Sieve Tube is a self-hosted reverse tunnel for publishing services that run on private networks. It follows the same basic model as Cloudflare Tunnel: run an **Edge** on an Internet-reachable server and a **Connector** beside the private service. The Connector establishes an outbound QUIC connection, and the Edge forwards public traffic through that connection—no inbound port needs to be opened on the private network.

> [!IMPORTANT]
> Sieve Tube is currently version `0.1.0`. Review the configuration and security model carefully before using it for production traffic.

## How it works

```text
 Internet client                 Public server                    Private network
┌───────────────┐  HTTP(S)/TCP  ┌────────────────┐     QUIC      ┌─────────────────┐
│ Browser / App │ ─────────────▶│ Sieve Tube Edge│◀─────────────│ Sieve Tube      │
└───────────────┘      UDP      └────────────────┘  outbound     │ Connector       │
                                               tunnel            └────────┬────────┘
                                                                        │
                                                                        ▼
                                                               ┌─────────────────┐
                                                               │ Local service   │
                                                               │ 127.0.0.1:8080  │
                                                               └─────────────────┘
```

- **Edge (`sievetube-edge`)** listens for public HTTP, HTTPS, TCP, or UDP traffic and accepts Connector sessions over QUIC.
- **Connector (`sievetube-connector`)** makes outbound connections to one or more Edges and forwards matching traffic to local targets.
- A signed JWT identifies the tenant and limits the hostnames a Connector may advertise.
- Ingress rules are evaluated from top to bottom; the first matching hostname and protocol wins.

## Features

- HTTP and HTTPS reverse proxying, including HTTP/1.1 and HTTP/2 on the public side
- Raw TCP and request/reply UDP forwarding
- Outbound-only QUIC tunnels from private networks
- HMAC-SHA256 JWT authentication with hostname allowlists
- Public TLS with user-provided certificates or ACME (`http-01` and `dns-01`)
- Optional multi-Edge routing with mutual-TLS mesh links and Valkey/Redis coordination
- Built-in CIDR blocking and rate limiting, plus sandboxed WebAssembly policy plugins
- Managed DNS records through Cloudflare or Amazon Route 53
- Structured JSON logs, health/readiness endpoints, and Prometheus metrics
- Graceful shutdown and safe configuration/certificate reloads

## Requirements

- A recent stable Rust toolchain with Cargo
- An Internet-reachable host for the Edge
- UDP `4433` reachable from each Connector to the Edge (or the port selected by `server.quic_listen`)
- Public listener ports reachable by clients: normally TCP `80`/`443`, plus any configured raw TCP or UDP ports
- A DNS record pointing each public hostname to the Edge

Valkey/Redis is optional for a single Edge in direct-routing mode. It is required for a mesh with peer Edges and for some coordinated features.

## Quick start

The following example publishes an HTTP service running at `127.0.0.1:8080` on a private server as `app.example.com`.

### 1. Build the binaries

```sh
git clone <repository-url> sievetube
cd sievetube
cargo build --release
```

The binaries are written to:

- `target/release/sievetube-edge`
- `target/release/sievetube-connector`

### 2. Configure and start the Edge

On the public server:

```sh
cp config/edge.example.toml edge.toml
```

At minimum, edit `edge.toml` as follows:

- Replace `auth.jwt_secret` with a long, random secret.
- Confirm `server.quic_listen`, `server.http_listen`, and `server.https_listen` are reachable on the intended ports.
- Keep `routing.mode = "direct"` for a single-Edge deployment.
- Set `tls.cert_dir` to the directory containing public HTTPS certificates. HTTP can be tested before a public certificate is installed.

Then start the Edge:

```sh
RUST_LOG=info ./target/release/sievetube-edge edge.toml
```

Binding ports below 1024 may require system service capabilities or elevated privileges. In production, run Sieve Tube under a service manager with the minimum permissions required.

### 3. Issue a Connector token

Use the same secret configured as `auth.jwt_secret`. Prefer a protected file or
the `SIEVETUBE_JWT_SECRET` environment variable so the secret is not exposed in
the process argument list:

```sh
./target/release/sievetube-edge issue-token \
  --secret-file /run/secrets/sievetube-jwt \
  --sub tenant-1 \
  --hostname app.example.com \
  --exp-hours 8760
```

The command prints a signed JWT. Treat it as a secret: anyone holding it can register the allowed hostnames until the token expires.

Persistent hostname ownership can be inspected and changed with compare-and-set
admin commands (use `transfer` in place of `release` to move ownership directly):

```sh
sievetube-edge owner get --valkey-file /run/secrets/valkey-url --hostname app.example.com
sievetube-edge owner release --valkey-file /run/secrets/valkey-url \
  --hostname app.example.com --tenant tenant-1
sievetube-edge owner transfer --valkey-file /run/secrets/valkey-url \
  --hostname app.example.com --tenant tenant-1 --new-tenant tenant-2
```

### 4. Configure and start the Connector

On the private server:

```sh
cp config/connector.example.toml connector.toml
```

Edit `connector.toml` to contain the generated token, the public Edge address, and the local service:

```toml
[auth]
token = "<generated-jwt>"

[network]
public_servers = ["edge.example.net:4433"]

# Configure one of these in production; see Security below.
# edge_ca_cert = "/etc/sievetube/edge-ca.pem"
# edge_cert_sha256 = ["<sha256-certificate-fingerprint>"]

[[ingress]]
hostname = "app.example.com"
protocol = "http"
target = "127.0.0.1:8080"

[[ingress]]
target = "http_status:404"
```

Start the Connector while the local service is running:

```sh
RUST_LOG=info ./target/release/sievetube-connector connector.toml
```

### 5. Route traffic to the Edge

Point the `A`/`AAAA` record for `app.example.com` to the public Edge, then test HTTP:

```sh
curl http://app.example.com/
```

HTTPS becomes available after a certificate for `app.example.com` is placed in `tls.cert_dir` or obtained through ACME.

## Configuration

Complete, commented configuration references are provided in:

- [`config/edge.example.toml`](config/edge.example.toml) — listeners, authentication, public TLS, ACME, policies, DNS, Valkey, and Edge mesh
- [`config/connector.example.toml`](config/connector.example.toml) — Edge connections, certificate verification, ingress rules, and heartbeat visibility

### Connector placement and redundancy

An Edge keeps one Connector connection per tenant (the JWT `sub` claim). A new connection for the same tenant replaces the old connection on that Edge. If multiple Connectors share a token, assign them to different Edges instead of listing the same Edge on each Connector. With direct routing, a Connector must connect to every Edge that should serve its traffic; with mesh routing, a redundant subset is sufficient because peer Edges can forward traffic internally.

### Raw TCP and UDP

Raw TCP and UDP traffic has no HTTP `Host` header, so each public listener is assigned a hostname in the Edge configuration. The same hostname and protocol must appear in the Connector ingress rules.

```toml
# edge.toml
[[server.tcp_listen]]
addr = "0.0.0.0:2222"
hostname = "ssh.example.com"

[[server.udp_listen]]
addr = "0.0.0.0:19132"
hostname = "game.example.com"
```

```toml
# connector.toml
[[ingress]]
hostname = "ssh.example.com"
protocol = "tcp"
target = "127.0.0.1:22"

[[ingress]]
hostname = "game.example.com"
protocol = "udp"
target = "127.0.0.1:19132"
```

## Security

- Replace every example secret before deployment and restrict access to Connector JWTs and private keys.
- Configure `network.edge_ca_cert` or `network.edge_cert_sha256` on every Connector. If neither is set, the Edge's QUIC certificate is **not verified**; this is intended only for initial migration or testing.
- For public HTTPS, place `<hostname>.crt` and `<hostname>.key` in `tls.cert_dir`, or enable ACME for an explicit domain allowlist.
- Keep the health/metrics listener on a private interface unless it is protected separately.
- Start traffic policies in `monitor` mode, inspect their decisions, and then switch to `enforce`.
- Only trust forwarded client addresses from networks listed in `policy.trusted_proxies`.

## Operations and observability

The Edge exposes the following endpoints on `server.health_listen` (default `127.0.0.1:9090`):

| Endpoint | Purpose |
| --- | --- |
| `/healthz` | Liveness and active Connector count |
| `/readyz` | Readiness, including certificate and Valkey checks |
| `/metrics` | Prometheus metrics |

The Connector exposes the same `/healthz` and `/metrics` paths plus `/readyz`
on `127.0.0.1:9091` by default. Its readiness is 200 only while at least one
Edge connection is authenticated and shutdown draining has not begun. Override
the address with `SIEVETUBE_HEALTH_ADDR`.

Logs are JSON and use `RUST_LOG` for filtering. See [`docs/operations.md`](docs/operations.md) for certificate lifecycle, ACME, policy rollout, DNS reconciliation, multi-Edge mesh setup, monitoring, graceful shutdown, and rollback procedures.

## Development

Run the workspace test suite:

```sh
cargo test --workspace
```

The workspace contains:

- `sievetube-edge` — public ingress and tunnel server
- `sievetube-connector` — private-network agent and local forwarder
- `sievetube-common` — shared protocol, authentication, configuration, and metrics types
- `tests/integration` — end-to-end tests
