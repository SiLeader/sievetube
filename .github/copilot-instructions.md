# Sieve Tube repository instructions

## Build, test, and lint

Run commands from the workspace root.

```sh
cargo build --workspace
cargo build --release
cargo test --workspace --all-targets
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Use package and test-name filters for focused tests:

```sh
# One unit test
cargo test -p sievetube-common hostname::tests::normalizes_case_and_trailing_dot

# One Edge or Connector unit test
cargo test -p sievetube-edge connector_registry::tests::stale_generation_does_not_remove_newer_connection
cargo test -p sievetube-connector ingress::tests::catch_all_fallback

# All end-to-end tests (the tests execute target/debug binaries)
cargo build -p sievetube-edge -p sievetube-connector
cargo test -p sievetube-integration-tests

# One end-to-end test binary or one test within it
cargo test -p sievetube-integration-tests --test e2e_http
cargo test -p sievetube-integration-tests --test e2e_http http_tunnel_basic
```

Mesh end-to-end tests require `SIEVETUBE_TEST_VALKEY_URL`; without it they skip. Integration fixtures allocate loopback ports, spawn the debug Edge and Connector binaries, and place temporary state under Cargo's target temp directory.

## Architecture

Sieve Tube is a Rust 2021 workspace with three runtime layers:

- `sievetube-edge` owns all public ingress (HTTP/HTTPS/raw TCP/request-reply UDP), Connector QUIC sessions, routing, public TLS/ACME, policy plugins, managed DNS, health/metrics, Valkey coordination, and optional Edge-to-Edge mesh forwarding.
- `sievetube-connector` opens outbound QUIC connections to every configured Edge, advertises the hostname/protocol combinations its ordered ingress rules can serve, and forwards accepted traffic to local socket addresses or HTTP status responses.
- `sievetube-common` is the compatibility boundary for JWT claims, configuration primitives, hostname handling, metrics, errors, and both QUIC wire protocols. Put types used by both binaries here rather than duplicating them.

The Connector authenticates with a JWT whose `sub` is the tenant and whose `hostnames` bound what it may advertise. Edge registration combines that authorization with the Connector's service advertisement. A single Edge keeps one active Connector per tenant; a newer connection replaces the older generation without allowing a stale disconnect to remove the replacement.

Routing is keyed by normalized hostname plus protocol. A local Connector always wins. In `direct` mode, no local route means unavailable. In `mesh` mode, the Edge consults TTL-bound Valkey route advertisements and forwards over a separate mutual-TLS QUIC protocol to the Edge holding the Connector. Mesh retries are allowed only before a peer accepts a request, preventing duplicate delivery.

There are separate security boundaries and certificates for Connector-to-Edge QUIC, public HTTPS termination, and Edge-to-Edge mesh mTLS. Do not reuse assumptions or configuration between these TLS paths.

## Repository-specific conventions

- Normalize every hostname used as a routing, ownership, certificate, policy, or DNS lookup key with the appropriate helper in `sievetube-common::hostname`. Ordinary hostnames, wildcard patterns, and DNS owner names intentionally use different normalization functions.
- Connector ingress rules are evaluated top-to-bottom and stop at the first match. Keep catch-all rules last. `http_status:<code>` is valid only for HTTP; local targets must be literal socket addresses, not DNS names.
- Configuration structs use `serde(deny_unknown_fields)` and explicit startup validation so typos and invalid feature combinations fail fast. Preserve the legacy compatibility rule: absent/`1` `config_version` defaults to direct routing, while version `2` defaults to mesh; new single-Edge examples explicitly set version `2` and `routing.mode = "direct"`.
- Wire compatibility matters. Connector traffic uses ALPN `sievetube/1`; mesh traffic uses `sievetube-mesh/1`. Control frames are length-prefixed tagged JSON followed by raw stream data. Additive fields used across versions should have Serde defaults and omission behavior, and existing tags, limits, acceptance semantics, and ALPN values must not change accidentally.
- Preserve the routing safety properties: hostname ownership is tenant-isolated, registry removal is generation-checked, local routes take precedence over mesh routes, mesh identity must match its certificate, and only pre-accept mesh failures are retryable.
- Concurrency limits are intentionally shared across all Edge connections on a Connector rather than multiplied per server. Shutdown paths stop readiness, send `GoingAway`, reject new work, and drain tracked tasks/streams within configured timeouts.
- Use `anyhow` with context at binary/application boundaries and typed `thiserror` errors in reusable shared code. Logging and operational state use `tracing`, Prometheus metrics, `/healthz`, and `/readyz`.
- Keep focused unit tests beside their implementation. Use `tests/integration/tests/e2e_<feature>.rs` plus shared helpers when behavior crosses process, QUIC, TLS, mesh, or network boundaries.
- When configuration semantics change, update the Rust config validation, `config/edge.example.toml` or `config/connector.example.toml`, and the relevant documentation together. Runtime configs, JWTs, private keys, certificate material, and production Valkey URLs must not be committed.
