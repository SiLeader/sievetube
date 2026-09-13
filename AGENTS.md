# Repository Guidelines

## Project Structure & Module Organization

Sieve Tube is a Rust 2021 workspace. `sievetube-edge/` contains the public ingress, QUIC tunnel server, routing, TLS/ACME, DNS, and mesh logic. `sievetube-connector/` maintains outbound Edge connections and forwards traffic to private services. Shared authentication, configuration, protocol, hostname, metrics, and error types live in `sievetube-common/`. End-to-end scenarios are in `tests/integration/tests/e2e_*.rs`, with common fixtures under `tests/integration/tests/helpers/`. Example runtime configuration belongs in `config/`; operational and architecture documentation belongs in `docs/`.

## Build, Test, and Development Commands

- `cargo build --workspace` builds all crates in debug mode.
- `cargo build --release` produces `target/release/sievetube-edge` and `target/release/sievetube-connector`.
- `cargo test --workspace --all-targets` runs unit and integration tests.
- `cargo test -p sievetube-integration-tests` runs only end-to-end tests; build both binaries first with `cargo build -p sievetube-edge -p sievetube-connector`.
- `cargo fmt --all --check` verifies formatting; use `cargo fmt --all` to apply it.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` treats lint warnings as failures.

For local smoke tests, copy `config/edge.example.toml` and `config/connector.example.toml`, then run the binaries with `RUST_LOG=info`. Do not commit generated configs containing secrets.

## Coding Style & Naming Conventions

Follow standard `rustfmt` output (four-space indentation). Use `snake_case` for modules, functions, and test names; `CamelCase` for structs, enums, and traits; and `SCREAMING_SNAKE_CASE` for constants. Keep shared wire and configuration types in `sievetube-common`; keep component-specific behavior in its owning crate. Prefer contextual errors with `anyhow` at application boundaries and typed errors with `thiserror` in reusable code.

## Testing Guidelines

Place focused unit tests beside the implementation using `#[test]` or `#[tokio::test]`. Name tests after observable behavior, for example `catch_all_fallback` or `http2_concurrent_requests_are_independent`. Add `e2e_<feature>.rs` coverage when behavior crosses Edge, Connector, or network boundaries. No numeric coverage threshold is enforced; new behavior and regressions should have targeted tests.

## Commit & Pull Request Guidelines

Recent history favors short, imperative subjects with a scope-like prefix, such as `docs: update configuration guide` or `refactor: improve error handling`. Use similarly focused commits and avoid mixing unrelated changes. Pull requests should explain the user-visible effect, identify configuration or protocol compatibility concerns, link relevant issues, and list commands used for verification. Include logs or screenshots only when they clarify operational or UI-facing changes.

## Security & Configuration

Never commit JWTs, private keys, certificate material, or production Valkey URLs. Preserve secure defaults and update both example configs and relevant documentation whenever configuration semantics change.
