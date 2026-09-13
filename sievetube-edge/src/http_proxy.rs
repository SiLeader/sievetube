//! Request-level HTTP/1.1 and HTTP/2 reverse proxy for the public listeners.
//!
//! Every request is validated and routed on its own normalized hostname, checked
//! against the traffic policy, then forwarded as HTTP/1.1 over a dedicated QUIC
//! stream to the Connector, which pipes the bytes to its local target. Bodies are
//! streamed in both directions.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use sievetube_common::config::Protocol;
use sievetube_common::hostname;

use crate::acme::{Http01Challenges, CHALLENGE_PATH_PREFIX};
use crate::config::HttpConfig;
use crate::policy::{Decision, Policy, RequestContext};
use crate::router::Router;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// Hop-by-hop headers that must not be forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// Per-connection facts established before any request is read.
#[derive(Debug)]
pub struct ConnInfo {
    pub client_addr: SocketAddr,
    pub scheme: Scheme,
    /// Normalized TLS server name (HTTPS only)
    pub sni: Option<String>,
}

/// How to build X-Forwarded-* headers for a request.
#[derive(Debug, Clone, Copy)]
struct Forwarded {
    peer_ip: IpAddr,
    /// The peer is a trusted proxy, so its forwarding headers are extended, not replaced
    trusted_peer: bool,
}

/// An early response produced by the proxy itself.
#[derive(Debug)]
pub struct Rejection {
    status: StatusCode,
    reason: &'static str,
    retry_after_secs: Option<u64>,
}

impl Rejection {
    fn new(status: StatusCode, reason: &'static str) -> Self {
        Rejection {
            status,
            reason,
            retry_after_secs: None,
        }
    }

    fn bad_request(reason: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason)
    }

    fn from_decision(decision: Decision) -> Self {
        match decision {
            Decision::RateLimited {
                retry_after_secs, ..
            } => Rejection {
                status: StatusCode::TOO_MANY_REQUESTS,
                reason: "rate limited by policy",
                retry_after_secs: Some(retry_after_secs),
            },
            Decision::Unavailable(_) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "policy evaluation failed")
            }
            Decision::Deny(_) | Decision::Allow => {
                Self::new(StatusCode::FORBIDDEN, "blocked by policy")
            }
        }
    }

    fn into_response(self) -> Response<ProxyBody> {
        let body = format!(
            "{} {}\n",
            self.status.as_u16(),
            self.status.canonical_reason().unwrap_or("")
        );
        let mut builder = Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
        if let Some(secs) = self.retry_after_secs {
            builder = builder.header(header::RETRY_AFTER, secs);
        }
        builder
            .body(full_body(body))
            .expect("static rejection response is valid")
    }
}

pub struct HttpProxy {
    router: Router,
    settings: HttpConfig,
    policy: Arc<Policy>,
    acme_challenges: Option<Arc<Http01Challenges>>,
    tracker: TaskTracker,
}

impl HttpProxy {
    pub fn new(
        router: Router,
        settings: HttpConfig,
        policy: Arc<Policy>,
        acme_challenges: Option<Arc<Http01Challenges>>,
        tracker: TaskTracker,
    ) -> Self {
        HttpProxy {
            router,
            settings,
            policy,
            acme_challenges,
            tracker,
        }
    }

    /// Accept plain HTTP connections until shutdown.
    pub async fn serve_http(self: Arc<Self>, listener: TcpListener, shutdown: CancellationToken) {
        loop {
            let (stream, client_addr) = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "HTTP accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let proxy = self.clone();
            let shutdown = shutdown.clone();
            self.tracker.spawn(async move {
                let info = ConnInfo {
                    client_addr,
                    scheme: Scheme::Http,
                    sni: None,
                };
                proxy
                    .serve_connection(TokioIo::new(stream), info, shutdown)
                    .await;
            });
        }
    }

    /// Accept TLS connections until shutdown. Certificates are chosen by SNI.
    pub async fn serve_https(
        self: Arc<Self>,
        listener: TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
        shutdown: CancellationToken,
    ) {
        loop {
            let (stream, client_addr) = tokio::select! {
                _ = shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "HTTPS accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let proxy = self.clone();
            let acceptor = acceptor.clone();
            let shutdown = shutdown.clone();
            self.tracker.spawn(async move {
                let handshake = tokio::time::timeout(
                    proxy.settings.tls_handshake_timeout(),
                    acceptor.accept(stream),
                );
                let tls = match handshake.await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => {
                        tracing::debug!(client_addr = %client_addr, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(client_addr = %client_addr, "TLS handshake timed out");
                        return;
                    }
                };
                let sni = tls
                    .get_ref()
                    .1
                    .server_name()
                    .and_then(|name| hostname::normalize_hostname(name).ok());
                let info = ConnInfo {
                    client_addr,
                    scheme: Scheme::Https,
                    sni,
                };
                proxy.serve_connection(TokioIo::new(tls), info, shutdown).await;
            });
        }
    }

    async fn serve_connection<I>(
        self: Arc<Self>,
        io: I,
        info: ConnInfo,
        shutdown: CancellationToken,
    ) where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let info = Arc::new(info);
        let proxy = self.clone();
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let proxy = proxy.clone();
            let info = info.clone();
            async move { Ok::<_, Infallible>(proxy.handle(req, &info).await) }
        });

        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(self.settings.header_read_timeout())
            .max_buf_size(self.settings.max_header_bytes);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(self.settings.h2_max_concurrent_streams)
            .max_header_list_size(self.settings.max_header_bytes as u32);

        let conn = builder.serve_connection_with_upgrades(io, service);
        tokio::pin!(conn);
        tokio::select! {
            result = conn.as_mut() => {
                if let Err(e) = result {
                    tracing::debug!(error = %e, "HTTP connection error");
                }
            }
            _ = shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "HTTP connection error during shutdown");
                }
            }
        }
    }

    async fn handle(&self, req: Request<Incoming>, info: &ConnInfo) -> Response<ProxyBody> {
        match self.proxy_request(req, info).await {
            Ok(response) => response,
            Err(rejection) => {
                tracing::debug!(
                    client_ip = %info.client_addr.ip(),
                    status = rejection.status.as_u16(),
                    reason = rejection.reason,
                    "request rejected"
                );
                rejection.into_response()
            }
        }
    }

    async fn proxy_request(
        &self,
        mut req: Request<Incoming>,
        info: &ConnInfo,
    ) -> Result<Response<ProxyBody>, Rejection> {
        if req.method() == Method::CONNECT {
            return Err(Rejection::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT is not supported",
            ));
        }
        let authority = request_authority(&req)?;
        let hostname = request_hostname(&authority)?;
        if info.scheme == Scheme::Https && info.sni.as_deref() != Some(hostname.as_str()) {
            return Err(Rejection::new(
                StatusCode::MISDIRECTED_REQUEST,
                "host does not match TLS server name",
            ));
        }

        // HTTP-01 validation for ACME-managed domains is answered by the Edge itself,
        // without a Connector. Only this exact prefix on managed names is exempt from
        // tenant policy; it has its own concurrency budget.
        if info.scheme == Scheme::Http && req.uri().path().starts_with(CHALLENGE_PATH_PREFIX) {
            if let Some(challenges) = self
                .acme_challenges
                .as_ref()
                .filter(|c| c.serves(&hostname))
            {
                return Ok(challenge_response(challenges, &hostname, &req));
            }
        }

        // The route also tells us which tenant owns the hostname, before any
        // stream is opened, so the policy can be applied first.
        let decision = self.router.route(&hostname, Protocol::Http);
        let Some(tenant_id) = decision.tenant_id().map(str::to_string) else {
            return Err(Rejection::new(
                StatusCode::BAD_GATEWAY,
                "no route for hostname",
            ));
        };

        // Policy runs once per request at the ingress Edge, before any stream is opened.
        let peer_ip = info.client_addr.ip().to_canonical();
        let client_ip = self.policy.client_ip(peer_ip, req.headers());
        let verdict = self
            .policy
            .evaluate_http(&RequestContext {
                tenant_id: &tenant_id,
                hostname: &hostname,
                protocol: Protocol::Http,
                client_ip,
                method: req.method().as_str(),
                path: req.uri().path(),
            })
            .await;
        if verdict.rejects() {
            return Err(Rejection::from_decision(verdict.decision));
        }

        let forwarded = self.settings.forwarded_headers.then(|| Forwarded {
            peer_ip,
            trusted_peer: self.policy.is_trusted_proxy(peer_ip),
        });
        let upgrade = upgrade_protocol(&req);
        let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut req));
        let backend_request =
            build_backend_request(req, &authority, info.scheme, upgrade, forwarded)?;

        let stream = match self
            .router
            .open(&decision, &hostname, Protocol::Http, info.client_addr)
            .await
        {
            Ok(stream) => stream,
            // Before the response starts, a missing or failing route is 502 and a
            // timeout waiting for the tunnel is 504.
            Err(e) if e.timed_out => {
                tracing::debug!(hostname, error = %e.message, "opening the tunnel timed out");
                return Err(Rejection::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "tunnel open timed out",
                ));
            }
            Err(e) => {
                tracing::debug!(hostname, error = %e.message, "cannot open tunnel stream");
                return Err(Rejection::new(
                    StatusCode::BAD_GATEWAY,
                    "tunnel unavailable",
                ));
            }
        };

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(self.settings.max_header_bytes)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|e| {
                tracing::debug!(hostname, error = %e, "backend handshake failed");
                Rejection::new(StatusCode::BAD_GATEWAY, "backend handshake failed")
            })?;
        self.tracker.spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "backend connection error");
            }
        });

        let send = tokio::time::timeout(
            self.settings.response_header_timeout(),
            sender.send_request(backend_request),
        );
        let mut response = match send.await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                tracing::debug!(hostname, error = %e, "backend request failed");
                return Err(Rejection::new(
                    StatusCode::BAD_GATEWAY,
                    "backend request failed",
                ));
            }
            Err(_) => {
                return Err(Rejection::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "backend response timed out",
                ))
            }
        };

        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(client_upgrade) = client_upgrade else {
                return Err(Rejection::new(
                    StatusCode::BAD_GATEWAY,
                    "unexpected upgrade from backend",
                ));
            };
            let backend_upgrade = hyper::upgrade::on(&mut response);
            self.tracker.spawn(async move {
                match tokio::try_join!(client_upgrade, backend_upgrade) {
                    Ok((client, backend)) => {
                        let mut client = TokioIo::new(client);
                        let mut backend = TokioIo::new(backend);
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
                    }
                    Err(e) => tracing::debug!(error = %e, "protocol upgrade failed"),
                }
            });
            let (parts, _) = response.into_parts();
            return Ok(Response::from_parts(parts, empty_body()));
        }

        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        Ok(Response::from_parts(
            parts,
            body.map_err(|e| Box::new(e) as BoxError).boxed(),
        ))
    }
}

fn challenge_response<B>(
    challenges: &Http01Challenges,
    hostname: &str,
    req: &Request<B>,
) -> Response<ProxyBody> {
    let Some(permit) = challenges.try_acquire() else {
        return Rejection::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many challenge requests",
        )
        .into_response();
    };
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Rejection::new(StatusCode::METHOD_NOT_ALLOWED, "challenge requires GET")
            .into_response();
    }
    let key_authorization = Http01Challenges::token_from_path(req.uri().path())
        .and_then(|token| challenges.lookup(hostname, token));
    let Some(key_authorization) = key_authorization else {
        return Rejection::new(StatusCode::NOT_FOUND, "unknown challenge token").into_response();
    };
    let body = PermitBody {
        inner: Full::new(Bytes::from(key_authorization)),
        _permit: permit,
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body.boxed())
        .expect("static challenge response is valid")
}

/// A body that holds a semaphore permit until it is dropped.
struct PermitBody {
    inner: Full<Bytes>,
    _permit: OwnedSemaphorePermit,
}

impl Body for PermitBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_frame(cx)
            .map_err(|never| match never {})
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The authority the client addressed: `:authority`/absolute URI or a single Host header.
fn request_authority<B>(req: &Request<B>) -> Result<String, Rejection> {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host_header = hosts.next();
    if hosts.next().is_some() {
        return Err(Rejection::bad_request("duplicate Host header"));
    }
    let host_header = host_header
        .map(|v| {
            v.to_str()
                .map_err(|_| Rejection::bad_request("invalid Host header"))
        })
        .transpose()?;
    let uri_authority = req.uri().authority().map(|a| a.as_str());
    match (uri_authority, host_header) {
        (Some(authority), Some(host)) if !authority.eq_ignore_ascii_case(host) => Err(
            Rejection::bad_request("Host header does not match request authority"),
        ),
        (Some(authority), _) => Ok(authority.to_string()),
        (None, Some(host)) => Ok(host.to_string()),
        (None, None) => Err(Rejection::bad_request("missing Host header")),
    }
}

fn request_hostname(authority: &str) -> Result<String, Rejection> {
    let (host, _port) = hostname::split_authority(authority)
        .map_err(|_| Rejection::bad_request("invalid authority"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    hostname::normalize_hostname(host).map_err(|_| Rejection::bad_request("invalid host"))
}

/// The `Upgrade` protocol of an HTTP/1.1 upgrade request, if any.
fn upgrade_protocol<B>(req: &Request<B>) -> Option<HeaderValue> {
    if req.version() != Version::HTTP_11 {
        return None;
    }
    let requests_upgrade = header_tokens(req.headers(), &header::CONNECTION)
        .any(|token| token.eq_ignore_ascii_case("upgrade"));
    if !requests_upgrade {
        return None;
    }
    req.headers().get(header::UPGRADE).cloned()
}

fn header_tokens<'a>(headers: &'a HeaderMap, name: &HeaderName) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = header_tokens(headers, &header::CONNECTION)
        .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
}

fn build_backend_request<B>(
    req: Request<B>,
    authority: &str,
    scheme: Scheme,
    upgrade: Option<HeaderValue>,
    forwarded: Option<Forwarded>,
) -> Result<Request<B>, Rejection> {
    let (mut parts, body) = req.into_parts();
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    parts.uri =
        Uri::try_from(target).map_err(|_| Rejection::bad_request("invalid request target"))?;
    parts.version = Version::HTTP_11;

    strip_hop_by_hop(&mut parts.headers);
    join_cookie_fields(&mut parts.headers);
    parts.headers.insert(
        header::HOST,
        HeaderValue::from_str(authority)
            .map_err(|_| Rejection::bad_request("invalid authority"))?,
    );
    if let Some(protocol) = upgrade {
        parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        parts.headers.insert(header::UPGRADE, protocol);
    }
    if let Some(forwarded) = forwarded {
        apply_forwarded_headers(&mut parts.headers, forwarded, scheme);
    }
    Ok(Request::from_parts(parts, body))
}

/// Join the `cookie` fields of a request into one. HTTP/2 clients send cookies
/// as separate fields, and an HTTP/1.1 backend may read only the first of them
/// (RFC 9113 §8.2.3).
fn join_cookie_fields(headers: &mut HeaderMap) {
    let mut values = headers.get_all(header::COOKIE).iter();
    if values.next().is_none() || values.next().is_none() {
        return;
    }
    let mut joined = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        if !joined.is_empty() {
            joined.extend_from_slice(b"; ");
        }
        joined.extend_from_slice(value.as_bytes());
    }
    let joined = HeaderValue::from_bytes(&joined).expect("joined header values stay valid");
    headers.insert(header::COOKIE, joined);
}

/// Set X-Forwarded-For / X-Forwarded-Proto. Values supplied by untrusted peers
/// are replaced; a trusted proxy's chain is extended with the proxy's address.
fn apply_forwarded_headers(headers: &mut HeaderMap, forwarded: Forwarded, scheme: Scheme) {
    let xff = HeaderName::from_static("x-forwarded-for");
    let proto = HeaderName::from_static("x-forwarded-proto");
    let peer = forwarded.peer_ip.to_string();

    let chain = if forwarded.trusted_peer {
        let prior: Vec<&str> = headers
            .get_all(&xff)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if prior.is_empty() {
            peer.clone()
        } else {
            format!("{}, {peer}", prior.join(", "))
        }
    } else {
        peer.clone()
    };
    let value = HeaderValue::from_str(&chain)
        .or_else(|_| HeaderValue::from_str(&peer))
        .expect("IP address is a valid header value");
    headers.insert(xff, value);

    if !(forwarded.trusted_peer && headers.contains_key(&proto)) {
        headers.insert(proto, HeaderValue::from_static(scheme.as_str()));
    }
}

fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarded(trusted_peer: bool) -> Option<Forwarded> {
        Some(Forwarded {
            peer_ip: "203.0.113.7".parse().unwrap(),
            trusted_peer,
        })
    }

    #[test]
    fn authority_from_host_or_uri() {
        let req = Request::builder()
            .uri("/")
            .header("host", "Web.Test:8080")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&req).unwrap(), "Web.Test:8080");
        assert_eq!(request_hostname("Web.Test:8080").unwrap(), "web.test");

        let req = Request::builder()
            .uri("http://a.test/x")
            .header("host", "a.test")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&req).unwrap(), "a.test");
    }

    #[test]
    fn rejects_ambiguous_authority() {
        let req = Request::builder()
            .uri("/")
            .header("host", "a.test")
            .header("host", "b.test")
            .body(())
            .unwrap();
        assert_eq!(
            request_authority(&req).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        let req = Request::builder()
            .uri("http://a.test/")
            .header("host", "b.test")
            .body(())
            .unwrap();
        assert!(request_authority(&req).is_err());

        let req = Request::builder().uri("/").body(()).unwrap();
        assert!(request_authority(&req).is_err());

        assert!(request_hostname("user@a.test").is_err());
        assert!(request_hostname("bad_host").is_err());
    }

    #[test]
    fn strips_hop_by_hop_and_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("1"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("x-app", HeaderValue::from_static("kept"));
        strip_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-app"));
    }

    #[test]
    fn backend_request_is_origin_form_http11_with_forwarding_headers() {
        let req = Request::builder()
            .method("POST")
            .uri("https://a.test/path?q=1")
            .version(Version::HTTP_2)
            .header("x-forwarded-for", "198.51.100.1")
            .header("x-forwarded-proto", "http")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let backend =
            build_backend_request(req, "a.test", Scheme::Https, None, forwarded(false)).unwrap();
        assert_eq!(backend.uri(), "/path?q=1");
        assert_eq!(backend.version(), Version::HTTP_11);
        assert_eq!(backend.headers()["host"], "a.test");
        assert_eq!(backend.headers()["x-forwarded-for"], "203.0.113.7");
        assert_eq!(backend.headers()["x-forwarded-proto"], "https");
        assert!(!backend.headers().contains_key("te"));
    }

    #[test]
    fn cookie_fields_of_http2_requests_are_joined() {
        let req = Request::builder()
            .uri("https://a.test/")
            .version(Version::HTTP_2)
            .header("cookie", "session=abc")
            .header("cookie", "csrf=def")
            .header("cookie", "theme=dark")
            .body(())
            .unwrap();
        let backend = build_backend_request(req, "a.test", Scheme::Https, None, None).unwrap();
        let cookies: Vec<_> = backend.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["session=abc; csrf=def; theme=dark"]);

        let req = Request::builder()
            .uri("/")
            .header("cookie", "session=abc; csrf=def")
            .body(())
            .unwrap();
        let backend = build_backend_request(req, "a.test", Scheme::Http, None, None).unwrap();
        assert_eq!(backend.headers()["cookie"], "session=abc; csrf=def");
    }

    #[test]
    fn trusted_proxy_chain_is_extended() {
        let req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "192.0.2.1")
            .header("x-forwarded-for", "10.0.0.5")
            .header("x-forwarded-proto", "https")
            .body(())
            .unwrap();
        let backend =
            build_backend_request(req, "a.test", Scheme::Http, None, forwarded(true)).unwrap();
        assert_eq!(
            backend.headers()["x-forwarded-for"],
            "192.0.2.1, 10.0.0.5, 203.0.113.7"
        );
        assert_eq!(backend.headers()["x-forwarded-proto"], "https");

        let req = Request::builder().uri("/").body(()).unwrap();
        let backend = build_backend_request(req, "a.test", Scheme::Http, None, None).unwrap();
        assert!(!backend.headers().contains_key("x-forwarded-for"));
    }

    #[test]
    fn policy_decisions_map_to_statuses() {
        use crate::policy::Reason;
        let limited = Rejection::from_decision(Decision::RateLimited {
            reason: Reason::RateLimit,
            retry_after_secs: 7,
        });
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.into_response().headers()["retry-after"], "7");
        assert_eq!(
            Rejection::from_decision(Decision::Deny(Reason::BlockedCidr)).status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            Rejection::from_decision(Decision::Unavailable(Reason::PluginFailure)).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn upgrade_detection_requires_connection_token() {
        let req = Request::builder()
            .uri("/ws")
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();
        assert_eq!(upgrade_protocol(&req).unwrap(), "websocket");

        let req = Request::builder()
            .uri("/ws")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();
        assert!(upgrade_protocol(&req).is_none());

        let upgrade = upgrade_protocol(
            &Request::builder()
                .uri("/ws")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(())
                .unwrap(),
        );
        let req = Request::builder().uri("/ws").body(()).unwrap();
        let backend = build_backend_request(req, "a.test", Scheme::Http, upgrade, None).unwrap();
        assert_eq!(backend.headers()["connection"], "upgrade");
        assert_eq!(backend.headers()["upgrade"], "websocket");
    }
}
