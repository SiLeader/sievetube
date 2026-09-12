//! Contract tests shared by every DNS provider adapter, run against local mock APIs.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use super::cloudflare::{CloudflareProvider, Secret};
use super::memory::MemoryProvider;
use super::{ChangeTicket, DnsError, Provider, RecordSet, RecordType};

pub fn set(name: &str, record_type: RecordType, ttl: u32, values: &[&str]) -> RecordSet {
    RecordSet {
        name: name.to_string(),
        record_type,
        ttl,
        values: values.iter().map(|v| v.to_string()).collect(),
        proxied: None,
    }
}

async fn wait_synced(provider: &Provider, ticket: ChangeTicket) {
    for _ in 0..100 {
        if provider.change_synced(&ticket).await.unwrap() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("change {ticket:?} did not sync");
}

async fn assert_current(
    provider: &Provider,
    name: &str,
    record_type: RecordType,
    expected: Option<&RecordSet>,
) {
    let observed = provider.get(name, record_type).await.unwrap();
    match (observed, expected) {
        (None, None) => {}
        (Some(observed), Some(expected)) => {
            assert!(
                observed.set.same_data(expected),
                "provider has {:?}, expected {expected:?}",
                observed.set
            )
        }
        (observed, expected) => panic!("provider has {observed:?}, expected {expected:?}"),
    }
}

async fn apply(provider: &Provider, expected: Option<&RecordSet>, desired: Option<&RecordSet>) {
    let target = desired.or(expected).expect("a change needs a record");
    let ticket = provider
        .replace(&target.name, target.record_type, expected, desired)
        .await
        .unwrap();
    wait_synced(provider, ticket).await;
}

fn assert_conflict(result: Result<ChangeTicket, DnsError>) {
    assert!(
        matches!(result, Err(DnsError::Conflict(_))),
        "expected conflict, got {result:?}"
    );
}

/// Behaviour every adapter must provide for the reconciler to be safe.
pub async fn provider_contract(provider: &Provider, zone: &str) {
    let name = format!("contract.{zone}");
    assert_current(provider, &name, RecordType::A, None).await;

    // Create with several values.
    let v1 = set(&name, RecordType::A, 300, &["192.0.2.1", "192.0.2.2"]);
    apply(provider, None, Some(&v1)).await;
    assert_current(provider, &name, RecordType::A, Some(&v1)).await;

    // Creating again is a conflict, not an overwrite.
    assert_conflict(
        provider
            .replace(&name, RecordType::A, None, Some(&v1))
            .await,
    );

    // Update with overlapping values and a TTL change.
    let v2 = set(&name, RecordType::A, 600, &["192.0.2.2", "192.0.2.3"]);
    apply(provider, Some(&v1), Some(&v2)).await;
    assert_current(provider, &name, RecordType::A, Some(&v2)).await;

    // A stale expectation is rejected and nothing changes.
    assert_conflict(
        provider
            .replace(&name, RecordType::A, Some(&v1), Some(&v1))
            .await,
    );
    assert_conflict(
        provider
            .replace(&name, RecordType::A, Some(&v1), None)
            .await,
    );
    assert_current(provider, &name, RecordType::A, Some(&v2)).await;

    // TXT values with spaces and quotes survive a round trip.
    let txt = set(
        &name,
        RecordType::Txt,
        120,
        &["hello world", "v=spf1 -all", "quote\"inside"],
    );
    apply(provider, None, Some(&txt)).await;
    assert_current(provider, &name, RecordType::Txt, Some(&txt)).await;
    let txt_less = set(&name, RecordType::Txt, 120, &["hello world"]);
    apply(provider, Some(&txt), Some(&txt_less)).await;
    assert_current(provider, &name, RecordType::Txt, Some(&txt_less)).await;

    // CNAME targets can be changed.
    let alias = format!("alias.{zone}");
    let c1 = set(&alias, RecordType::Cname, 300, &["edge-a.example.net"]);
    let c2 = set(&alias, RecordType::Cname, 300, &["edge-b.example.net"]);
    apply(provider, None, Some(&c1)).await;
    apply(provider, Some(&c1), Some(&c2)).await;
    assert_current(provider, &alias, RecordType::Cname, Some(&c2)).await;

    // IPv6 values are compared in canonical form.
    let v6 = set(&name, RecordType::Aaaa, 300, &["2001:db8::1"]);
    apply(provider, None, Some(&v6)).await;
    assert_current(provider, &name, RecordType::Aaaa, Some(&v6)).await;

    // Deletion.
    apply(provider, Some(&v2), None).await;
    apply(provider, Some(&txt_less), None).await;
    apply(provider, Some(&c2), None).await;
    apply(provider, Some(&v6), None).await;
    assert_current(provider, &name, RecordType::A, None).await;
    assert_current(provider, &alias, RecordType::Cname, None).await;
    assert_conflict(
        provider
            .replace(&name, RecordType::A, Some(&v2), None)
            .await,
    );
}

#[tokio::test]
async fn memory_provider_contract() {
    provider_contract(&Provider::Memory(MemoryProvider::new()), "example.com").await;
    provider_contract(
        &Provider::Memory(MemoryProvider::with_tracked_changes()),
        "example.com",
    )
    .await;
}

// --- Cloudflare mock API ----------------------------------------------------

#[derive(Clone, Debug)]
struct MockRecord {
    id: String,
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

#[derive(Default)]
struct CloudflareState {
    records: Vec<MockRecord>,
    next_id: u64,
    failures: VecDeque<(Method, u16, Option<u64>)>,
    requests: Vec<Method>,
    observer: Option<super::ChangeObserver>,
}

impl CloudflareState {
    fn notify(&self, name: &str, record_type: &str) {
        if let Some(observer) = &self.observer {
            let values = self
                .records
                .iter()
                .filter(|r| r.name == name && r.record_type == record_type)
                .map(|r| super::unquote_txt(&r.content))
                .collect();
            observer(name, record_type, values);
        }
    }
}

pub struct CloudflareMock {
    pub base_url: String,
    state: Arc<Mutex<CloudflareState>>,
}

pub const MOCK_ZONE_ID: &str = "zone123";
pub const MOCK_TOKEN: &str = "test-token";

impl CloudflareMock {
    pub async fn start() -> Self {
        Self::start_with_observer(None).await
    }

    pub async fn start_with_observer(observer: Option<super::ChangeObserver>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(CloudflareState {
            observer,
            ..CloudflareState::default()
        }));
        let served = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = served.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(cloudflare_handle(req, state).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        CloudflareMock {
            base_url: format!("http://{addr}/client/v4"),
            state,
        }
    }

    pub fn provider(&self, token: &str) -> Provider {
        crate::test_support::install_crypto();
        Provider::Cloudflare(Box::new(
            CloudflareProvider::new(
                MOCK_ZONE_ID.to_string(),
                Some(self.base_url.clone()),
                Secret::new(token.to_string()),
                Duration::from_secs(5),
            )
            .unwrap(),
        ))
    }

    /// Fail the next request with `method` with an HTTP status.
    pub fn fail_next(&self, method: Method, status: u16, retry_after: Option<u64>) {
        self.state
            .lock()
            .unwrap()
            .failures
            .push_back((method, status, retry_after));
    }

    pub fn insert(&self, record_type: &str, name: &str, content: &str, ttl: u32, proxied: bool) {
        let mut state = self.state.lock().unwrap();
        state.next_id += 1;
        let id = format!("rec{}", state.next_id);
        state.records.push(MockRecord {
            id,
            record_type: record_type.to_string(),
            name: name.to_string(),
            content: content.to_string(),
            ttl,
            proxied,
        });
    }

    pub fn requests(&self, method: &Method) -> usize {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|m| *m == method)
            .count()
    }
}

fn json_response(status: u16, body: Value, retry_after: Option<u64>) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some(secs) = retry_after {
        builder = builder.header("retry-after", secs.to_string());
    }
    builder
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn api_error(status: u16, code: i64, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        json!({"success": false, "errors": [{"code": code, "message": message}], "result": null}),
        None,
    )
}

fn record_json(r: &MockRecord) -> Value {
    json!({"id": r.id, "type": r.record_type, "name": r.name, "content": r.content, "ttl": r.ttl, "proxied": r.proxied})
}

async fn cloudflare_handle(
    req: Request<Incoming>,
    state: Arc<Mutex<CloudflareState>>,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {MOCK_TOKEN}"));
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let body = req.into_body().collect().await.unwrap().to_bytes();

    let mut state = state.lock().unwrap();
    state.requests.push(method.clone());
    if !authorized {
        return api_error(403, 10000, "Authentication error");
    }
    if state.failures.front().is_some_and(|(m, _, _)| *m == method) {
        let (_, status, retry_after) = state.failures.pop_front().unwrap();
        return json_response(
            status,
            json!({"success": false, "errors": [{"code": 1, "message": "injected"}]}),
            retry_after,
        );
    }

    let prefix = format!("/client/v4/zones/{MOCK_ZONE_ID}/dns_records");
    let Some(rest) = path.strip_prefix(&prefix) else {
        return api_error(404, 7003, "Could not route to zone");
    };
    let id = rest
        .strip_prefix('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();

    match (method, id) {
        (Method::GET, None) => {
            let matching: Vec<&MockRecord> = state
                .records
                .iter()
                .filter(|r| params.get("type").is_none_or(|t| *t == r.record_type))
                .filter(|r| params.get("name").is_none_or(|n| *n == r.name))
                .collect();
            // One record per page, to exercise pagination.
            let page: usize = params.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
            let total_pages = matching.len().max(1);
            let result: Vec<Value> = matching
                .get(page - 1)
                .map(|r| vec![record_json(r)])
                .unwrap_or_default();
            json_response(
                200,
                json!({"success": true, "errors": [], "result": result, "result_info": {"page": page, "per_page": 1, "total_pages": total_pages, "count": result.len(), "total_count": matching.len()}}),
                None,
            )
        }
        (Method::POST, None) => {
            let v: Value = serde_json::from_slice(&body).unwrap();
            let record_type = v["type"].as_str().unwrap().to_string();
            let name = v["name"].as_str().unwrap().to_string();
            let content = v["content"].as_str().unwrap().to_string();
            if state
                .records
                .iter()
                .any(|r| r.name == name && (r.record_type == "CNAME" || record_type == "CNAME"))
            {
                return api_error(
                    400,
                    81053,
                    "An A, AAAA, or CNAME record with that host already exists.",
                );
            }
            if state
                .records
                .iter()
                .any(|r| r.name == name && r.record_type == record_type && r.content == content)
            {
                return api_error(
                    400,
                    81058,
                    "A record with the same settings already exists.",
                );
            }
            state.next_id += 1;
            let record = MockRecord {
                id: format!("rec{}", state.next_id),
                record_type,
                name,
                content,
                ttl: v["ttl"].as_u64().unwrap_or(1) as u32,
                proxied: v["proxied"].as_bool().unwrap_or(false),
            };
            let response = record_json(&record);
            let (name, record_type) = (record.name.clone(), record.record_type.clone());
            state.records.push(record);
            state.notify(&name, &record_type);
            json_response(
                200,
                json!({"success": true, "errors": [], "result": response}),
                None,
            )
        }
        (Method::PATCH, Some(id)) => {
            let v: Value = serde_json::from_slice(&body).unwrap();
            let Some(record) = state.records.iter_mut().find(|r| r.id == id) else {
                return api_error(404, 81044, "Record does not exist.");
            };
            if let Some(ttl) = v["ttl"].as_u64() {
                record.ttl = ttl as u32;
            }
            if let Some(proxied) = v["proxied"].as_bool() {
                record.proxied = proxied;
            }
            json_response(
                200,
                json!({"success": true, "errors": [], "result": record_json(record)}),
                None,
            )
        }
        (Method::DELETE, Some(id)) => {
            let Some(removed) = state.records.iter().find(|r| r.id == id).cloned() else {
                return api_error(404, 81044, "Record does not exist.");
            };
            state.records.retain(|r| r.id != id);
            state.notify(&removed.name, &removed.record_type);
            json_response(
                200,
                json!({"success": true, "errors": [], "result": {"id": id}}),
                None,
            )
        }
        _ => api_error(405, 10405, "Method not allowed"),
    }
}

#[tokio::test]
async fn cloudflare_provider_contract() {
    let mock = CloudflareMock::start().await;
    let provider = mock.provider(MOCK_TOKEN);
    provider_contract(&provider, "example.com").await;
    assert!(
        mock.requests(&Method::GET) > 20,
        "paginated listing expected"
    );
}

#[tokio::test]
async fn cloudflare_maps_errors_and_hides_the_token() {
    let mock = CloudflareMock::start().await;
    let provider = mock.provider(MOCK_TOKEN);

    mock.fail_next(Method::GET, 429, Some(7));
    let err = provider
        .get("www.example.com", RecordType::A)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        DnsError::RateLimited {
            retry_after: Some(Duration::from_secs(7))
        }
    );

    mock.fail_next(Method::GET, 502, None);
    assert!(matches!(
        provider.get("www.example.com", RecordType::A).await,
        Err(DnsError::Provider(_))
    ));

    let wrong = mock.provider("expired-token");
    assert!(matches!(
        wrong.get("www.example.com", RecordType::A).await,
        Err(DnsError::Auth(_))
    ));

    let Provider::Cloudflare(inner) = &provider else {
        unreachable!()
    };
    assert!(
        !format!("{inner:?}").contains(MOCK_TOKEN),
        "token must not appear in Debug output"
    );
}

#[tokio::test]
async fn cloudflare_keeps_proxy_setting_and_recovers_from_partial_update() {
    let mock = CloudflareMock::start().await;
    let provider = mock.provider(MOCK_TOKEN);
    let name = "www.example.com";

    mock.insert("A", name, "192.0.2.1", 1, true);
    mock.insert("A", name, "192.0.2.2", 1, true);
    let current = provider
        .get(name, RecordType::A)
        .await
        .unwrap()
        .unwrap()
        .set;
    assert_eq!(current.proxied, Some(true));

    // Desired state without a proxy preference: the proxy flag is kept.
    let desired = set(name, RecordType::A, 1, &["192.0.2.2", "192.0.2.3"]);
    mock.fail_next(Method::DELETE, 500, None);
    let err = provider
        .replace(name, RecordType::A, Some(&current), Some(&desired))
        .await
        .unwrap_err();
    assert!(matches!(err, DnsError::Provider(_)));

    // The new value was added but the old one not removed; resuming from the
    // observed intermediate state completes the change.
    let partial = provider
        .get(name, RecordType::A)
        .await
        .unwrap()
        .unwrap()
        .set;
    assert_eq!(partial.values.len(), 3);
    provider
        .replace(name, RecordType::A, Some(&partial), Some(&desired))
        .await
        .unwrap();
    let done = provider
        .get(name, RecordType::A)
        .await
        .unwrap()
        .unwrap()
        .set;
    assert!(done.same_data(&desired));
    assert_eq!(done.proxied, Some(true));

    // Records with inconsistent settings are reported as unsupported.
    mock.insert("A", "mixed.example.com", "192.0.2.1", 300, false);
    mock.insert("A", "mixed.example.com", "192.0.2.2", 600, false);
    let mixed = provider
        .get("mixed.example.com", RecordType::A)
        .await
        .unwrap()
        .unwrap();
    assert!(mixed.unsupported.is_some());
}
