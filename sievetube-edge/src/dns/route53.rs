//! Amazon Route 53 adapter.
//!
//! Only simple record sets in public hosted zones are managed; alias records and
//! routing policies (weighted, failover, ...) are reported as unsupported. A change
//! is one atomic change batch: DELETE of the exact current record set plus CREATE
//! of the desired one, so any concurrent modification makes the batch fail.

use std::collections::BTreeSet;
use std::time::Duration;

use aws_sdk_route53::config::{BehaviorVersion, Region};
use aws_sdk_route53::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;

use super::{quote_txt, ChangeTicket, DnsError, Observed, RecordSet, RecordType};

const DEFAULT_REGION: &str = "us-east-1";
const LIST_PAGE_SIZE: i32 = 10;

pub struct Route53Provider {
    client: Client,
    hosted_zone_id: String,
    timeout: Duration,
}

impl std::fmt::Debug for Route53Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route53Provider")
            .field("hosted_zone_id", &self.hosted_zone_id)
            .finish_non_exhaustive()
    }
}

fn rr_type(record_type: RecordType) -> RrType {
    match record_type {
        RecordType::A => RrType::A,
        RecordType::Aaaa => RrType::Aaaa,
        RecordType::Cname => RrType::Cname,
        RecordType::Txt => RrType::Txt,
    }
}

fn fqdn(name: &str) -> String {
    format!("{}.", name.replace('*', "\\052"))
}

/// Route 53 returns names with a trailing dot and octal escapes (`\052` for `*`).
fn decode_name(raw: &str) -> String {
    let mut out = String::new();
    let bytes = raw.trim_end_matches('.').as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit)
        {
            let code = std::str::from_utf8(&bytes[i + 1..i + 4])
                .ok()
                .and_then(|s| u8::from_str_radix(s, 8).ok());
            if let Some(code) = code {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out.to_ascii_lowercase()
}

fn normalize_zone_id(id: String) -> String {
    id.trim()
        .trim_start_matches("/hostedzone/")
        .trim_start_matches("hostedzone/")
        .to_string()
}

fn map_error<E, R>(error: SdkError<E, R>) -> DnsError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug,
{
    if let SdkError::ServiceError(service) = &error {
        let code = service.err().code().unwrap_or_default().to_string();
        let message = service.err().message().unwrap_or_default().to_string();
        return match code.as_str() {
            "InvalidChangeBatch" => DnsError::Conflict(message),
            "PriorRequestNotComplete"
            | "Throttling"
            | "ThrottlingException"
            | "RequestLimitExceeded" => DnsError::RateLimited { retry_after: None },
            "AccessDenied"
            | "AccessDeniedException"
            | "InvalidClientTokenId"
            | "SignatureDoesNotMatch"
            | "ExpiredToken"
            | "UnrecognizedClientException" => DnsError::Auth(format!("{code}: {message}")),
            _ => DnsError::Provider(format!("{code}: {message}")),
        };
    }
    match error {
        SdkError::TimeoutError(_) => DnsError::Timeout,
        other => {
            let detail = DisplayErrorContext(&other).to_string();
            if detail.contains("credentials") {
                DnsError::Auth(detail)
            } else {
                DnsError::Provider(detail)
            }
        }
    }
}

impl Route53Provider {
    /// Uses the AWS SDK's standard credential chain (environment, profile, SSO,
    /// web identity, instance/container roles) and a ring-based rustls client.
    pub async fn new(
        hosted_zone_id: String,
        endpoint_url: Option<String>,
        region: Option<String>,
        timeout: Duration,
    ) -> Self {
        let http_client = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http_client)
            .region(Region::new(
                region.unwrap_or_else(|| DEFAULT_REGION.to_string()),
            ));
        if let Some(url) = endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let sdk_config = loader.load().await;
        Self::with_client(Client::new(&sdk_config), hosted_zone_id, timeout)
    }

    pub fn with_client(client: Client, hosted_zone_id: String, timeout: Duration) -> Self {
        Route53Provider {
            client,
            hosted_zone_id: normalize_zone_id(hosted_zone_id),
            timeout,
        }
    }

    /// All record sets with exactly this name and type (several only with routing policies).
    async fn list_exact(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<ResourceRecordSet>, DnsError> {
        let mut found = Vec::new();
        let mut next_identifier: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_resource_record_sets()
                .hosted_zone_id(&self.hosted_zone_id)
                .start_record_name(fqdn(name))
                .start_record_type(rr_type(record_type))
                .max_items(LIST_PAGE_SIZE);
            if let Some(identifier) = &next_identifier {
                request = request.start_record_identifier(identifier);
            }
            let output = tokio::time::timeout(self.timeout, request.send())
                .await
                .map_err(|_| DnsError::Timeout)?
                .map_err(map_error)?;

            let mut left_range = false;
            for set in output.resource_record_sets() {
                if decode_name(set.name()) == name && *set.r#type() == rr_type(record_type) {
                    found.push(set.clone());
                } else {
                    left_range = true;
                    break;
                }
            }
            let continues_here = output.is_truncated()
                && !left_range
                && output.next_record_name().map(decode_name).as_deref() == Some(name)
                && output.next_record_type() == Some(&rr_type(record_type));
            if !continues_here {
                return Ok(found);
            }
            next_identifier = output.next_record_identifier().map(str::to_string);
            if next_identifier.is_none() {
                return Ok(found);
            }
        }
    }

    fn observed(
        name: &str,
        record_type: RecordType,
        sets: &[ResourceRecordSet],
    ) -> Option<Observed> {
        let first = sets.first()?;
        let values: BTreeSet<String> = first
            .resource_records()
            .iter()
            .filter_map(|r| record_type.normalize_value(r.value()).ok())
            .collect();
        let unsupported = if sets.len() > 1 || first.set_identifier().is_some() {
            Some("record sets with routing policies are not supported".to_string())
        } else if first.alias_target().is_some() {
            Some("alias records are not supported".to_string())
        } else if values.len() != first.resource_records().len() {
            Some("unparsable record values".to_string())
        } else {
            None
        };
        Some(Observed {
            set: RecordSet {
                name: name.to_string(),
                record_type,
                ttl: first.ttl().unwrap_or(0).clamp(0, u32::MAX as i64) as u32,
                values,
                proxied: None,
            },
            unsupported,
        })
    }

    pub async fn get(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<Observed>, DnsError> {
        let sets = self.list_exact(name, record_type).await?;
        Ok(Self::observed(name, record_type, &sets))
    }

    fn build_set(set: &RecordSet) -> Result<ResourceRecordSet, DnsError> {
        let records = set
            .values
            .iter()
            .map(|value| {
                let value = match set.record_type {
                    RecordType::Txt => quote_txt(value),
                    RecordType::Cname => format!("{value}."),
                    _ => value.clone(),
                };
                ResourceRecord::builder()
                    .value(value)
                    .build()
                    .map_err(|e| DnsError::Provider(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ResourceRecordSet::builder()
            .name(fqdn(&set.name))
            .r#type(rr_type(set.record_type))
            .ttl(set.ttl as i64)
            .set_resource_records(Some(records))
            .build()
            .map_err(|e| DnsError::Provider(e.to_string()))
    }

    pub async fn replace(
        &self,
        name: &str,
        record_type: RecordType,
        expected: Option<&RecordSet>,
        desired: Option<&RecordSet>,
    ) -> Result<ChangeTicket, DnsError> {
        // Delete the provider's exact record set (textual forms may differ from our
        // normalized values); the batch fails if it changes before being applied.
        let current_sets = self.list_exact(name, record_type).await?;
        let current = Self::observed(name, record_type, &current_sets);
        if let Some(reason) = current.as_ref().and_then(|c| c.unsupported.clone()) {
            return Err(DnsError::Conflict(reason));
        }
        if !super::same_optional(current.as_ref().map(|c| &c.set), expected) {
            return Err(DnsError::Conflict(
                "record set changed at the provider".to_string(),
            ));
        }
        if expected.is_none() && desired.is_none() {
            return Ok(ChangeTicket::Immediate);
        }

        let mut changes = Vec::new();
        if let Some(raw) = current_sets.into_iter().next() {
            changes.push(
                Change::builder()
                    .action(ChangeAction::Delete)
                    .resource_record_set(raw)
                    .build()
                    .map_err(|e| DnsError::Provider(e.to_string()))?,
            );
        }
        if let Some(desired) = desired {
            changes.push(
                Change::builder()
                    .action(ChangeAction::Create)
                    .resource_record_set(Self::build_set(desired)?)
                    .build()
                    .map_err(|e| DnsError::Provider(e.to_string()))?,
            );
        }
        let batch = ChangeBatch::builder()
            .comment("managed by sievetube")
            .set_changes(Some(changes))
            .build()
            .map_err(|e| DnsError::Provider(e.to_string()))?;
        let request = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send();
        let output = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(map_error)?;
        let change_id = output
            .change_info()
            .map(|info| info.id().trim_start_matches("/change/").to_string())
            .ok_or_else(|| DnsError::Provider("response without change id".to_string()))?;
        Ok(ChangeTicket::Route53 { change_id })
    }

    /// PENDING → INSYNC inside Route 53. Recursive resolvers may still serve old data.
    pub async fn change_synced(&self, change_id: &str) -> Result<bool, DnsError> {
        let request = self.client.get_change().id(change_id).send();
        let output = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(map_error)?;
        Ok(output
            .change_info()
            .is_some_and(|info| *info.status() == ChangeStatus::Insync))
    }
}

#[cfg(test)]
pub mod mock {
    //! Minimal Route 53 REST-XML API with conditional change batches.

    use std::collections::{HashMap, VecDeque};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    #[derive(Clone, Debug, PartialEq)]
    pub struct MockSet {
        pub ttl: i64,
        pub values: Vec<String>,
        pub set_identifier: Option<String>,
        pub alias: bool,
    }

    #[derive(Default)]
    struct State {
        sets: HashMap<(String, String), MockSet>,
        changes: HashMap<String, u32>,
        next_change: u64,
        failures: VecDeque<(u16, String)>,
        observer: Option<crate::dns::ChangeObserver>,
    }

    pub struct Route53Mock {
        pub endpoint: String,
        state: Arc<Mutex<State>>,
    }

    impl Route53Mock {
        pub async fn start() -> Self {
            Self::start_with_observer(None).await
        }

        pub async fn start_with_observer(observer: Option<crate::dns::ChangeObserver>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(State {
                observer,
                ..State::default()
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
                            async move { Ok::<_, Infallible>(handle(req, state).await) }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            });
            Route53Mock {
                endpoint: format!("http://{addr}"),
                state,
            }
        }

        /// Insert a record set as another tool would (`name` with trailing dot).
        pub fn insert(&self, name: &str, record_type: &str, set: MockSet) {
            self.state
                .lock()
                .unwrap()
                .sets
                .insert((name.to_string(), record_type.to_string()), set);
        }

        pub fn fail_next(&self, status: u16, code: &str) {
            self.state
                .lock()
                .unwrap()
                .failures
                .push_back((status, code.to_string()));
        }
    }

    fn escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    fn unescape(value: &str) -> String {
        value
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// Contents of each non-nested `<tag>…</tag>` occurrence.
    fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
        let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
        let mut found = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find(&open) {
            let after = &rest[start + open.len()..];
            let Some(end) = after.find(&close) else { break };
            found.push(&after[..end]);
            rest = &after[end + close.len()..];
        }
        found
    }

    fn first(xml: &str, tag: &str) -> Option<String> {
        elements(xml, tag).first().map(|v| unescape(v))
    }

    fn xml(status: u16, body: String) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/xml")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    fn error(status: u16, code: &str, message: &str) -> Response<Full<Bytes>> {
        xml(
            status,
            format!(
                r#"<?xml version="1.0"?><ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>{code}</Code><Message>{}</Message></Error><RequestId>req-1</RequestId></ErrorResponse>"#,
                escape(message)
            ),
        )
    }

    fn set_xml(name: &str, record_type: &str, set: &MockSet) -> String {
        let mut out = format!(
            "<ResourceRecordSet><Name>{}</Name><Type>{record_type}</Type>",
            escape(name)
        );
        if let Some(id) = &set.set_identifier {
            out.push_str(&format!(
                "<SetIdentifier>{id}</SetIdentifier><Weight>10</Weight>"
            ));
        }
        if set.alias {
            out.push_str("<AliasTarget><HostedZoneId>Z2</HostedZoneId><DNSName>lb.example.net.</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>");
        } else {
            out.push_str(&format!("<TTL>{}</TTL><ResourceRecords>", set.ttl));
            for value in &set.values {
                out.push_str(&format!(
                    "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                    escape(value)
                ));
            }
            out.push_str("</ResourceRecords>");
        }
        out.push_str("</ResourceRecordSet>");
        out
    }

    fn change_info(tag: &str, id: &str, status: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><{tag} xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeInfo><Id>/change/{id}</Id><Status>{status}</Status><SubmittedAt>2026-09-11T00:00:00.000Z</SubmittedAt></ChangeInfo></{tag}>"#
        )
    }

    async fn handle(req: Request<Incoming>, state: Arc<Mutex<State>>) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query: HashMap<String, String> = req
            .uri()
            .query()
            .unwrap_or("")
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_string(), percent_decode(v)))
            .collect();
        let signed = req.headers().contains_key("authorization");
        let body = String::from_utf8(req.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();

        let mut state = state.lock().unwrap();
        if !signed {
            return error(
                403,
                "MissingAuthenticationToken",
                "Missing Authentication Token",
            );
        }
        if let Some((status, code)) = state.failures.pop_front() {
            return error(status, &code, "injected failure");
        }

        if let Some(change_id) = path.strip_prefix("/2013-04-01/change/") {
            let polls = state.changes.entry(change_id.to_string()).or_insert(0);
            *polls += 1;
            let status = if *polls > 1 { "INSYNC" } else { "PENDING" };
            return xml(200, change_info("GetChangeResponse", change_id, status));
        }
        if !path.starts_with("/2013-04-01/hostedzone/Z123/rrset") {
            return error(404, "NoSuchHostedZone", "No hosted zone found");
        }

        if method == http::Method::GET {
            let name = query.get("name").cloned().unwrap_or_default();
            let record_type = query.get("type").cloned().unwrap_or_default();
            let mut items = String::new();
            if let Some(set) = state.sets.get(&(name.clone(), record_type.clone())) {
                items = set_xml(&name, &record_type, set);
            }
            return xml(
                200,
                format!(
                    r#"<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets>{items}</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>10</MaxItems></ListResourceRecordSetsResponse>"#
                ),
            );
        }

        // POST change batch: validate every change against a working copy, then commit.
        let mut working = state.sets.clone();
        let mut touched = Vec::new();
        for change in elements(&body, "Change") {
            let action = first(change, "Action").unwrap_or_default();
            let set_xml = elements(change, "ResourceRecordSet")
                .first()
                .copied()
                .unwrap_or_default();
            let name = first(set_xml, "Name").unwrap_or_default();
            let record_type = first(set_xml, "Type").unwrap_or_default();
            let set = MockSet {
                ttl: first(set_xml, "TTL")
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0),
                values: elements(set_xml, "Value")
                    .iter()
                    .map(|v| unescape(v))
                    .collect(),
                set_identifier: first(set_xml, "SetIdentifier"),
                alias: set_xml.contains("<AliasTarget>"),
            };
            let key = (name.clone(), record_type.clone());
            touched.push(key.clone());
            match action.as_str() {
                "CREATE" => {
                    if working.contains_key(&key) {
                        return error(400, "InvalidChangeBatch", &format!("Tried to create resource record set [name='{name}', type='{record_type}'] but it already exists"));
                    }
                    working.insert(key, set);
                }
                "DELETE" => {
                    let matches = working.get(&key).is_some_and(|existing| {
                        let mut a = existing.values.clone();
                        let mut b = set.values.clone();
                        a.sort();
                        b.sort();
                        existing.ttl == set.ttl && a == b
                    });
                    if !matches {
                        return error(400, "InvalidChangeBatch", &format!("Tried to delete resource record set [name='{name}', type='{record_type}'] but the values provided do not match the current values"));
                    }
                    working.remove(&key);
                }
                other => return error(400, "InvalidInput", &format!("unsupported action {other}")),
            }
        }
        state.sets = working;
        if let Some(observer) = &state.observer {
            for (name, record_type) in touched {
                let values = state
                    .sets
                    .get(&(name.clone(), record_type.clone()))
                    .map(|set| {
                        set.values
                            .iter()
                            .map(|v| crate::dns::unquote_txt(v))
                            .collect()
                    })
                    .unwrap_or_default();
                observer(name.trim_end_matches('.'), &record_type, values);
            }
        }
        state.next_change += 1;
        let id = format!("C{}", state.next_change);
        state.changes.insert(id.clone(), 0);
        xml(
            200,
            change_info("ChangeResourceRecordSetsResponse", &id, "PENDING"),
        )
    }

    fn percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(b) =
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

#[cfg(test)]
pub mod tests_support {
    use super::*;

    /// SDK client for a local mock endpoint with static credentials and no retries.
    pub fn client(endpoint: &str) -> Client {
        client_with_retries(endpoint, false)
    }

    pub fn client_with_retries(endpoint: &str, retries: bool) -> Client {
        crate::test_support::install_crypto();
        let http_client = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let mut config = aws_sdk_route53::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_credential_types::Credentials::new(
                "AKIDTEST", "secret", None, None, "test",
            ))
            .endpoint_url(endpoint)
            .http_client(http_client);
        if !retries {
            config = config.retry_config(aws_sdk_route53::config::retry::RetryConfig::disabled());
        }
        Client::from_conf(config.build())
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{MockSet, Route53Mock};
    use super::tests_support::client_with_retries as client;
    use super::*;
    use crate::dns::contract_tests::provider_contract;
    use crate::dns::Provider;

    #[test]
    fn names_are_encoded_and_decoded() {
        assert_eq!(fqdn("*.example.org"), "\\052.example.org.");
        assert_eq!(decode_name("\\052.Example.org."), "*.example.org");
        assert_eq!(normalize_zone_id("/hostedzone/Z123".into()), "Z123");
    }

    #[tokio::test]
    async fn route53_provider_contract() {
        let mock = Route53Mock::start().await;
        let provider = Provider::Route53(Box::new(Route53Provider::with_client(
            client(&mock.endpoint, false),
            "/hostedzone/Z123".into(),
            Duration::from_secs(10),
        )));
        provider_contract(&provider, "example.org").await;
    }

    #[tokio::test]
    async fn route53_reports_unsupported_sets_and_maps_errors() {
        let mock = Route53Mock::start().await;
        let provider = Route53Provider::with_client(
            client(&mock.endpoint, false),
            "Z123".into(),
            Duration::from_secs(10),
        );

        mock.insert(
            "lb.example.org.",
            "A",
            MockSet {
                ttl: 0,
                values: vec![],
                set_identifier: None,
                alias: true,
            },
        );
        let alias = provider
            .get("lb.example.org", RecordType::A)
            .await
            .unwrap()
            .unwrap();
        assert!(alias.unsupported.unwrap().contains("alias"));

        mock.insert(
            "w.example.org.",
            "A",
            MockSet {
                ttl: 60,
                values: vec!["192.0.2.1".into()],
                set_identifier: Some("blue".into()),
                alias: false,
            },
        );
        let weighted = provider
            .get("w.example.org", RecordType::A)
            .await
            .unwrap()
            .unwrap();
        assert!(weighted.unsupported.is_some());

        // Values stored in another textual form are still matched and deleted exactly.
        mock.insert(
            "v6.example.org.",
            "AAAA",
            MockSet {
                ttl: 300,
                values: vec!["2001:0DB8:0:0:0:0:0:1".into()],
                set_identifier: None,
                alias: false,
            },
        );
        let current = provider
            .get("v6.example.org", RecordType::Aaaa)
            .await
            .unwrap()
            .unwrap()
            .set;
        assert_eq!(current.values.iter().next().unwrap(), "2001:db8::1");
        provider
            .replace("v6.example.org", RecordType::Aaaa, Some(&current), None)
            .await
            .unwrap();
        assert!(provider
            .get("v6.example.org", RecordType::Aaaa)
            .await
            .unwrap()
            .is_none());

        mock.fail_next(400, "PriorRequestNotComplete");
        assert!(matches!(
            provider.get("x.example.org", RecordType::A).await,
            Err(DnsError::RateLimited { .. })
        ));
        mock.fail_next(403, "AccessDenied");
        assert!(matches!(
            provider.get("x.example.org", RecordType::A).await,
            Err(DnsError::Auth(_))
        ));
    }
}
