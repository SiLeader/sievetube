//! Cloudflare DNS adapter (API v4).
//!
//! Cloudflare stores one record per value; this adapter presents them as a single
//! normalized record set and applies the difference value by value.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;

use super::{quote_txt, same_optional, ChangeTicket, DnsError, Observed, RecordSet, RecordType};

pub const DEFAULT_API_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
const PAGE_SIZE: u32 = 100;
const MAX_PAGES: u32 = 1000;
/// Cloudflare error codes meaning "a conflicting record already exists"
const CONFLICT_CODES: [i64; 3] = [81053, 81057, 81058];

pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// HTTPS client verifying servers with the platform trust store. Plain HTTP is
/// allowed only because the base URL can point at a local test server.
pub fn https_client() -> Result<HttpsClient, DnsError> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .try_with_platform_verifier()
        .map_err(|e| DnsError::Provider(format!("TLS setup failed: {e}")))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// A credential that is never printed.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    #[cfg(test)]
    pub fn new(value: String) -> Self {
        Secret(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Read an API token from an environment variable or a file.
pub fn load_token(env: Option<&str>, file: Option<&str>) -> anyhow::Result<Secret> {
    let token = match (env, file) {
        (Some(var), _) => std::env::var(var)
            .map_err(|_| anyhow::anyhow!("environment variable {var} is not set"))?,
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read token file {path}: {e}"))?,
        (None, None) => anyhow::bail!("no API token source configured"),
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("API token is empty");
    }
    Ok(Secret(token))
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct ApiMessage {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    total_pages: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct CfRecord {
    id: String,
    content: String,
    ttl: u32,
    #[serde(default)]
    proxied: Option<bool>,
}

#[derive(Debug)]
pub struct CloudflareProvider {
    zone_id: String,
    base_url: String,
    token: Secret,
    client: HttpsClient,
    timeout: Duration,
}

fn proxiable(record_type: RecordType) -> bool {
    matches!(
        record_type,
        RecordType::A | RecordType::Aaaa | RecordType::Cname
    )
}

impl CloudflareProvider {
    pub fn new(
        zone_id: String,
        base_url: Option<String>,
        token: Secret,
        timeout: Duration,
    ) -> Result<Self, DnsError> {
        Ok(CloudflareProvider {
            zone_id,
            base_url: base_url
                .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            token,
            client: https_client()?,
            timeout,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Envelope<T>, DnsError> {
        let body = body
            .map(|b| Bytes::from(serde_json::to_vec(&b).expect("JSON value serializes")))
            .unwrap_or_default();
        let request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base_url))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token.0))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .map_err(|e| DnsError::Provider(format!("invalid request: {e}")))?;

        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Provider(format!("request failed: {e}")))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let bytes = tokio::time::timeout(self.timeout, response.into_body().collect())
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Provider(format!("reading response failed: {e}")))?
            .to_bytes();

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(DnsError::RateLimited { retry_after });
        }
        let envelope = serde_json::from_slice::<Envelope<T>>(&bytes);
        let messages = |errors: &[ApiMessage]| {
            errors
                .iter()
                .map(|e| format!("{} ({})", e.message, e.code))
                .collect::<Vec<_>>()
                .join("; ")
        };
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let detail = envelope
                .as_ref()
                .map(|e| messages(&e.errors))
                .unwrap_or_else(|_| status.to_string());
            return Err(DnsError::Auth(detail));
        }
        if status.is_server_error() {
            return Err(DnsError::Provider(format!("HTTP {status}")));
        }
        let envelope = envelope
            .map_err(|e| DnsError::Provider(format!("unexpected response (HTTP {status}): {e}")))?;
        if !envelope.success {
            let detail = messages(&envelope.errors);
            if envelope
                .errors
                .iter()
                .any(|e| CONFLICT_CODES.contains(&e.code))
            {
                return Err(DnsError::Conflict(detail));
            }
            return Err(DnsError::Provider(detail));
        }
        Ok(envelope)
    }

    async fn list(&self, name: &str, record_type: RecordType) -> Result<Vec<CfRecord>, DnsError> {
        let mut records = Vec::new();
        let mut page = 1;
        loop {
            let path = format!(
                "/zones/{}/dns_records?type={}&name={name}&per_page={PAGE_SIZE}&page={page}",
                self.zone_id,
                record_type.as_str()
            );
            let envelope: Envelope<Vec<CfRecord>> = self.call(Method::GET, &path, None).await?;
            records.extend(envelope.result.unwrap_or_default());
            let total_pages = envelope.result_info.map(|i| i.total_pages).unwrap_or(1);
            if page >= total_pages || page >= MAX_PAGES {
                break;
            }
            page += 1;
        }
        Ok(records)
    }

    fn observed(name: &str, record_type: RecordType, records: &[CfRecord]) -> Option<Observed> {
        let first = records.first()?;
        let values: BTreeSet<String> = records
            .iter()
            .filter_map(|r| record_type.normalize_value(&r.content).ok())
            .collect();
        let proxy_settings: BTreeSet<Option<bool>> = records.iter().map(|r| r.proxied).collect();
        let unsupported = if values.len() != records.len() {
            Some("duplicate or unparsable record values".to_string())
        } else if records.iter().any(|r| r.ttl != first.ttl) {
            Some("records with different TTLs".to_string())
        } else if proxy_settings.len() > 1 {
            Some("records with different proxy settings".to_string())
        } else {
            None
        };
        Some(Observed {
            set: RecordSet {
                name: name.to_string(),
                record_type,
                ttl: first.ttl,
                values,
                proxied: if proxiable(record_type) {
                    first.proxied
                } else {
                    None
                },
            },
            unsupported,
        })
    }

    pub async fn get(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<Observed>, DnsError> {
        let records = self.list(name, record_type).await?;
        Ok(Self::observed(name, record_type, &records))
    }

    pub async fn replace(
        &self,
        name: &str,
        record_type: RecordType,
        expected: Option<&RecordSet>,
        desired: Option<&RecordSet>,
    ) -> Result<ChangeTicket, DnsError> {
        let records = self.list(name, record_type).await?;
        let current = Self::observed(name, record_type, &records);
        if let Some(reason) = current.as_ref().and_then(|c| c.unsupported.clone()) {
            return Err(DnsError::Conflict(reason));
        }
        if !same_optional(current.as_ref().map(|c| &c.set), expected) {
            return Err(DnsError::Conflict(
                "record set changed at the provider".to_string(),
            ));
        }

        let value_of = |record: &CfRecord| record_type.normalize_value(&record.content).ok();
        let keep = desired.map(|d| d.values.clone()).unwrap_or_default();
        let obsolete: Vec<&CfRecord> = records
            .iter()
            .filter(|r| !value_of(r).is_some_and(|v| keep.contains(&v)))
            .collect();

        // A name can hold only one CNAME, so remove the old target first; for other
        // types add new values first to avoid an empty answer during the change.
        if record_type == RecordType::Cname {
            self.delete_records(&obsolete).await?;
        }
        if let Some(desired) = desired {
            let proxied = desired
                .proxied
                .or(current.as_ref().and_then(|c| c.set.proxied))
                .unwrap_or(false);
            for value in &desired.values {
                let existing = records.iter().find(|r| value_of(r).as_ref() == Some(value));
                match existing {
                    Some(record) => {
                        let proxy_changed =
                            proxiable(record_type) && record.proxied != Some(proxied);
                        if record.ttl != desired.ttl || proxy_changed {
                            let mut body = json!({ "ttl": desired.ttl });
                            if proxiable(record_type) {
                                body["proxied"] = json!(proxied);
                            }
                            let path = format!("/zones/{}/dns_records/{}", self.zone_id, record.id);
                            self.call::<serde_json::Value>(Method::PATCH, &path, Some(body))
                                .await?;
                        }
                    }
                    None => {
                        let content = match record_type {
                            RecordType::Txt => quote_txt(value),
                            _ => value.clone(),
                        };
                        let mut body = json!({
                            "type": record_type.as_str(),
                            "name": name,
                            "content": content,
                            "ttl": desired.ttl,
                        });
                        if proxiable(record_type) {
                            body["proxied"] = json!(proxied);
                        }
                        let path = format!("/zones/{}/dns_records", self.zone_id);
                        self.call::<serde_json::Value>(Method::POST, &path, Some(body))
                            .await?;
                    }
                }
            }
        }
        if record_type != RecordType::Cname {
            self.delete_records(&obsolete).await?;
        }
        Ok(ChangeTicket::Immediate)
    }

    async fn delete_records(&self, records: &[&CfRecord]) -> Result<(), DnsError> {
        for record in records {
            let path = format!("/zones/{}/dns_records/{}", self.zone_id, record.id);
            self.call::<serde_json::Value>(Method::DELETE, &path, None)
                .await?;
        }
        Ok(())
    }
}
