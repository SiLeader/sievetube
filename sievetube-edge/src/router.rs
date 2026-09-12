use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sievetube_common::config::Protocol;

use crate::connector_registry::{ConnectorHandle, ConnectorRegistry};
use crate::mesh::forward::MeshService;
use crate::mesh::routes::RemoteRoute;
use crate::tunnel::{self, TunnelStream};

/// Where traffic for a hostname and protocol should be sent.
pub enum RouteDecision {
    /// A Connector authorized for the hostname is connected to this Edge
    Local(Arc<ConnectorHandle>),
    /// Peer Edges that advertise a Connector for it, best candidate first
    Remote(Vec<RemoteRoute>),
    Unavailable,
}

impl RouteDecision {
    /// The tenant owning the hostname, known before any stream is opened.
    pub fn tenant_id(&self) -> Option<&str> {
        match self {
            RouteDecision::Local(handle) => Some(&handle.tenant_id),
            RouteDecision::Remote(routes) => routes.first().map(|route| route.tenant_id.as_str()),
            RouteDecision::Unavailable => None,
        }
    }

    pub fn is_available(&self) -> bool {
        !matches!(self, RouteDecision::Unavailable)
    }
}

#[derive(Debug)]
pub struct OpenError {
    pub message: String,
    /// Distinguishes a gateway timeout from other failures
    pub timed_out: bool,
}

impl OpenError {
    fn failed(message: impl Into<String>) -> Self {
        OpenError {
            message: message.into(),
            timed_out: false,
        }
    }
}

#[derive(Clone)]
pub struct Router {
    registry: ConnectorRegistry,
    mesh: Option<Arc<MeshService>>,
    local_open_timeout: Duration,
}

impl Router {
    pub fn new(registry: ConnectorRegistry) -> Self {
        Router {
            registry,
            mesh: None,
            local_open_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_mesh(mut self, mesh: Arc<MeshService>) -> Self {
        self.mesh = Some(mesh);
        self
    }

    pub fn with_open_timeout(mut self, timeout: Duration) -> Self {
        self.local_open_timeout = timeout;
        self
    }

    pub fn mesh(&self) -> Option<&Arc<MeshService>> {
        self.mesh.as_ref()
    }

    /// Route a normalized hostname. A local Connector always wins; remote routes
    /// are used only while their advertisement is valid.
    pub fn route(&self, hostname: &str, protocol: Protocol) -> RouteDecision {
        if let Some(handle) = self.registry.get_by_hostname(hostname) {
            if handle.supports(hostname, protocol) {
                return RouteDecision::Local(handle);
            }
        }
        let Some(mesh) = &self.mesh else {
            return RouteDecision::Unavailable;
        };
        let candidates: Vec<RemoteRoute> = mesh
            .routes()
            .candidates(hostname, protocol, Instant::now())
            .into_iter()
            .filter(|route| !mesh.pool().cooling_down(&route.edge_id))
            .collect();
        if candidates.is_empty() {
            RouteDecision::Unavailable
        } else {
            RouteDecision::Remote(candidates)
        }
    }

    /// Open a stream for a decision. Only failures from before the peer accepted
    /// the request are retried on another candidate, so nothing is delivered twice.
    pub async fn open(
        &self,
        decision: &RouteDecision,
        hostname: &str,
        protocol: Protocol,
        client_addr: SocketAddr,
    ) -> Result<TunnelStream, OpenError> {
        match decision {
            RouteDecision::Local(handle) => {
                let open = tunnel::open_local_stream(handle, hostname, protocol, client_addr);
                match tokio::time::timeout(self.local_open_timeout, open).await {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(e)) => Err(OpenError::failed(format!("{e:#}"))),
                    Err(_) => Err(OpenError {
                        message: "opening the tunnel stream timed out".to_string(),
                        timed_out: true,
                    }),
                }
            }
            RouteDecision::Remote(routes) => {
                let Some(mesh) = &self.mesh else {
                    return Err(OpenError::failed("mesh forwarding is not enabled"));
                };
                let mut last = OpenError::failed("no mesh candidate accepted the request");
                for route in routes {
                    match mesh
                        .open_remote_stream(route, hostname, protocol, client_addr)
                        .await
                    {
                        Ok(stream) => return Ok(stream),
                        Err(e) => {
                            tracing::debug!(
                                peer = %route.edge_id,
                                hostname,
                                error = %e.message,
                                retryable = e.retryable,
                                "mesh forwarding attempt failed"
                            );
                            let retryable = e.retryable;
                            last = OpenError {
                                message: e.message,
                                timed_out: e.timed_out,
                            };
                            if !retryable {
                                break;
                            }
                        }
                    }
                }
                Err(last)
            }
            RouteDecision::Unavailable => Err(OpenError::failed("no route for hostname")),
        }
    }
}
