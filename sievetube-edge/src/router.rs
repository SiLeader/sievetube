use std::sync::Arc;

use sievetube_common::config::Protocol;
use sievetube_common::error::SieveTubeError;

use crate::connector_registry::{ConnectorHandle, ConnectorRegistry};

/// Look up the ConnectorHandle responsible for the given hostname and protocol.
pub fn route(
    registry: &ConnectorRegistry,
    hostname: &str,
    _protocol: Protocol,
) -> Result<Arc<ConnectorHandle>, SieveTubeError> {
    registry
        .get_by_hostname(hostname)
        .ok_or_else(|| SieveTubeError::ConnectorNotFound(hostname.to_string()))
}
