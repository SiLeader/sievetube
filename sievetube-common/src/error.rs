use thiserror::Error;

#[derive(Debug, Error)]
pub enum SieveTubeError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("no matching ingress rule for hostname={hostname:?} protocol={protocol:?}")]
    NoIngressMatch { hostname: String, protocol: String },

    #[error("connector not connected for hostname={0}")]
    ConnectorNotFound(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// QUIC application error codes
pub mod app_error {
    pub const AUTH_FAILED: u32 = 1;
    pub const NO_ROUTE: u32 = 2;
    pub const INTERNAL: u32 = 3;
    pub const GOING_AWAY: u32 = 4;
    /// A newer connection of the same tenant took over on this Edge. A Connector
    /// that is still running when it receives this shares its token with another.
    pub const REPLACED: u32 = 5;
}
