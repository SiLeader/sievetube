use serde::{Deserialize, Serialize};

/// A single ingress routing rule.
/// Rules are evaluated top-to-bottom; the first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    /// Optional hostname to match (None = catch-all)
    pub hostname: Option<String>,
    /// Optional protocol filter; None matches any protocol
    pub protocol: Option<Protocol>,
    /// Forwarding target: "127.0.0.1:8080" or "http_status:404"
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http => write!(f, "http"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(Protocol::Http),
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            other => Err(format!("unknown protocol: {other}")),
        }
    }
}

/// Parsed target endpoint
#[derive(Debug, Clone)]
pub enum Target {
    /// Forward to a local address
    Address(std::net::SocketAddr),
    /// Return an HTTP status code
    HttpStatus(u16),
}

impl Target {
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(code_str) = s.strip_prefix("http_status:") {
            let code: u16 = code_str
                .parse()
                .map_err(|_| format!("invalid http status code: {code_str}"))?;
            Ok(Target::HttpStatus(code))
        } else {
            let addr: std::net::SocketAddr = s
                .parse()
                .map_err(|_| format!("invalid socket address: {s}"))?;
            Ok(Target::Address(addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_address() {
        let t = Target::parse("127.0.0.1:8080").unwrap();
        assert!(matches!(t, Target::Address(_)));
    }

    #[test]
    fn parse_target_http_status() {
        let t = Target::parse("http_status:404").unwrap();
        assert!(matches!(t, Target::HttpStatus(404)));
    }

    #[test]
    fn parse_protocol() {
        assert_eq!("http".parse::<Protocol>().unwrap(), Protocol::Http);
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("udp".parse::<Protocol>().unwrap(), Protocol::Udp);
    }
}
