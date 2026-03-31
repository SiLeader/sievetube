use sievetube_common::config::{IngressRule, Protocol, Target};
use sievetube_common::error::SieveTubeError;

pub struct IngressMatcher {
    rules: Vec<IngressRule>,
}

impl IngressMatcher {
    pub fn new(rules: Vec<IngressRule>) -> Self {
        IngressMatcher { rules }
    }

    /// Evaluate rules top-to-bottom; return the Target for the first match.
    pub fn match_request(
        &self,
        hostname: &str,
        protocol: Protocol,
    ) -> Result<Target, SieveTubeError> {
        for rule in &self.rules {
            let hostname_matches = rule
                .hostname
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(hostname))
                .unwrap_or(true); // None = catch-all

            let protocol_matches = rule
                .protocol
                .map(|p| p == protocol)
                .unwrap_or(true); // None = any protocol

            if hostname_matches && protocol_matches {
                return Target::parse(&rule.target)
                    .map_err(|e| SieveTubeError::Config(e));
            }
        }

        Err(SieveTubeError::NoIngressMatch {
            hostname: hostname.to_string(),
            protocol: protocol.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sievetube_common::config::IngressRule;

    fn make_rule(hostname: Option<&str>, protocol: Option<Protocol>, target: &str) -> IngressRule {
        IngressRule {
            hostname: hostname.map(str::to_string),
            protocol,
            target: target.to_string(),
        }
    }

    #[test]
    fn exact_hostname_match() {
        let matcher = IngressMatcher::new(vec![
            make_rule(Some("web.example.com"), Some(Protocol::Http), "127.0.0.1:8080"),
            make_rule(None, None, "http_status:404"),
        ]);
        let t = matcher.match_request("web.example.com", Protocol::Http).unwrap();
        assert!(matches!(t, Target::Address(_)));
    }

    #[test]
    fn catch_all_fallback() {
        let matcher = IngressMatcher::new(vec![
            make_rule(Some("web.example.com"), Some(Protocol::Http), "127.0.0.1:8080"),
            make_rule(None, None, "http_status:404"),
        ]);
        let t = matcher.match_request("other.example.com", Protocol::Http).unwrap();
        assert!(matches!(t, Target::HttpStatus(404)));
    }

    #[test]
    fn no_match_returns_error() {
        let matcher = IngressMatcher::new(vec![
            make_rule(Some("web.example.com"), Some(Protocol::Http), "127.0.0.1:8080"),
        ]);
        assert!(matcher.match_request("other.example.com", Protocol::Tcp).is_err());
    }

    #[test]
    fn protocol_filter() {
        let matcher = IngressMatcher::new(vec![
            make_rule(Some("ssh.example.com"), Some(Protocol::Tcp), "127.0.0.1:22"),
            make_rule(None, None, "http_status:404"),
        ]);
        // TCP matches
        let t = matcher.match_request("ssh.example.com", Protocol::Tcp).unwrap();
        assert!(matches!(t, Target::Address(_)));
        // HTTP falls through to catch-all
        let t2 = matcher.match_request("ssh.example.com", Protocol::Http).unwrap();
        assert!(matches!(t2, Target::HttpStatus(404)));
    }

    #[test]
    fn case_insensitive_hostname() {
        let matcher = IngressMatcher::new(vec![
            make_rule(Some("Web.Example.Com"), None, "127.0.0.1:8080"),
        ]);
        let t = matcher.match_request("web.example.com", Protocol::Http).unwrap();
        assert!(matches!(t, Target::Address(_)));
    }
}
