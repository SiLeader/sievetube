//! Edge-to-Edge forwarding mesh.
//!
//! An ingress Edge that has no local Connector for a hostname forwards the
//! traffic over exactly one hop to an Edge that has one. Peers authenticate each
//! other with certificates from a private mesh CA, routes are advertised through
//! the control plane with a TTL, and the receiving Edge re-checks that the
//! hostname belongs to the claimed tenant before delivering locally.

pub mod certs;
pub mod forward;
pub mod routes;
pub mod setup;
pub mod transport;
