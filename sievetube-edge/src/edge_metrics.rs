//! Edge-specific Prometheus metrics. Labels are limited to low-cardinality values;
//! hostnames, client IPs and request ids belong in structured logs.

use std::sync::OnceLock;

use prometheus::{
    register_gauge, register_gauge_vec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge, register_int_gauge_vec, Gauge, GaugeVec, HistogramVec, IntCounterVec,
    IntGauge, IntGaugeVec,
};

use crate::tls::CertResolver;

pub struct EdgeMetrics {
    /// Loaded certificates by source and state (valid|expired)
    pub tls_certificates: IntGaugeVec,
    /// Smallest remaining validity among certificates of a source
    pub tls_min_remaining_seconds: GaugeVec,
    /// Policy decisions by protocol, decision, reason and mode
    pub policy_decisions_total: IntCounterVec,
    pub policy_evaluation_seconds: HistogramVec,
    /// Token buckets currently tracked per table
    pub policy_buckets: IntGaugeVec,
    /// Policy plugin calls that failed, by plugin name and failure kind
    pub policy_plugin_failures_total: IntCounterVec,
    /// UDP datagrams dropped by the Edge, by reason
    pub udp_dropped_total: IntCounterVec,
    /// ACME orders by result (success|failure)
    pub acme_orders_total: IntCounterVec,
    /// Earliest time at which an ACME order is next attempted
    pub acme_next_attempt_timestamp_seconds: Gauge,
    /// Configured DNS records by reconcile status
    pub dns_records: IntGaugeVec,
    /// DNS provider write attempts by provider type and result
    pub dns_changes_total: IntCounterVec,
    /// Last completed DNS reconciliation
    pub dns_last_reconcile_timestamp_seconds: Gauge,
    /// Streams forwarded between Edges, by protocol and stage
    pub mesh_forwarded_total: IntCounterVec,
    /// Forward requests rejected by this Edge, by reason
    pub mesh_rejected_total: IntCounterVec,
    /// Remote routes currently known
    pub mesh_routes: IntGauge,
    /// Connected mesh peers
    pub mesh_peers: IntGauge,
}

static METRICS: OnceLock<EdgeMetrics> = OnceLock::new();

pub fn get() -> &'static EdgeMetrics {
    METRICS.get_or_init(|| EdgeMetrics {
        tls_certificates: register_int_gauge_vec!(
            "sievetube_tls_certificates",
            "Loaded public TLS certificates",
            &["source", "state"]
        )
        .expect("register sievetube_tls_certificates"),
        tls_min_remaining_seconds: register_gauge_vec!(
            "sievetube_tls_certificate_min_remaining_seconds",
            "Smallest remaining validity of loaded certificates",
            &["source"]
        )
        .expect("register sievetube_tls_certificate_min_remaining_seconds"),
        policy_decisions_total: register_int_counter_vec!(
            "sievetube_policy_decisions_total",
            "Traffic policy decisions",
            &["protocol", "decision", "reason", "mode"]
        )
        .expect("register sievetube_policy_decisions_total"),
        policy_evaluation_seconds: register_histogram_vec!(
            "sievetube_policy_evaluation_seconds",
            "Time spent evaluating traffic policy",
            &["protocol"],
            vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]
        )
        .expect("register sievetube_policy_evaluation_seconds"),
        policy_buckets: register_int_gauge_vec!(
            "sievetube_policy_buckets",
            "Token buckets tracked by the traffic policy",
            &["table"]
        )
        .expect("register sievetube_policy_buckets"),
        policy_plugin_failures_total: register_int_counter_vec!(
            "sievetube_policy_plugin_failures_total",
            "Policy plugin calls that failed",
            &["plugin", "failure"]
        )
        .expect("register sievetube_policy_plugin_failures_total"),
        udp_dropped_total: register_int_counter_vec!(
            "sievetube_udp_dropped_total",
            "UDP datagrams dropped by the edge",
            &["reason"]
        )
        .expect("register sievetube_udp_dropped_total"),
        acme_orders_total: register_int_counter_vec!(
            "sievetube_acme_orders_total",
            "ACME certificate orders",
            &["result"]
        )
        .expect("register sievetube_acme_orders_total"),
        acme_next_attempt_timestamp_seconds: register_gauge!(
            "sievetube_acme_next_attempt_timestamp_seconds",
            "Earliest unix time at which an ACME order is next attempted"
        )
        .expect("register sievetube_acme_next_attempt_timestamp_seconds"),
        dns_records: register_int_gauge_vec!(
            "sievetube_dns_records",
            "Configured DNS records by reconcile status",
            &["status"]
        )
        .expect("register sievetube_dns_records"),
        dns_changes_total: register_int_counter_vec!(
            "sievetube_dns_changes_total",
            "DNS provider write attempts",
            &["provider_type", "result"]
        )
        .expect("register sievetube_dns_changes_total"),
        dns_last_reconcile_timestamp_seconds: register_gauge!(
            "sievetube_dns_last_reconcile_timestamp_seconds",
            "Unix time of the last completed DNS reconciliation"
        )
        .expect("register sievetube_dns_last_reconcile_timestamp_seconds"),
        mesh_forwarded_total: register_int_counter_vec!(
            "sievetube_mesh_forwarded_total",
            "Streams forwarded between edges",
            &["protocol", "stage"]
        )
        .expect("register sievetube_mesh_forwarded_total"),
        mesh_rejected_total: register_int_counter_vec!(
            "sievetube_mesh_rejected_total",
            "Forward requests rejected by this edge",
            &["reason"]
        )
        .expect("register sievetube_mesh_rejected_total"),
        mesh_routes: register_int_gauge!(
            "sievetube_mesh_routes",
            "Remote routes currently known to this edge"
        )
        .expect("register sievetube_mesh_routes"),
        mesh_peers: register_int_gauge!("sievetube_mesh_peers", "Connected mesh peers")
            .expect("register sievetube_mesh_peers"),
    })
}

pub fn update_certificates(resolver: &CertResolver, now: i64) {
    let m = get();
    for source in ["byoc", "acme"] {
        let entries: Vec<_> = resolver
            .entries()
            .into_iter()
            .filter(|e| e.source.as_str() == source)
            .collect();
        let expired = entries.iter().filter(|e| e.is_expired(now)).count();
        m.tls_certificates
            .with_label_values(&[source, "valid"])
            .set((entries.len() - expired) as i64);
        m.tls_certificates
            .with_label_values(&[source, "expired"])
            .set(expired as i64);
        // Without a reset the gauge would keep reporting the last certificate of
        // a source after it was removed, so alerts would fire (or stay quiet)
        // against a certificate that no longer exists.
        let min = entries
            .iter()
            .map(|e| e.remaining_secs(now))
            .min()
            .unwrap_or(0);
        m.tls_min_remaining_seconds
            .with_label_values(&[source])
            .set(min as f64);
    }
}
