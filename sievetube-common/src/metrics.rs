use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec,
    Registry,
};
use std::sync::OnceLock;

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub struct Metrics {
    pub bytes_transferred_total: CounterVec,
    pub active_quic_connections: Gauge,
    pub tunnel_latency_seconds: HistogramVec,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        let bytes_transferred_total = register_counter_vec!(
            prometheus::opts!(
                "sievetube_bytes_transferred_total",
                "Total bytes transferred through tunnels"
            ),
            &["direction", "protocol"]
        )
        .expect("failed to register bytes_transferred_total");
        registry
            .register(Box::new(bytes_transferred_total.clone()))
            .ok();

        let active_quic_connections = register_gauge!(prometheus::opts!(
            "sievetube_active_quic_connections",
            "Number of active QUIC connections from Connectors"
        ))
        .expect("failed to register active_quic_connections");
        registry
            .register(Box::new(active_quic_connections.clone()))
            .ok();

        let tunnel_latency_seconds = register_histogram_vec!(
            prometheus::histogram_opts!(
                "sievetube_tunnel_latency_seconds",
                "Tunnel round-trip latency in seconds",
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
            ),
            &["protocol"]
        )
        .expect("failed to register tunnel_latency_seconds");
        registry
            .register(Box::new(tunnel_latency_seconds.clone()))
            .ok();

        Metrics {
            bytes_transferred_total,
            active_quic_connections,
            tunnel_latency_seconds,
        }
    }
}

/// Initialize the global metrics registry. Call once at startup.
pub fn init() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let registry = prometheus::default_registry();
        Metrics::new(registry)
    })
}

/// Get the global metrics handle, initializing it on first use.
pub fn global() -> &'static Metrics {
    init()
}
