use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Arc<Registry>,
    pub requests_total: IntCounterVec,
    pub header_rewrites_total: IntCounterVec,
    pub upstream_errors_total: IntCounterVec,
    pub request_duration_seconds: HistogramVec,
    // HTTPS interception metrics
    pub tls_handshakes_total: IntCounterVec,
    pub https_interception_cert_issued_total: IntCounterVec,
    pub https_interception_cert_cache_total: IntCounterVec,
    pub https_interception_host_mismatch_total: IntCounter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("botbox_requests_total", "Total requests"),
            &["host", "decision"],
        )
        .unwrap();

        let header_rewrites_total = IntCounterVec::new(
            Opts::new(
                "botbox_header_rewrites_total",
                "Total header rewrites performed",
            ),
            &["host"],
        )
        .unwrap();

        let upstream_errors_total = IntCounterVec::new(
            Opts::new("botbox_upstream_errors_total", "Total upstream errors"),
            &["host", "status_code"],
        )
        .unwrap();

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "botbox_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["host"],
        )
        .unwrap();

        let tls_handshakes_total = IntCounterVec::new(
            Opts::new(
                "botbox_tls_handshakes_total",
                "Total HTTPS interception TLS handshakes",
            ),
            &["result"],
        )
        .unwrap();

        let https_interception_cert_issued_total = IntCounterVec::new(
            Opts::new(
                "botbox_https_interception_cert_issued_total",
                "Total HTTPS interception certificates issued",
            ),
            &["decision"],
        )
        .unwrap();

        let https_interception_cert_cache_total = IntCounterVec::new(
            Opts::new(
                "botbox_https_interception_cert_cache_total",
                "Total HTTPS interception cert cache operations",
            ),
            &["result"],
        )
        .unwrap();

        let https_interception_host_mismatch_total = IntCounter::new(
            "botbox_https_interception_host_mismatch_total",
            "Total HTTPS interception SNI/Host mismatches",
        )
        .unwrap();

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry
            .register(Box::new(header_rewrites_total.clone()))
            .unwrap();
        registry
            .register(Box::new(upstream_errors_total.clone()))
            .unwrap();
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(tls_handshakes_total.clone()))
            .unwrap();
        registry
            .register(Box::new(https_interception_cert_issued_total.clone()))
            .unwrap();
        registry
            .register(Box::new(https_interception_cert_cache_total.clone()))
            .unwrap();
        registry
            .register(Box::new(https_interception_host_mismatch_total.clone()))
            .unwrap();

        Metrics {
            registry: Arc::new(registry),
            requests_total,
            header_rewrites_total,
            upstream_errors_total,
            request_duration_seconds,
            tls_handshakes_total,
            https_interception_cert_issued_total,
            https_interception_cert_cache_total,
            https_interception_host_mismatch_total,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle metrics and health requests on the metrics port.
pub fn handle_metrics_request<B>(
    req: Request<B>,
    metrics: &Metrics,
    ready: &Arc<AtomicBool>,
) -> Response<Full<Bytes>> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = metrics.registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .header("content-type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap()
        }
        "/healthz" => {
            if ready.load(Ordering::Relaxed) {
                Response::builder()
                    .status(200)
                    .body(Full::new(Bytes::from("ok")))
                    .unwrap()
            } else {
                Response::builder()
                    .status(503)
                    .body(Full::new(Bytes::from("not ready")))
                    .unwrap()
            }
        }
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    }
}
