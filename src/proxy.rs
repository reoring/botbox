use crate::allowlist::{Allowlist, Decision};
use crate::config::{extract_port, normalize_policy_host, strip_port};
use crate::error::ProxyError;
use crate::header_rewrite::apply_rewrites;
use crate::metrics::Metrics;
use crate::secrets::SecretStore;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::tls::HttpsConnector;

pub type ProxyBody = Either<Full<Bytes>, Incoming>;

pub struct ProxyHandler {
    client: Client<HttpsConnector, Incoming>,
    allowlist: Arc<Allowlist>,
    secrets: SecretStore,
    metrics: Metrics,
    timeout: Duration,
}

impl ProxyHandler {
    pub fn new(
        connector: HttpsConnector,
        allowlist: Arc<Allowlist>,
        secrets: SecretStore,
        metrics: Metrics,
        timeout: Duration,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);
        ProxyHandler {
            client,
            allowlist,
            secrets,
            metrics,
            timeout,
        }
    }

    pub async fn handle(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, anyhow::Error> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();

        // Reject CONNECT method to prevent TLS bypass
        if method == hyper::Method::CONNECT {
            warn!(
                request_id = %request_id,
                method = %method,
                "CONNECT method rejected"
            );
            self.metrics
                .requests_total
                .with_label_values(&["unknown", "denied_connect"])
                .inc();
            return Ok(error_response(405, "CONNECT method not allowed"));
        }

        // Extract host from request
        let host = match extract_host(&req) {
            Some(h) if !h.is_empty() => h,
            _ => {
                warn!(
                    request_id = %request_id,
                    "missing host in request"
                );
                self.metrics
                    .requests_total
                    .with_label_values(&["unknown", "denied_no_host"])
                    .inc();
                return Ok(error_response(400, "missing host"));
            }
        };

        let host_only = normalize_policy_host(&host);

        // Check allowlist
        let rule = match self.allowlist.check(&host) {
            Decision::Allow(rule) => {
                info!(
                    request_id = %request_id,
                    host = %host_only,
                    method = %method,
                    path = %path,
                    decision = "allow",
                    "request allowed"
                );
                self.metrics
                    .requests_total
                    .with_label_values(&[host_only.as_str(), "allow"])
                    .inc();
                rule
            }
            Decision::DefaultAllow(rule) => {
                info!(
                    request_id = %request_id,
                    host = %host_only,
                    method = %method,
                    path = %path,
                    decision = "default_allow",
                    "request allowed by default policy"
                );
                self.metrics
                    .requests_total
                    .with_label_values(&["_default_allow", "allow"])
                    .inc();
                rule
            }
            Decision::Deny => {
                warn!(
                    request_id = %request_id,
                    host = %host_only,
                    method = %method,
                    path = %path,
                    decision = "deny",
                    "request denied"
                );
                self.metrics
                    .requests_total
                    .with_label_values(&["_denied", "deny"])
                    .inc();
                return Ok(error_response(403, "host not allowed"));
            }
        };

        // Start duration timer
        let timer = self
            .metrics
            .request_duration_seconds
            .with_label_values(&[host_only.as_str()])
            .start_timer();

        // Build upstream request: rewrite URI to HTTPS
        let upstream_uri = build_upstream_uri(&uri, &host)?;
        let (mut parts, body) = req.into_parts();
        parts.uri = upstream_uri
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid upstream URI: {}", e))?;

        let mut upstream_req = Request::from_parts(parts, body);

        // Strip hop-by-hop headers
        strip_hop_by_hop_headers(&mut upstream_req);

        // Set Host header for upstream (include port when non-443)
        let host_hdr = host_header_value(&host);
        upstream_req.headers_mut().insert(
            hyper::header::HOST,
            HeaderValue::from_str(&host_hdr).unwrap_or_else(|_| HeaderValue::from_static("")),
        );

        // Apply header rewrites (inject secrets)
        if let Some(rewrites) = &rule.header_rewrites {
            let secrets_guard = self.secrets.load();
            match apply_rewrites(&mut upstream_req, rewrites, &secrets_guard) {
                Ok(rewritten) => {
                    for header in &rewritten {
                        info!(
                            request_id = %request_id,
                            host = %host_only,
                            header_rewritten = %header,
                            "header rewritten"
                        );
                    }
                    if !rewritten.is_empty() {
                        self.metrics
                            .header_rewrites_total
                            .with_label_values(&[host_only.as_str()])
                            .inc();
                    }
                }
                Err(ProxyError::SecretNotFound(key)) => {
                    error!(
                        request_id = %request_id,
                        host = %host_only,
                        secret_ref = %key,
                        "secret not found"
                    );
                    timer.observe_duration();
                    return Ok(error_response(500, "internal error: secret not available"));
                }
                Err(e) => {
                    error!(
                        request_id = %request_id,
                        host = %host_only,
                        error = %e,
                        "header rewrite failed"
                    );
                    timer.observe_duration();
                    return Ok(error_response(500, "internal error"));
                }
            }
        }

        // Forward to upstream with timeout
        match tokio::time::timeout(self.timeout, self.client.request(upstream_req)).await {
            Ok(Ok(resp)) => {
                let status = resp.status();
                if status.is_server_error() || status.is_client_error() {
                    self.metrics
                        .upstream_errors_total
                        .with_label_values(&[host_only.as_str(), status.as_str()])
                        .inc();
                }

                info!(
                    request_id = %request_id,
                    host = %host_only,
                    upstream_status = %status,
                    "upstream response"
                );

                timer.observe_duration();

                // Stream the response body directly without buffering.
                // SEC-007: This stream has no idle timeout. An upstream that stalls
                // the response body can hold this connection and its semaphore permit
                // indefinitely (up to the drain timeout on shutdown). A body-level
                // idle timeout would require wrapping Incoming in a timeout-aware
                // body adapter, which is deferred for a future release.
                let (parts, body) = resp.into_parts();
                Ok(Response::from_parts(parts, Either::Right(body)))
            }
            Ok(Err(e)) => {
                error!(
                    request_id = %request_id,
                    host = %host_only,
                    error = %e,
                    "upstream request failed"
                );
                self.metrics
                    .upstream_errors_total
                    .with_label_values(&[host_only.as_str(), "connection_error"])
                    .inc();
                timer.observe_duration();
                Ok(error_response(502, "upstream connection failed"))
            }
            Err(_elapsed) => {
                error!(
                    request_id = %request_id,
                    host = %host_only,
                    "upstream request timed out"
                );
                self.metrics
                    .upstream_errors_total
                    .with_label_values(&[host_only.as_str(), "timeout"])
                    .inc();
                timer.observe_duration();
                Ok(error_response(504, "gateway timeout"))
            }
        }
    }
}

/// Strip hop-by-hop headers that should not be forwarded to upstream.
fn strip_hop_by_hop_headers<B>(req: &mut Request<B>) {
    let connection_tokens: Vec<HeaderName> = req
        .headers()
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                None
            } else {
                HeaderName::from_bytes(token.as_bytes()).ok()
            }
        })
        .collect();

    let headers = req.headers_mut();
    headers.remove("connection");
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
    headers.remove("te");
    headers.remove("trailer");
    headers.remove("transfer-encoding");
    headers.remove("upgrade");

    for token in connection_tokens {
        headers.remove(token);
    }
}

/// Extract host (with port if present) from the request URI or Host header.
fn extract_host<B>(req: &Request<B>) -> Option<String> {
    // For proxy requests, the URI contains the full URL.
    // Use authority to preserve host:port.
    if let Some(authority) = req.uri().authority() {
        return Some(authority.as_str().to_string());
    }

    // Fallback to Host header (already includes port if provided)
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Check if a string looks like a bare IPv6 address (multiple colons, no brackets).
/// A single colon (e.g. "host:port") is NOT IPv6; requires 2+ colons.
fn is_ipv6_literal(host: &str) -> bool {
    host.matches(':').count() > 1 && !host.contains('[')
}

/// Format a host (potentially IPv6) as a valid URI authority.
/// IPv6 addresses are wrapped in brackets as required by RFC 3986.
fn format_authority(host: &str, port: Option<u16>) -> String {
    match (is_ipv6_literal(host), port) {
        (true, Some(p)) if p != 443 => format!("[{}]:{}", host, p),
        (true, _) => format!("[{}]", host),
        (false, Some(p)) if p != 443 => format!("{}:{}", host, p),
        (false, _) => host.to_string(),
    }
}

/// Return the host value to use for the Host header.
/// Includes port only when it is present and not 443.
/// IPv6 addresses are wrapped in brackets per RFC 3986.
fn host_header_value(host: &str) -> String {
    let host_only = strip_port(host).to_lowercase();
    let port = extract_port(host);
    format_authority(&host_only, port)
}

/// Build the upstream HTTPS URI from the original request.
/// `host` should include port if non-default (e.g. "example.com:8443").
fn build_upstream_uri(original: &hyper::Uri, host: &str) -> Result<String, anyhow::Error> {
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Use host with port for correct upstream routing
    let authority = host_header_value(host);
    Ok(format!("https://{}{}", authority, path_and_query))
}

fn error_response(status: u16, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Either::Left(Full::new(Bytes::from(body.to_string()))))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- strip_port tests ---

    #[test]
    fn test_strip_port_ipv4_with_port() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn test_strip_port_ipv4_without_port() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn test_strip_port_ipv6_with_brackets() {
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn test_strip_port_bare_ipv6() {
        assert_eq!(strip_port("::1"), "::1");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn test_strip_port_non_numeric_after_colon() {
        // "host:notaport" should NOT strip since "notaport" isn't a u16
        assert_eq!(strip_port("host:notaport"), "host:notaport");
    }

    // --- extract_host tests ---

    #[test]
    fn test_extract_host_from_uri() {
        let req = Request::builder()
            .uri("http://api.openai.com/v1/models")
            .body(())
            .unwrap();
        assert_eq!(extract_host(&req), Some("api.openai.com".to_string()));
    }

    #[test]
    fn test_extract_host_from_host_header() {
        let req = Request::builder()
            .uri("/v1/models")
            .header("host", "api.openai.com:443")
            .body(())
            .unwrap();
        // Now preserves port from Host header
        assert_eq!(extract_host(&req), Some("api.openai.com:443".to_string()));
    }

    #[test]
    fn test_extract_host_missing() {
        let req = Request::builder().uri("/").body(()).unwrap();
        assert_eq!(extract_host(&req), None);
    }

    // --- strip_hop_by_hop_headers tests ---

    #[test]
    fn test_strip_hop_by_hop_headers() {
        let mut req = Request::builder()
            .uri("http://example.com")
            .header("connection", "keep-alive")
            .header("keep-alive", "timeout=5")
            .header("proxy-authorization", "Basic abc")
            .header("transfer-encoding", "chunked")
            .header("x-custom", "should-remain")
            .header("authorization", "Bearer token")
            .body(())
            .unwrap();

        strip_hop_by_hop_headers(&mut req);

        assert!(req.headers().get("connection").is_none());
        assert!(req.headers().get("keep-alive").is_none());
        assert!(req.headers().get("proxy-authorization").is_none());
        assert!(req.headers().get("transfer-encoding").is_none());
        // Non-hop-by-hop headers should remain
        assert_eq!(req.headers().get("x-custom").unwrap(), "should-remain");
        assert_eq!(req.headers().get("authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn test_strip_hop_by_hop_headers_connection_tokens() {
        let mut req = Request::builder()
            .uri("http://example.com")
            .header("connection", "x-forward-me-not, keep-alive")
            .header("x-forward-me-not", "drop-this")
            .header("proxy-connection", "keep-alive")
            .header("x-should-remain", "still-here")
            .body(())
            .unwrap();

        strip_hop_by_hop_headers(&mut req);

        assert!(req.headers().get("connection").is_none());
        assert!(req.headers().get("proxy-connection").is_none());
        assert!(req.headers().get("x-forward-me-not").is_none());
        assert_eq!(req.headers().get("x-should-remain").unwrap(), "still-here");
    }

    // --- build_upstream_uri tests ---

    #[test]
    fn test_build_upstream_uri_basic() {
        let uri: hyper::Uri = "http://api.openai.com/v1/models".parse().unwrap();
        let result = build_upstream_uri(&uri, "api.openai.com").unwrap();
        assert_eq!(result, "https://api.openai.com/v1/models");
    }

    #[test]
    fn test_build_upstream_uri_with_query() {
        let uri: hyper::Uri = "http://example.com/path?key=value&foo=bar".parse().unwrap();
        let result = build_upstream_uri(&uri, "example.com").unwrap();
        assert_eq!(result, "https://example.com/path?key=value&foo=bar");
    }

    #[test]
    fn test_build_upstream_uri_root() {
        let uri: hyper::Uri = "http://example.com".parse().unwrap();
        let result = build_upstream_uri(&uri, "example.com").unwrap();
        assert_eq!(result, "https://example.com/");
    }

    // --- extract_port tests ---

    #[test]
    fn test_extract_port_present() {
        assert_eq!(extract_port("example.com:8443"), Some(8443));
        assert_eq!(extract_port("example.com:443"), Some(443));
    }

    #[test]
    fn test_extract_port_absent() {
        assert_eq!(extract_port("example.com"), None);
        assert_eq!(extract_port("::1"), None);
    }

    #[test]
    fn test_extract_port_bracketed_ipv6() {
        assert_eq!(extract_port("[::1]:8080"), Some(8080));
    }

    // --- host_header_value tests ---

    #[test]
    fn test_host_header_value_port_443_omitted() {
        assert_eq!(host_header_value("example.com:443"), "example.com");
    }

    #[test]
    fn test_host_header_value_port_8443_included() {
        assert_eq!(host_header_value("example.com:8443"), "example.com:8443");
    }

    #[test]
    fn test_host_header_value_no_port() {
        assert_eq!(host_header_value("example.com"), "example.com");
    }

    // --- build_upstream_uri with custom port ---

    #[test]
    fn test_build_upstream_uri_custom_port() {
        let uri: hyper::Uri = "http://example.com:8443/api/v1".parse().unwrap();
        let result = build_upstream_uri(&uri, "example.com:8443").unwrap();
        assert_eq!(result, "https://example.com:8443/api/v1");
    }

    #[test]
    fn test_build_upstream_uri_port_443_stripped() {
        let uri: hyper::Uri = "http://example.com:443/api/v1".parse().unwrap();
        let result = build_upstream_uri(&uri, "example.com:443").unwrap();
        assert_eq!(result, "https://example.com/api/v1");
    }

    // --- extract_host with port preservation ---

    #[test]
    fn test_extract_host_preserves_port_from_uri() {
        let req = Request::builder()
            .uri("http://example.com:8443/path")
            .body(())
            .unwrap();
        assert_eq!(extract_host(&req), Some("example.com:8443".to_string()));
    }

    #[test]
    fn test_extract_host_preserves_port_from_header() {
        let req = Request::builder()
            .uri("/path")
            .header("host", "example.com:8443")
            .body(())
            .unwrap();
        assert_eq!(extract_host(&req), Some("example.com:8443".to_string()));
    }

    // --- IPv6 authority formatting tests ---

    #[test]
    fn test_host_header_value_ipv6_no_port() {
        assert_eq!(host_header_value("::1"), "[::1]");
        assert_eq!(host_header_value("2001:db8::1"), "[2001:db8::1]");
    }

    #[test]
    fn test_host_header_value_ipv6_port_443() {
        assert_eq!(host_header_value("[::1]:443"), "[::1]");
    }

    #[test]
    fn test_host_header_value_ipv6_non_443_port() {
        assert_eq!(host_header_value("[::1]:8443"), "[::1]:8443");
        assert_eq!(host_header_value("[2001:db8::1]:8080"), "[2001:db8::1]:8080");
    }

    #[test]
    fn test_build_upstream_uri_ipv6() {
        let uri: hyper::Uri = "http://[::1]/test".parse().unwrap();
        let result = build_upstream_uri(&uri, "[::1]").unwrap();
        assert_eq!(result, "https://[::1]/test");
    }

    #[test]
    fn test_build_upstream_uri_ipv6_with_port() {
        let uri: hyper::Uri = "http://[::1]:8443/test".parse().unwrap();
        let result = build_upstream_uri(&uri, "[::1]:8443").unwrap();
        assert_eq!(result, "https://[::1]:8443/test");
    }
}
