use crate::allowlist::{Allowlist, Decision};
use crate::config::{extract_port, normalize_policy_host, MitmConfig};
use crate::metrics::Metrics;
use crate::proxy::{ProxyBody, ProxyHandler};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use lru::LruCache;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SanType, SerialNumber,
};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// CA material loaded from PEM files.
pub struct MitmCa {
    pub ca_cert_pem: String,
    pub ca_cert_der: Vec<u8>,
    pub ca_key_pair: KeyPair,
}

impl MitmCa {
    pub fn load(cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| anyhow::anyhow!("failed to read CA cert from '{}': {}", cert_path, e))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| anyhow::anyhow!("failed to read CA key from '{}': {}", key_path, e))?;

        let ca_key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| anyhow::anyhow!("failed to parse CA key PEM: {}", e))?;

        let ca_cert_der = pem_to_der(&cert_pem)?;

        Ok(MitmCa {
            ca_cert_pem: cert_pem,
            ca_cert_der,
            ca_key_pair,
        })
    }
}

fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let cert = CertificateDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to decode CA cert PEM: {}", e))?;
    Ok(cert.to_vec())
}

struct CachedCert {
    certified_key: Arc<CertifiedKey>,
    expires_at: Instant,
}

pub struct CertCache {
    inner: Mutex<LruCache<String, CachedCert>>,
    ttl: Duration,
}

impl CertCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        CertCache {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity must be > 0"),
            )),
            ttl,
        }
    }

    fn get(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get(hostname) {
            if Instant::now() < entry.expires_at {
                return Some(entry.certified_key.clone());
            }
            // Expired - remove it
            cache.pop(hostname);
        }
        None
    }

    fn insert(&self, hostname: String, key: Arc<CertifiedKey>) {
        let mut cache = self.inner.lock().unwrap();
        cache.put(
            hostname,
            CachedCert {
                certified_key: key,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

/// Validate SNI hostname: trim, lowercase, reject empty/oversized/wildcard/invalid chars.
pub fn validate_sni(sni: &str) -> Result<String, &'static str> {
    let host = sni.trim().to_lowercase();
    if host.is_empty() {
        return Err("empty SNI hostname");
    }
    if host.len() > 253 {
        return Err("SNI hostname exceeds 253 characters");
    }
    if host.contains('*') {
        return Err("wildcard SNI not allowed");
    }
    for ch in host.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '.' {
            return Err("invalid character in SNI hostname");
        }
    }
    Ok(host)
}

/// MITM certificate resolver implementing rustls `ResolvesServerCert`.
///
/// SNI is always required — without it, no hostname is available and no
/// certificate can be issued.  Invalid SNI always causes handshake failure
/// for the same reason.
pub struct MitmCertResolver {
    ca: Arc<MitmCa>,
    cache: CertCache,
    cert_ttl: Duration,
    deny_handshake_on_disallowed_sni: bool,
    allowlist: Arc<Allowlist>,
    metrics: Metrics,
}

impl fmt::Debug for MitmCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmCertResolver")
            .field(
                "deny_handshake_on_disallowed_sni",
                &self.deny_handshake_on_disallowed_sni,
            )
            .finish()
    }
}

impl MitmCertResolver {
    pub fn new(
        ca: Arc<MitmCa>,
        config: &MitmConfig,
        allowlist: Arc<Allowlist>,
        metrics: Metrics,
    ) -> Self {
        MitmCertResolver {
            ca,
            cache: CertCache::new(
                config.cert_cache_size() as usize,
                Duration::from_secs(config.cert_cache_ttl_seconds()),
            ),
            cert_ttl: Duration::from_secs(config.cert_ttl_seconds()),
            deny_handshake_on_disallowed_sni: config.deny_handshake_on_disallowed_sni(),
            allowlist,
            metrics,
        }
    }

    fn issue_leaf(&self, hostname: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        // Generate ECDSA P-256 leaf key
        let leaf_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| anyhow::anyhow!("failed to generate leaf key: {}", e))?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.subject_alt_names =
            vec![SanType::DnsName(hostname.try_into().map_err(|e| {
                anyhow::anyhow!("invalid DNS name '{}': {}", hostname, e)
            })?)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = IsCa::NoCa;
        params.serial_number = Some(SerialNumber::from_slice(
            &uuid::Uuid::new_v4().as_bytes()[..],
        ));

        // Set validity: not_before = now - 5 minutes, not_after = now + cert_ttl
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::seconds(self.cert_ttl.as_secs() as i64);

        // Create issuer from CA cert PEM + key pair
        let issuer = Issuer::from_ca_cert_pem(&self.ca.ca_cert_pem, &self.ca.ca_key_pair)
            .map_err(|e| anyhow::anyhow!("failed to create CA issuer: {}", e))?;

        // Sign leaf cert
        let leaf_cert = params
            .signed_by(&leaf_key_pair, &issuer)
            .map_err(|e| anyhow::anyhow!("failed to sign leaf certificate: {}", e))?;

        let leaf_der = rustls::pki_types::CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = rustls::pki_types::CertificateDer::from(self.ca.ca_cert_der.clone());

        // Convert leaf key pair to rustls signing key
        let leaf_key_der =
            rustls::pki_types::PrivateKeyDer::try_from(leaf_key_pair.serialize_der())
                .map_err(|e| anyhow::anyhow!("failed to convert leaf key to DER: {}", e))?;
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&leaf_key_der)
            .map_err(|e| anyhow::anyhow!("failed to create signing key: {}", e))?;

        let certified_key = CertifiedKey::new(vec![leaf_der, ca_der], signing_key);
        Ok(Arc::new(certified_key))
    }
}

impl ResolvesServerCert for MitmCertResolver {
    /// Resolve a certificate for the given ClientHello.
    ///
    /// Metrics policy: this function tracks **cert issuance** and **cache** counters
    /// only.  The **handshake result** counter (`tls_handshakes_total`) is owned
    /// exclusively by the accept loop in `run_mitm_listener()` so that each TCP
    /// connection is counted exactly once.
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // SNI is always required — without a hostname we cannot issue a cert.
        let sni = client_hello.server_name()?;

        // Validate SNI
        let hostname = match validate_sni(sni) {
            Ok(h) => h,
            Err(_reason) => {
                self.metrics
                    .mitm_cert_issued_total
                    .with_label_values(&["skipped_invalid"])
                    .inc();
                return None;
            }
        };

        // Check allowlist if deny_handshake_on_disallowed_sni is true
        if self.deny_handshake_on_disallowed_sni {
            let decision = self.allowlist.check(&hostname);
            if matches!(decision, Decision::Deny) {
                self.metrics
                    .mitm_cert_issued_total
                    .with_label_values(&["skipped_disallowed"])
                    .inc();
                return None;
            }
        }

        // Check cache
        if let Some(key) = self.cache.get(&hostname) {
            self.metrics
                .mitm_cert_cache_total
                .with_label_values(&["hit"])
                .inc();
            return Some(key);
        }
        self.metrics
            .mitm_cert_cache_total
            .with_label_values(&["miss"])
            .inc();

        // Issue leaf cert (outside any lock)
        match self.issue_leaf(&hostname) {
            Ok(key) => {
                self.cache.insert(hostname, key.clone());
                self.metrics
                    .mitm_cert_issued_total
                    .with_label_values(&["issued_allow"])
                    .inc();
                Some(key)
            }
            Err(e) => {
                error!(error = %e, "failed to issue MITM leaf certificate");
                None
            }
        }
    }
}

/// Build a rustls ServerConfig for the MITM TLS listener.
pub fn build_mitm_server_config(resolver: Arc<MitmCertResolver>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Validate an HTTP request arriving over the MITM TLS listener.
///
/// MITM connections are transparently redirected from port 443. The app container
/// thinks it is talking directly to the upstream server, so it MUST send
/// origin-form requests (`GET /path HTTP/1.1`).  An absolute-form request
/// (`GET http://host:PORT/path HTTP/1.1`) would carry its own authority/scheme
/// that `ProxyHandler::handle()` would trust over the Host header, allowing an
/// attacker to bypass the port-443 restriction and the SNI/Host match check.
/// We therefore reject any request that contains a URI authority or scheme.
#[allow(clippy::result_large_err)]
pub fn validate_mitm_request<B>(
    req: &Request<B>,
    sni_host: &str,
    enforce_sni_host_match: bool,
    metrics: &Metrics,
) -> Result<(), Response<ProxyBody>> {
    // Reject absolute-form requests (scheme/authority in URI).
    // MITM traffic must use origin-form only; absolute-form could bypass
    // the Host/SNI checks because ProxyHandler prioritizes URI authority.
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return Err(error_response(
            400,
            "absolute-form request not allowed on MITM listener",
        ));
    }

    // Extract host from Host header
    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if host_header.is_empty() {
        return Err(error_response(400, "missing Host header"));
    }

    // Check port: must be 443 or absent
    let port = extract_port(host_header);
    if let Some(p) = port {
        if p != 443 {
            return Err(error_response(
                403,
                "MITM listener only accepts port 443 traffic",
            ));
        }
    }

    // SNI/Host match check
    if enforce_sni_host_match {
        let host_only = normalize_policy_host(host_header);
        let sni_normalized = sni_host.trim().to_lowercase();
        if host_only != sni_normalized {
            metrics.mitm_host_mismatch_total.inc();
            return Err(error_response(400, "SNI/Host header mismatch"));
        }
    }

    Ok(())
}

fn error_response(status: u16, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(http_body_util::Either::Left(Full::new(Bytes::from(
            body.to_string(),
        ))))
        .unwrap()
}

/// Run the MITM TLS listener.
pub async fn run_mitm_listener(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    handler: Arc<ProxyHandler>,
    mitm_config: MitmConfig,
    metrics: Metrics,
    semaphore: Arc<tokio::sync::Semaphore>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let handshake_timeout = Duration::from_millis(mitm_config.handshake_timeout_ms());
    let enforce_sni_host_match = mitm_config.enforce_sni_host_match();

    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(peer = %addr, "MITM connection limit reached, dropping connection");
                                drop(stream);
                                continue;
                            }
                        };
                        let acceptor = acceptor.clone();
                        let handler = handler.clone();
                        let metrics = metrics.clone();

                        connections.spawn(async move {
                            let _permit = permit;
                            // TLS handshake with timeout
                            let tls_stream = match tokio::time::timeout(
                                handshake_timeout,
                                acceptor.accept(stream),
                            ).await {
                                Ok(Ok(tls)) => tls,
                                Ok(Err(e)) => {
                                    if !e.to_string().contains("connection closed") {
                                        warn!(peer = %addr, error = %e, "MITM TLS handshake failed");
                                    }
                                    metrics
                                        .tls_handshakes_total
                                        .with_label_values(&["io_error"])
                                        .inc();
                                    return;
                                }
                                Err(_) => {
                                    warn!(peer = %addr, "MITM TLS handshake timed out");
                                    metrics
                                        .tls_handshakes_total
                                        .with_label_values(&["timeout"])
                                        .inc();
                                    return;
                                }
                            };

                            metrics
                                .tls_handshakes_total
                                .with_label_values(&["ok"])
                                .inc();

                            // Extract SNI from the TLS connection
                            let sni_host = tls_stream
                                .get_ref()
                                .1
                                .server_name()
                                .unwrap_or("")
                                .to_string();

                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let handler = handler.clone();
                                let sni = sni_host.clone();
                                let metrics = metrics.clone();
                                async move {
                                    // Validate MITM-specific constraints
                                    if let Err(resp) = validate_mitm_request(
                                        &req,
                                        &sni,
                                        enforce_sni_host_match,
                                        &metrics,
                                    ) {
                                        return Ok::<_, hyper::Error>(resp);
                                    }

                                    // Delegate to the existing proxy handler
                                    handler.handle(req).await.or_else(|e| {
                                        error!(error = %e, "MITM request handling error");
                                        Ok::<_, hyper::Error>(
                                            Response::builder()
                                                .status(500)
                                                .body(ProxyBody::Left(Full::new(Bytes::from(
                                                    "internal server error",
                                                ))))
                                                .unwrap(),
                                        )
                                    })
                                }
                            });

                            if let Err(e) = http1::Builder::new()
                                .preserve_header_case(true)
                                .max_buf_size(64 * 1024)
                                .serve_connection(io, service)
                                .await
                            {
                                if !e.to_string().contains("connection closed") {
                                    error!(
                                        peer = %addr,
                                        error = %e,
                                        "MITM connection error"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "MITM accept error");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                break;
            }
        }
    }

    // Drain in-flight MITM connections
    info!(
        "MITM listener shutting down, draining {} connections",
        connections.len()
    );
    let drain_result = tokio::time::timeout(Duration::from_secs(30), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drain_result.is_err() {
        warn!(
            "MITM drain timeout, aborting {} remaining connections",
            connections.len()
        );
        connections.abort_all();
    }
    info!("MITM listener stopped");
}
