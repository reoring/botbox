use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;

pub type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

/// Build an HTTPS connector that enforces TLS for all outbound connections.
/// Uses system CA roots (webpki-roots) for certificate validation.
pub fn build_https_connector() -> HttpsConnector {
    HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build()
}
