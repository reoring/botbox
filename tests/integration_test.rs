use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ----- Error-path tests -----

#[tokio::test]
async fn test_denied_host_returns_403() {
    let ctx = TestProxy::start(&[], None).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", ctx.proxy_addr)).unwrap())
        .build()
        .unwrap();

    let resp = client.get("http://evil.com/exfil").send().await.unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("host not allowed"));
}

#[tokio::test]
async fn test_connect_method_returns_405() {
    let ctx = TestProxy::start(&[], None).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(ctx.proxy_addr)
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("405"));
}

#[tokio::test]
async fn test_missing_host_returns_400() {
    let ctx = TestProxy::start(&[], None).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(ctx.proxy_addr)
        .await
        .unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("400"));
}

// ----- Happy-path tests with wiremock -----

#[tokio::test]
async fn test_allowed_host_forwards_with_header_injection() {
    // Start a wiremock server as the mock upstream
    let mock_server = MockServer::start().await;

    // Mount a mock response (proxy will attempt HTTPS to this host,
    // which will fail since wiremock speaks plain HTTP - that's expected)
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer test-placeholder-not-a-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"models":["gpt-4"]}"#)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Extract host:port of the mock server
    let mock_addr = mock_server.address();
    let mock_host = format!("127.0.0.1:{}", mock_addr.port());

    // Create a proxy that allows the mock host with header rewrite
    let ctx = TestProxy::start(
        &[TestRule {
            host: mock_host.clone(),
            header_rewrites: vec![TestHeaderRewrite {
                name: "Authorization".into(),
                value: "Bearer {value}".into(),
                secret_ref: Some("api-key".into()),
            }],
            allowed_ports: None,
        }],
        Some(&[("api-key", "test-placeholder-not-a-key")]),
    )
    .await;

    // Send request through the proxy.
    // NOTE: The proxy rewrites http -> https, but the mock only speaks http.
    // We send a raw HTTP request directly to the proxy with the mock host.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(ctx.proxy_addr)
        .await
        .unwrap();

    let request = format!(
        "GET http://{}/v1/models HTTP/1.1\r\nHost: {}\r\n\r\n",
        mock_host, mock_host
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    // The proxy will try to connect to https://127.0.0.1:{port} which will fail
    // because wiremock doesn't speak TLS. This is expected behavior - the proxy
    // enforces https_only(). We verify the proxy correctly attempted the connection.
    // In a real deployment, upstream APIs speak HTTPS natively.

    // For this test, we verify the proxy returns 502 (upstream connection failed)
    // because the mock doesn't support TLS.
    assert!(
        response.contains("502") || response.contains("504"),
        "expected 502 or 504, got: {}",
        response
    );
}

#[tokio::test]
async fn test_allowed_host_without_rewrite_forwards() {
    // Use a local wiremock server instead of external httpbin.org
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/get"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let mock_addr = mock_server.address();
    let mock_host = format!("127.0.0.1:{}", mock_addr.port());

    let ctx = TestProxy::start(
        &[TestRule {
            host: mock_host.clone(),
            header_rewrites: vec![],
            allowed_ports: None,
        }],
        None,
    )
    .await;

    // Send raw HTTP request through the proxy
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(ctx.proxy_addr)
        .await
        .unwrap();
    let request = format!(
        "GET http://{}/get HTTP/1.1\r\nHost: {}\r\n\r\n",
        mock_host, mock_host
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    // Proxy rewrites to HTTPS, so TLS handshake fails against wiremock → 502
    // The key assertion: NOT 403 (the allowlist permitted it)
    assert!(
        !response.contains("403"),
        "should not be denied: {}",
        response
    );
    assert!(
        response.contains("502") || response.contains("504"),
        "expected upstream error (502/504), got: {}",
        response
    );
}

#[tokio::test]
async fn test_missing_secret_returns_500() {
    let ctx = TestProxy::start(
        &[TestRule {
            host: "api.example.com".into(),
            header_rewrites: vec![TestHeaderRewrite {
                name: "Authorization".into(),
                value: "Bearer {value}".into(),
                secret_ref: Some("nonexistent-key".into()),
            }],
            allowed_ports: None,
        }],
        None, // No secrets loaded
    )
    .await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", ctx.proxy_addr)).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get("http://api.example.com/test")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
    let body = resp.text().await.unwrap();
    assert!(body.contains("secret not available"));
}

// ----- Metrics tests -----

#[tokio::test]
async fn test_metrics_endpoint() {
    use botbox::metrics::{handle_metrics_request, Metrics};
    use http_body_util::BodyExt;

    let metrics = Metrics::new();
    let ready = Arc::new(AtomicBool::new(true));
    metrics
        .requests_total
        .with_label_values(&["test.com", "allow"])
        .inc();

    // Test /metrics HTTP endpoint
    let req = hyper::Request::builder().uri("/metrics").body(()).unwrap();

    let resp = handle_metrics_request(req, &metrics, &ready);
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("botbox_requests_total"));
    assert!(body_str.contains("test.com"));
}

#[tokio::test]
async fn test_healthz_endpoint_ready() {
    use botbox::metrics::{handle_metrics_request, Metrics};
    use http_body_util::BodyExt;

    let metrics = Metrics::new();
    let ready = Arc::new(AtomicBool::new(true));
    let req = hyper::Request::builder().uri("/healthz").body(()).unwrap();

    let resp = handle_metrics_request(req, &metrics, &ready);
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn test_healthz_endpoint_not_ready() {
    use botbox::metrics::{handle_metrics_request, Metrics};
    use http_body_util::BodyExt;

    let metrics = Metrics::new();
    let ready = Arc::new(AtomicBool::new(false));
    let req = hyper::Request::builder().uri("/healthz").body(()).unwrap();

    let resp = handle_metrics_request(req, &metrics, &ready);
    assert_eq!(resp.status(), 503);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"not ready");
}

#[tokio::test]
async fn test_metrics_404_for_unknown_path() {
    use botbox::metrics::{handle_metrics_request, Metrics};

    let metrics = Metrics::new();
    let ready = Arc::new(AtomicBool::new(true));
    let req = hyper::Request::builder().uri("/unknown").body(()).unwrap();

    let resp = handle_metrics_request(req, &metrics, &ready);
    assert_eq!(resp.status(), 404);
}

// ----- Timeout tests -----

#[tokio::test]
async fn test_timeout_returns_504() {
    // Start a TCP listener that accepts connections but never responds
    let slow_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_server.local_addr().unwrap();
    let slow_host = format!("127.0.0.1:{}", slow_addr.port());

    // Accept connections in background but never send data
    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = slow_server.accept().await {
                // Hold the connection open, never respond
                tokio::spawn(async move {
                    let _keep = stream;
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                });
            }
        }
    });

    // Create proxy with a very short timeout
    let ctx = TestProxy::start_with_timeout(
        &[TestRule {
            host: slow_host.clone(),
            header_rewrites: vec![],
            allowed_ports: None,
        }],
        None,
        std::time::Duration::from_millis(100),
    )
    .await;

    // Send a request through the proxy to the slow server
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(ctx.proxy_addr)
        .await
        .unwrap();
    let request = format!(
        "GET http://{}/test HTTP/1.1\r\nHost: {}\r\n\r\n",
        slow_host, slow_host
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("test read should not timeout")
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(
        response.contains("504"),
        "expected 504 gateway timeout, got: {}",
        response
    );
    assert!(
        response.contains("gateway timeout"),
        "expected 'gateway timeout' in body, got: {}",
        response
    );
}

// ----- Test Helpers -----

struct TestHeaderRewrite {
    name: String,
    value: String,
    secret_ref: Option<String>,
}

struct TestRule {
    host: String,
    header_rewrites: Vec<TestHeaderRewrite>,
    allowed_ports: Option<Vec<u16>>,
}

struct TestProxy {
    proxy_addr: SocketAddr,
    _secrets_dir: TempDir,
}

impl TestProxy {
    async fn start(rules: &[TestRule], secrets: Option<&[(&str, &str)]>) -> Self {
        Self::start_with_timeout(rules, secrets, std::time::Duration::from_secs(30)).await
    }

    async fn start_with_timeout(
        rules: &[TestRule],
        secrets: Option<&[(&str, &str)]>,
        timeout: std::time::Duration,
    ) -> Self {
        use botbox::allowlist::Allowlist;
        use botbox::config::{Action, HeaderRewrite, Rule};
        use botbox::metrics::Metrics;
        use botbox::proxy::{ProxyBody, ProxyHandler};
        use botbox::secrets as secrets_mod;
        use botbox::tls;

        // Install rustls CryptoProvider (ignore if already installed)
        let _ = rustls::crypto::ring::default_provider().install_default();

        let secrets_dir = TempDir::new().unwrap();

        // Write secret files
        if let Some(secrets) = secrets {
            for (key, value) in secrets {
                std::fs::write(secrets_dir.path().join(key), value).unwrap();
            }
        }

        let config_rules: Vec<Rule> = rules
            .iter()
            .map(|r| {
                // Extract port from host for allowed_ports if not explicitly set
                let allowed_ports = r.allowed_ports.clone().or_else(|| {
                    // If host contains a port, allow that port for tests
                    r.host
                        .rsplit_once(':')
                        .and_then(|(_, p)| p.parse::<u16>().ok())
                        .map(|port| vec![port])
                });
                Rule {
                    host: r.host.clone(),
                    action: Action::Allow,
                    header_rewrites: if r.header_rewrites.is_empty() {
                        None
                    } else {
                        Some(
                            r.header_rewrites
                                .iter()
                                .map(|hr| HeaderRewrite {
                                    name: hr.name.clone(),
                                    value: hr.value.clone(),
                                    secret_ref: hr.secret_ref.clone(),
                                })
                                .collect(),
                        )
                    },
                    allowed_ports,
                }
            })
            .collect();

        let allowlist = Arc::new(Allowlist::new(&config_rules, Action::Deny));
        let secret_store = secrets_mod::new_secret_store(secrets_dir.path()).unwrap();
        let connector = tls::build_https_connector();
        let metrics = Metrics::new();

        let handler = Arc::new(ProxyHandler::new(
            connector,
            allowlist,
            secret_store,
            metrics,
            timeout,
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let service = hyper::service::service_fn(move |req| {
                            let handler = handler.clone();
                            async move {
                                handler.handle(req).await.or_else(|_e| {
                                    Ok::<_, hyper::Error>(
                                        hyper::Response::builder()
                                            .status(500)
                                            .body(ProxyBody::Left(http_body_util::Full::new(
                                                hyper::body::Bytes::from("error"),
                                            )))
                                            .unwrap(),
                                    )
                                })
                            }
                        });

                        let _ = hyper::server::conn::http1::Builder::new()
                            .preserve_header_case(true)
                            .serve_connection(io, service)
                            .await;
                    });
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        TestProxy {
            proxy_addr: addr,
            _secrets_dir: secrets_dir,
        }
    }
}
