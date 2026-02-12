use anyhow::Result;
use botbox::allowlist::Allowlist;
use botbox::config::Config;
use botbox::https_interception;
use botbox::metrics::{handle_metrics_request, Metrics};
use botbox::proxy::{ProxyBody, ProxyHandler};
use botbox::{logging, secrets, tls};
use clap::Parser;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::SignalKind;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "botbox", about = "Sidecar egress proxy with secret injection")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the rustls CryptoProvider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default CryptoProvider");

    logging::init_logging();

    let cli = Cli::parse();

    info!(config_path = %cli.config.display(), "loading configuration");
    let config = Config::load(&cli.config)?;

    // Initialize secrets
    let secrets_dir = PathBuf::from(config.secrets_dir());
    let secret_store = secrets::new_secret_store(&secrets_dir)?;

    // Check if required secrets are available
    let required_refs = config.required_secret_refs();
    let missing = secrets::check_required_secrets(&secret_store, &required_refs);
    let ready = Arc::new(AtomicBool::new(missing.is_empty()));
    if missing.is_empty() {
        info!("all required secrets loaded, system ready");
    } else {
        warn!(
            missing = ?missing,
            "required secrets not yet available, /healthz will return 503"
        );
    }

    // Start secret file watcher for hot-reload
    let _watcher = if secrets_dir.exists() {
        match secrets::start_secret_watcher(secrets_dir.clone(), secret_store.clone()) {
            Ok(w) => {
                info!(dir = %secrets_dir.display(), "secret file watcher started");
                Some(w)
            }
            Err(e) => {
                error!(error = %e, "failed to start secret watcher, hot-reload disabled");
                None
            }
        }
    } else {
        None
    };

    // Periodically check for required secrets and update readiness
    if !required_refs.is_empty() {
        let ready_clone2 = ready.clone();
        let store_clone2 = secret_store.clone();
        let required_refs_clone = required_refs.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let missing = secrets::check_required_secrets(&store_clone2, &required_refs_clone);
                let was_ready = ready_clone2.load(std::sync::atomic::Ordering::Relaxed);
                let is_ready = missing.is_empty();
                ready_clone2.store(is_ready, std::sync::atomic::Ordering::Relaxed);
                if is_ready && !was_ready {
                    info!("all required secrets now available, system ready");
                } else if !is_ready && was_ready {
                    warn!(missing = ?missing, "required secrets became unavailable");
                }
            }
        });
    }

    // Build allowlist
    let allowlist = Arc::new(Allowlist::new(
        &config.egress_policy.rules,
        config.default_action(),
    ));

    // Build TLS connector
    let connector = tls::build_https_connector();

    // Initialize metrics
    let metrics = Metrics::new();

    // Create proxy handler
    let handler = Arc::new(ProxyHandler::new(
        connector,
        allowlist.clone(),
        secret_store,
        metrics.clone(),
        std::time::Duration::from_secs(30),
    ));

    // Shared shutdown channel for metrics + HTTPS interception listeners
    let (shutdown_tx, _) = tokio::sync::watch::channel(());

    // Start metrics server
    let metrics_addr: SocketAddr = format!("127.0.0.1:{}", config.metrics_port())
        .parse()
        .unwrap();
    let metrics_clone = metrics.clone();
    let ready_clone = ready.clone();
    let metrics_shutdown_rx = shutdown_tx.subscribe();
    let metrics_handle = tokio::spawn(async move {
        run_metrics_server(
            metrics_addr,
            metrics_clone,
            ready_clone,
            metrics_shutdown_rx,
        )
        .await;
    });

    // Shared connection semaphore (HTTP proxy + HTTPS interception share the same pool)
    let semaphore = Arc::new(Semaphore::new(config.max_connections() as usize));

    // HTTPS interception TLS listener (if enabled)
    let https_interception_handle = if let Some(ref cfg) = config.https_interception {
        if cfg.enabled {
            info!("HTTPS interception mode enabled, loading CA material");
            let ca =
                https_interception::HttpsInterceptionCa::load(&cfg.ca_cert_path, &cfg.ca_key_path)?;
            let ca = Arc::new(ca);

            let resolver = Arc::new(https_interception::HttpsInterceptionCertResolver::new(
                ca,
                cfg,
                allowlist,
                metrics.clone(),
            ));
            let tls_config = https_interception::build_https_interception_server_config(resolver);

            let addr: SocketAddr = format!("{}:{}", cfg.listen_addr(), cfg.listen_port())
                .parse()
                .unwrap();
            info!(addr = %addr, "starting HTTPS interception TLS listener");
            let listener = TcpListener::bind(addr).await?;

            let handler = handler.clone();
            let metrics = metrics.clone();
            let semaphore = semaphore.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let cfg = cfg.clone();

            Some(tokio::spawn(async move {
                https_interception::run_https_interception_listener(
                    listener,
                    tls_config,
                    handler,
                    cfg,
                    metrics,
                    semaphore,
                    shutdown_rx,
                )
                .await;
            }))
        } else {
            None
        }
    } else {
        None
    };

    // Start proxy server
    let proxy_addr: SocketAddr = format!("{}:{}", config.listen_addr(), config.listen_port())
        .parse()
        .unwrap();

    info!(addr = %proxy_addr, "starting proxy server");
    let listener = TcpListener::bind(proxy_addr).await?;

    // Graceful shutdown on SIGINT or SIGTERM
    let shutdown = async {
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received");
            }
        }
    };
    tokio::pin!(shutdown);

    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(peer = %addr, "connection limit reached, dropping connection");
                                drop(stream);
                                continue;
                            }
                        };
                        let handler = handler.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let handler = handler.clone();
                                async move {
                                    handler.handle(req).await.or_else(|e| {
                                        error!(error = %e, "request handling error");
                                        Ok::<_, hyper::Error>(
                                            hyper::Response::builder()
                                                .status(500)
                                                .body(ProxyBody::Left(Full::new(Bytes::from("internal server error"))))
                                                .unwrap(),
                                        )
                                    })
                                }
                            });

                            // SEC-007: Connection-level timeout. The proxy timeout (30s) covers
                            // the upstream request phase. Body streaming has no separate idle timeout.
                            // For defense-in-depth, hyper's max_buf_size limits memory per connection.
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
                                        "connection error"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    info!(
        "shutdown signal received, draining {} connections",
        connections.len()
    );

    // Give in-flight connections a grace period
    let drain_timeout = tokio::time::sleep(std::time::Duration::from_secs(30));
    tokio::pin!(drain_timeout);

    loop {
        tokio::select! {
            _ = &mut drain_timeout => {
                info!("drain timeout reached, aborting {} remaining connections", connections.len());
                connections.abort_all();
                break;
            }
            result = connections.join_next() => {
                match result {
                    Some(_) => continue,
                    None => {
                        info!("all connections drained");
                        break;
                    }
                }
            }
        }
    }

    // Signal metrics + HTTPS interception servers to shut down
    drop(shutdown_tx);
    info!("waiting for metrics server to stop");
    let _ = metrics_handle.await;

    if let Some(handle) = https_interception_handle {
        info!("waiting for HTTPS interception listener to stop");
        let _ = handle.await;
    }

    info!("proxy server stopped");
    Ok(())
}

async fn run_metrics_server(
    addr: SocketAddr,
    metrics: Metrics,
    ready: Arc<AtomicBool>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!(addr = %addr, "metrics server listening");
            l
        }
        Err(e) => {
            error!(error = %e, addr = %addr, "failed to bind metrics server");
            return;
        }
    };

    let mut metrics_connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let metrics = metrics.clone();
                        let ready = ready.clone();
                        metrics_connections.spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let resp = handle_metrics_request(req, &metrics, &ready);
                                async move { Ok::<_, hyper::Error>(resp) }
                            });

                            if let Err(e) = http1::Builder::new()
                                .max_buf_size(64 * 1024)
                                .serve_connection(io, service)
                                .await
                            {
                                if !e.to_string().contains("connection closed") {
                                    error!(error = %e, "metrics connection error");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "metrics accept error");
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                break;
            }
        }
    }

    // Drain in-flight metrics connections
    info!(
        "metrics server shutting down, draining {} connections",
        metrics_connections.len()
    );
    let drain_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while metrics_connections.join_next().await.is_some() {}
    })
    .await;
    if drain_result.is_err() {
        warn!(
            "metrics drain timeout, aborting {} remaining connections",
            metrics_connections.len()
        );
        metrics_connections.abort_all();
    }
    info!("metrics server stopped");
}
