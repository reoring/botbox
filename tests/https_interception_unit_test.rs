use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

// Long-lived fallback test CA material for environments without openssl.
// Valid until year 2126; generated as EC P-256 with PKCS#8 private key.
const FALLBACK_CA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUI4Jb5Mjw1HiB/Ay/jXZt64p6LtAwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXYm90Ym94LWZhbGxiYWNrLXRlc3QtY2EwIBcNMjYwMjExMDIy
NzQ0WhgPMjEyNjAxMTgwMjI3NDRaMCIxIDAeBgNVBAMMF2JvdGJveC1mYWxsYmFj
ay10ZXN0LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGl/LQkZ/OiA3llsw
Ce/PKGPQhXO5+rFfPv2uCsdL7Yo52TjjnUkgFstgPOKrn4ra3HZaJ0HfDRNnSc+C
TvfHe6NTMFEwHQYDVR0OBBYEFMvSr2iFXMCpAOcwCI2rhRRrE/elMB8GA1UdIwQY
MBaAFMvSr2iFXMCpAOcwCI2rhRRrE/elMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgHO0fAIMmnYo4xDhp2w2/a7X9/mUU/G0+PdL8afVhSsQCIFBi
M9tLhzGxzKc9S4Tw4l670tl8W730MI/73TFnwupX
-----END CERTIFICATE-----
"#;

const FALLBACK_CA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyVt3DfTNlKcB2BSO
CM2bCNh+hdVhQuYsueCZV7MIq7uhRANCAAQaX8tCRn86IDeWWzAJ788oY9CFc7n6
sV8+/a4Kx0vtijnZOOOdSSAWy2A84qufitrcdlonQd8NE2dJz4JO98d7
-----END PRIVATE KEY-----
"#;

struct HttpsInterceptionSpec {
    rules_yaml: String,
    write_ca_files: bool,
    initial_secrets: Vec<(String, String)>,
    max_connections: u32,
    deny_handshake_on_disallowed_sni: bool,
    cert_ttl_seconds: u64,
    cert_cache_size: u64,
    cert_cache_ttl_seconds: u64,
}

impl Default for HttpsInterceptionSpec {
    fn default() -> Self {
        Self {
            rules_yaml: rules_allow_hosts(&["localhost"]),
            write_ca_files: true,
            initial_secrets: Vec::new(),
            max_connections: 256,
            deny_handshake_on_disallowed_sni: false,
            cert_ttl_seconds: 86_400,
            cert_cache_size: 1024,
            cert_cache_ttl_seconds: 3600,
        }
    }
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn generate_test_ca_material(ca_cert_path: &Path, ca_key_path: &Path) -> Result<Vec<u8>> {
    if openssl_available() {
        let key_path = ca_key_path.display().to_string();
        let cert_path = ca_cert_path.display().to_string();

        let (key_status, _, key_stderr) = run_openssl(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            &key_path,
        ])?;
        if !key_status.success() {
            return Err(anyhow!("openssl genpkey failed: {}", key_stderr));
        }

        let (cert_status, _, cert_stderr) = run_openssl(&[
            "req",
            "-x509",
            "-new",
            "-key",
            &key_path,
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=botbox-test-ca",
            "-out",
            &cert_path,
        ])?;
        if !cert_status.success() {
            return Err(anyhow!("openssl req -x509 failed: {}", cert_stderr));
        }

        return std::fs::read(ca_cert_path).with_context(|| {
            format!(
                "failed to read generated CA cert PEM from {}",
                ca_cert_path.display()
            )
        });
    }

    std::fs::write(ca_cert_path, FALLBACK_CA_CERT_PEM)
        .context("failed to write fallback CA certificate")?;
    std::fs::write(ca_key_path, FALLBACK_CA_KEY_PEM)
        .context("failed to write fallback CA private key")?;
    Ok(FALLBACK_CA_CERT_PEM.as_bytes().to_vec())
}

struct BotboxProcess {
    child: Child,
    _tmp: TempDir,
    metrics_addr: SocketAddr,
    https_interception_addr: SocketAddr,
    ca_cert_pem: Vec<u8>,
    secrets_dir: std::path::PathBuf,
    stdout_log_path: PathBuf,
    stderr_log_path: PathBuf,
}

impl Drop for BotboxProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl BotboxProcess {
    fn start(spec: HttpsInterceptionSpec) -> Self {
        let tmp = TempDir::new().expect("failed to create tempdir");
        let config_path = tmp.path().join("config.yaml");
        let secrets_dir = tmp.path().join("secrets");
        let ca_cert_path = tmp.path().join("ca.crt");
        let ca_key_path = tmp.path().join("ca.key");
        let stdout_log_path = tmp.path().join("botbox.stdout.log");
        let stderr_log_path = tmp.path().join("botbox.stderr.log");

        std::fs::create_dir_all(&secrets_dir).expect("failed to create secrets dir");
        for (k, v) in &spec.initial_secrets {
            std::fs::write(secrets_dir.join(k), v).expect("failed to write initial secret");
        }

        let mut ca_cert_pem = Vec::new();
        if spec.write_ca_files {
            ca_cert_pem = generate_test_ca_material(&ca_cert_path, &ca_key_path)
                .expect("failed to generate test CA material");
        }

        let listen_port = pick_free_port();
        let metrics_port = pick_free_port();
        let https_interception_port = pick_free_port();

        let config = format!(
            r#"listen_addr: "127.0.0.1"
listen_port: {listen_port}
metrics_port: {metrics_port}
secrets_dir: "{secrets_dir}"
max_connections: {max_connections}

egress_policy:
  default_action: deny
  rules:
{rules_yaml}

https_interception:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: {https_interception_port}
  ca_cert_path: "{ca_cert_path}"
  ca_key_path: "{ca_key_path}"
  enforce_sni_host_match: true
  deny_handshake_on_disallowed_sni: {deny_handshake_on_disallowed_sni}
  cert_ttl_seconds: {cert_ttl_seconds}
  cert_cache_size: {cert_cache_size}
  cert_cache_ttl_seconds: {cert_cache_ttl_seconds}
  handshake_timeout_ms: 5000
"#,
            listen_port = listen_port,
            metrics_port = metrics_port,
            secrets_dir = secrets_dir.display(),
            max_connections = spec.max_connections,
            rules_yaml = spec.rules_yaml,
            https_interception_port = https_interception_port,
            ca_cert_path = ca_cert_path.display(),
            ca_key_path = ca_key_path.display(),
            deny_handshake_on_disallowed_sni = spec.deny_handshake_on_disallowed_sni,
            cert_ttl_seconds = spec.cert_ttl_seconds,
            cert_cache_size = spec.cert_cache_size,
            cert_cache_ttl_seconds = spec.cert_cache_ttl_seconds,
        );

        std::fs::write(&config_path, config).expect("failed to write config");

        let bin_path = env!("CARGO_BIN_EXE_botbox");

        let stdout_file = std::fs::File::create(&stdout_log_path)
            .expect("failed to create botbox stdout log file");
        let stderr_file = std::fs::File::create(&stderr_log_path)
            .expect("failed to create botbox stderr log file");

        let child = Command::new(bin_path)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .expect("failed to spawn botbox process");

        Self {
            child,
            _tmp: tmp,
            metrics_addr: SocketAddr::from(([127, 0, 0, 1], metrics_port)),
            https_interception_addr: SocketAddr::from(([127, 0, 0, 1], https_interception_port)),
            ca_cert_pem,
            secrets_dir,
            stdout_log_path,
            stderr_log_path,
        }
    }

    fn write_secret(&self, name: &str, value: &str) {
        std::fs::write(self.secrets_dir.join(name), value).expect("failed to write secret");
    }

    fn wait_for_healthz_endpoint(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.try_wait() {
                panic!(
                    "botbox exited before /healthz became available: {}\n{}",
                    status,
                    self.log_tail(80)
                );
            }

            if healthz_status(self.metrics_addr).is_some() {
                return;
            }

            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "/healthz endpoint did not become reachable within {:?}\n{}",
            timeout,
            self.log_tail(80)
        );
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.try_wait() {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child
            .try_wait()
            .expect("failed to poll botbox process status")
    }

    fn log_tail(&self, max_lines: usize) -> String {
        fn tail_of(path: &Path, max_lines: usize) -> String {
            let content = std::fs::read_to_string(path).unwrap_or_else(|_| "<unreadable>".into());
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(max_lines);
            lines[start..].join("\n")
        }

        format!(
            "--- botbox stdout (tail) ---\n{}\n--- botbox stderr (tail) ---\n{}\n",
            tail_of(&self.stdout_log_path, max_lines),
            tail_of(&self.stderr_log_path, max_lines)
        )
    }
}

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind ephemeral port")
        .local_addr()
        .expect("failed to read local addr")
        .port()
}

fn rules_allow_hosts(hosts: &[&str]) -> String {
    hosts
        .iter()
        .map(|h| format!("    - host: {}\n      action: allow\n", h))
        .collect::<String>()
}

fn rules_allow_host_with_secret_rewrite(host: &str, secret_ref: &str) -> String {
    format!(
        r#"    - host: {host}
      action: allow
      header_rewrites:
        - name: Authorization
          value: "Bearer {{value}}"
          secret_ref: {secret_ref}
"#
    )
}

fn healthz_status(metrics_addr: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&metrics_addr, Duration::from_millis(250)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;

    let req = b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req).ok()?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    parse_status_code(&buf)
}

fn metrics_body(metrics_addr: SocketAddr) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&metrics_addr, Duration::from_millis(250)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;

    let req = b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req).ok()?;

    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let (_, body) = raw.split_once("\r\n\r\n")?;
    Some(body.to_string())
}

fn tls_handshake_counter(metrics_text: &str, result: &str) -> u64 {
    let prefix = format!("botbox_tls_handshakes_total{{result=\"{}\"}} ", result);
    metrics_text
        .lines()
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn tls_handshake_counter_total(metrics_text: &str) -> u64 {
    metrics_text
        .lines()
        .filter(|line| line.starts_with("botbox_tls_handshakes_total{"))
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|v| v.parse::<u64>().ok())
        .sum()
}

fn parse_status_code(raw_http: &str) -> Option<u16> {
    raw_http
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
}

fn load_root_store(ca_cert_pem: &[u8]) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let certs =
        CertificateDer::pem_slice_iter(ca_cert_pem).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no CA certificates found in PEM"));
    }

    for cert in certs {
        root_store
            .add(cert)
            .context("failed to add test CA cert to root store")?;
    }
    Ok(root_store)
}

fn connect_tls_stream(
    https_interception_addr: SocketAddr,
    sni_dns_name: &str,
    ca_cert_pem: &[u8],
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store = load_root_store(ca_cert_pem)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(sni_dns_name.to_string())
        .map_err(|_| anyhow!("invalid SNI DNS name: {}", sni_dns_name))?;

    let connection = ClientConnection::new(Arc::new(client_config), server_name)
        .context("failed to build rustls client connection")?;

    let socket = TcpStream::connect_timeout(&https_interception_addr, Duration::from_secs(2))
        .with_context(|| {
            format!(
                "failed to connect to HTTPS interception listener at {}",
                https_interception_addr
            )
        })?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("failed to set read timeout")?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .context("failed to set write timeout")?;

    let mut tls = StreamOwned::new(connection, socket);
    tls.conn
        .complete_io(&mut tls.sock)
        .context("TLS handshake failed")?;
    Ok(tls)
}

fn tls_handshake_leaf_cert(
    https_interception_addr: SocketAddr,
    sni_dns_name: &str,
    ca_cert_pem: &[u8],
) -> Result<Vec<u8>> {
    let tls = connect_tls_stream(https_interception_addr, sni_dns_name, ca_cert_pem)?;
    let leaf = tls
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| anyhow!("no peer certificate in TLS connection"))?;

    Ok(leaf.as_ref().to_vec())
}

fn tls_http_request(
    https_interception_addr: SocketAddr,
    sni_dns_name: &str,
    host_header: &str,
    path: &str,
    ca_cert_pem: &[u8],
) -> Result<String> {
    let mut tls = connect_tls_stream(https_interception_addr, sni_dns_name, ca_cert_pem)?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_header
    );
    tls.write_all(req.as_bytes())
        .context("failed to write HTTP request over TLS")?;
    tls.flush().context("failed to flush TLS stream")?;

    let mut buf = vec![0u8; 16 * 1024];
    let n = tls
        .read(&mut buf)
        .context("failed to read HTTP response over TLS")?;
    if n == 0 {
        return Err(anyhow!("received empty HTTP response"));
    }
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn run_openssl(args: &[&str]) -> Result<(ExitStatus, String, String)> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute openssl with args: {:?}", args))?;

    Ok((
        output.status,
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

#[test]
fn https_interception_config_fails_closed_when_ca_files_are_missing() {
    let spec = HttpsInterceptionSpec {
        write_ca_files: false,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);

    let exit = proc.wait_for_exit(Duration::from_secs(3));
    let status = exit.unwrap_or_else(|| {
        panic!(
            "expected startup failure when CA files are missing, but process stayed alive\n{}",
            proc.log_tail(80)
        )
    });
    assert!(
        !status.success(),
        "HTTPS interception enabled must fail startup when CA files are missing"
    );
}

#[test]
fn https_interception_readiness_requires_required_secrets_and_ca_loaded() {
    // required secret missing -> /healthz should stay 503
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_host_with_secret_rewrite("localhost", "openai-api-key"),
        initial_secrets: Vec::new(),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));
    assert_eq!(
        healthz_status(proc.metrics_addr),
        Some(503),
        "missing required secret must keep readiness at 503"
    );

    proc.write_secret("openai-api-key", "test-not-a-real-key");

    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if healthz_status(proc.metrics_addr) == Some(200) {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }

    panic!("readiness did not flip to 200 after required secret was added");
}

#[test]
fn https_interception_sni_validation_accepts_valid_ascii_and_punycode_hosts() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost", "api.openai.com", "xn--bcher-kva.example"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    for host in ["localhost", "api.openai.com", "xn--bcher-kva.example"] {
        tls_handshake_leaf_cert(proc.https_interception_addr, host, &proc.ca_cert_pem)
            .unwrap_or_else(|e| {
                panic!("valid SNI host '{}' should complete handshake: {}", host, e)
            });
    }
}

#[test]
fn https_interception_sni_validation_rejects_invalid_or_oversized_hosts() {
    let spec = HttpsInterceptionSpec::default();
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let oversized = format!("{}.example.com", "a".repeat(254));
    for host in ["bad host", "bad_host", "*.example.com", &oversized] {
        let result = tls_handshake_leaf_cert(proc.https_interception_addr, host, &proc.ca_cert_pem);
        assert!(
            result.is_err(),
            "invalid SNI host '{}' must be rejected",
            host
        );
    }
}

#[test]
fn https_interception_leaf_certificate_contains_san_dns_expected_validity_and_ca_issuer() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        cert_ttl_seconds: 86_400,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let leaf_der =
        tls_handshake_leaf_cert(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
            .unwrap_or_else(|e| {
                panic!(
                    "expected successful TLS handshake for certificate inspection: {}",
                    e
                )
            });
    assert!(
        !leaf_der.is_empty(),
        "leaf certificate DER must not be empty"
    );

    if !openssl_available() {
        eprintln!("openssl is not available; skipping SAN/TTL/CA verify subprocess checks");
        return;
    }

    let inspect_tmp = TempDir::new().expect("failed to create tempdir for openssl inspection");
    let leaf_der_path = inspect_tmp.path().join("leaf.der");
    let leaf_pem_path = inspect_tmp.path().join("leaf.pem");
    let ca_pem_path = inspect_tmp.path().join("ca.crt");
    std::fs::write(&leaf_der_path, &leaf_der).expect("failed to write leaf DER");
    std::fs::write(&ca_pem_path, &proc.ca_cert_pem).expect("failed to write CA PEM");

    let leaf_der_path = leaf_der_path.display().to_string();
    let leaf_pem_path = leaf_pem_path.display().to_string();
    let ca_pem_path = ca_pem_path.display().to_string();

    let (text_status, text_stdout, text_stderr) = run_openssl(&[
        "x509",
        "-inform",
        "der",
        "-in",
        &leaf_der_path,
        "-noout",
        "-text",
    ])
    .expect("failed to inspect leaf cert via openssl");
    assert!(
        text_status.success(),
        "openssl x509 -text failed: {}",
        text_stderr
    );
    assert!(
        text_stdout.contains("DNS:localhost"),
        "leaf cert SAN must contain DNS:localhost"
    );
    assert!(
        text_stdout.contains("Issuer: CN = botbox-test-ca")
            || text_stdout.contains("Issuer: CN=botbox-test-ca")
            || text_stdout.contains("issuer=CN = botbox-test-ca")
            || text_stdout.contains("issuer=CN=botbox-test-ca"),
        "leaf cert issuer must be the configured CA, got:\n{}",
        text_stdout
    );

    let (min_ttl_status, _, min_ttl_stderr) = run_openssl(&[
        "x509",
        "-inform",
        "der",
        "-in",
        &leaf_der_path,
        "-noout",
        "-checkend",
        "80000",
    ])
    .expect("failed to run openssl -checkend (min ttl)");
    assert!(
        min_ttl_status.success(),
        "leaf cert should be valid for at least ~22h (checkend=80000): {}",
        min_ttl_stderr
    );

    let (max_ttl_status, _, _) = run_openssl(&[
        "x509",
        "-inform",
        "der",
        "-in",
        &leaf_der_path,
        "-noout",
        "-checkend",
        "200000",
    ])
    .expect("failed to run openssl -checkend (max ttl)");
    assert!(
        !max_ttl_status.success(),
        "leaf cert should not be valid for ~55h when ttl is configured to 24h"
    );

    let (convert_status, _, convert_stderr) = run_openssl(&[
        "x509",
        "-inform",
        "der",
        "-in",
        &leaf_der_path,
        "-out",
        &leaf_pem_path,
    ])
    .expect("failed to convert leaf DER to PEM");
    assert!(
        convert_status.success(),
        "failed to convert leaf DER to PEM: {}",
        convert_stderr
    );

    let (verify_status, verify_stdout, verify_stderr) =
        run_openssl(&["verify", "-CAfile", &ca_pem_path, &leaf_pem_path])
            .expect("failed to run openssl verify");
    assert!(
        verify_status.success(),
        "leaf cert must verify against configured CA. stdout='{}' stderr='{}'",
        verify_stdout,
        verify_stderr
    );
}

#[test]
fn https_interception_cert_cache_exposes_hit_ttl_expiry_and_lru_eviction_behaviour() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost", "api.openai.com", "files.openai.com"]),
        cert_cache_size: 1,
        cert_cache_ttl_seconds: 1,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let cert_a1 =
        tls_handshake_leaf_cert(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
            .expect("first localhost handshake should succeed");
    let cert_a2 =
        tls_handshake_leaf_cert(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
            .expect("second localhost handshake should succeed");
    assert_eq!(cert_a1, cert_a2, "expected cache hit for repeated same SNI");

    let _cert_b = tls_handshake_leaf_cert(
        proc.https_interception_addr,
        "api.openai.com",
        &proc.ca_cert_pem,
    )
    .expect("api.openai.com handshake should succeed");
    let cert_a3 =
        tls_handshake_leaf_cert(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
            .expect("localhost handshake after eviction should succeed");
    assert_ne!(
        cert_a1, cert_a3,
        "expected LRU eviction with cache_size=1 after another host was issued"
    );

    let cert_c1 = tls_handshake_leaf_cert(
        proc.https_interception_addr,
        "files.openai.com",
        &proc.ca_cert_pem,
    )
    .expect("files.openai.com handshake should succeed");
    thread::sleep(Duration::from_secs(2));
    let cert_c2 = tls_handshake_leaf_cert(
        proc.https_interception_addr,
        "files.openai.com",
        &proc.ca_cert_pem,
    )
    .expect("files.openai.com handshake after TTL should succeed");
    assert_ne!(
        cert_c1, cert_c2,
        "expected cert cache TTL expiry to force re-issuance"
    );
}

#[test]
fn https_interception_integration_trusted_tls_client_can_send_http1_request() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let resp = tls_http_request(
        proc.https_interception_addr,
        "localhost",
        "localhost",
        "/",
        &proc.ca_cert_pem,
    )
    .expect("trusted rustls client should complete TLS and receive an HTTP response");

    let status = parse_status_code(&resp).expect("response must include an HTTP status line");
    assert!(
        (100..600).contains(&status),
        "expected a valid HTTP status code over HTTPS interception TLS listener, got {}",
        status
    );
}

#[test]
fn https_interception_integration_rejects_sni_host_mismatch_with_400() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost", "example.com"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let resp = tls_http_request(
        proc.https_interception_addr,
        "localhost",
        "example.com",
        "/",
        &proc.ca_cert_pem,
    )
    .expect("SNI/Host mismatch request should still return an HTTP response");

    assert_eq!(
        parse_status_code(&resp),
        Some(400),
        "SNI/Host mismatch must be rejected with HTTP 400"
    );
}

#[test]
fn https_interception_integration_rejects_non_443_host_port() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let resp = tls_http_request(
        proc.https_interception_addr,
        "localhost",
        "localhost:8443",
        "/",
        &proc.ca_cert_pem,
    )
    .expect("non-443 Host request should still return an HTTP response");

    assert_eq!(
        parse_status_code(&resp),
        Some(403),
        "Host header with non-443 explicit port must be rejected"
    );
}

#[test]
fn https_interception_integration_rejects_absolute_form_request() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    // Send an absolute-form request (http://localhost/path) instead of origin-form (/path).
    // This should be rejected with 400 to prevent URI authority bypass.
    let mut tls = connect_tls_stream(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
        .expect("TLS handshake should succeed for allowed host");
    let req =
        "GET http://localhost:9999/bypass HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes())
        .expect("failed to write absolute-form request");
    tls.flush().expect("failed to flush");

    let mut buf = vec![0u8; 16 * 1024];
    let n = tls.read(&mut buf).expect("failed to read response");
    assert!(n > 0, "expected non-empty response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(
        parse_status_code(&resp),
        Some(400),
        "absolute-form request must be rejected with 400 on HTTPS interception listener"
    );
}

#[test]
fn https_interception_integration_rejects_absolute_form_even_with_matching_sni_host_and_port() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let mut tls = connect_tls_stream(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
        .expect("TLS handshake should succeed for allowed host");
    let req = "GET https://localhost:443/safe HTTP/1.1\r\nHost: localhost:443\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes())
        .expect("failed to write absolute-form request");
    tls.flush().expect("failed to flush");

    let mut buf = vec![0u8; 16 * 1024];
    let n = tls.read(&mut buf).expect("failed to read response");
    assert!(n > 0, "expected non-empty response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(
        parse_status_code(&resp),
        Some(400),
        "absolute-form request must be rejected even when Host/SNI/port match"
    );
}

#[test]
fn https_interception_config_rejects_cert_cache_ttl_larger_than_cert_ttl() {
    let spec = HttpsInterceptionSpec {
        cert_ttl_seconds: 60,
        cert_cache_ttl_seconds: 61,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);

    let exit = proc.wait_for_exit(Duration::from_secs(3));
    let status = exit.unwrap_or_else(|| {
        panic!(
            "expected startup failure when cert cache TTL exceeds cert TTL, but process stayed alive\n{}",
            proc.log_tail(80)
        )
    });
    assert!(
        !status.success(),
        "HTTPS interception config must fail startup when cert_cache_ttl_seconds > cert_ttl_seconds"
    );
}

#[test]
fn https_interception_integration_enforces_connection_limit_on_https_interception_listener() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        max_connections: 1,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let first_conn =
        connect_tls_stream(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
            .expect("first TLS connection should succeed");
    thread::sleep(Duration::from_millis(150));

    let second = connect_tls_stream(proc.https_interception_addr, "localhost", &proc.ca_cert_pem);
    drop(first_conn);
    assert!(
        second.is_err(),
        "second HTTPS interception TLS connection should be rejected when max_connections=1 and one connection is held open"
    );
}

#[test]
fn https_interception_metrics_tls_handshakes_are_counted_once_per_connection() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        deny_handshake_on_disallowed_sni: true,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    tls_handshake_leaf_cert(proc.https_interception_addr, "localhost", &proc.ca_cert_pem)
        .expect("successful handshake must succeed");
    let disallowed = tls_handshake_leaf_cert(
        proc.https_interception_addr,
        "disallowed.example.com",
        &proc.ca_cert_pem,
    );
    assert!(
        disallowed.is_err(),
        "disallowed SNI handshake should fail when deny_handshake_on_disallowed_sni=true"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut latest_metrics = String::new();
    while Instant::now() < deadline {
        if let Some(m) = metrics_body(proc.metrics_addr) {
            let ok = tls_handshake_counter(&m, "ok");
            let io_error = tls_handshake_counter(&m, "io_error");
            latest_metrics = m;
            if ok >= 1 && io_error >= 1 {
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    assert_eq!(
        tls_handshake_counter(&latest_metrics, "ok"),
        1,
        "one successful handshake should be counted exactly once"
    );
    assert_eq!(
        tls_handshake_counter(&latest_metrics, "io_error"),
        1,
        "one failed handshake should be counted exactly once"
    );
    assert_eq!(
        tls_handshake_counter_total(&latest_metrics),
        2,
        "tls_handshakes_total should not be double-counted across resolver + accept loop"
    );
}

#[test]
fn https_interception_integration_disallowed_sni_handshake_can_be_denied() {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        deny_handshake_on_disallowed_sni: true,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let result = tls_handshake_leaf_cert(
        proc.https_interception_addr,
        "disallowed.example.com",
        &proc.ca_cert_pem,
    );
    assert!(
        result.is_err(),
        "deny_handshake_on_disallowed_sni=true must fail the TLS handshake for disallowed SNI"
    );
}

#[test]
fn https_interception_integration_disallowed_sni_can_return_http_403_when_handshake_denial_is_disabled(
) {
    let spec = HttpsInterceptionSpec {
        rules_yaml: rules_allow_hosts(&["localhost"]),
        deny_handshake_on_disallowed_sni: false,
        ..HttpsInterceptionSpec::default()
    };
    let mut proc = BotboxProcess::start(spec);
    proc.wait_for_healthz_endpoint(Duration::from_secs(5));

    let resp = tls_http_request(
        proc.https_interception_addr,
        "disallowed.example.com",
        "disallowed.example.com",
        "/",
        &proc.ca_cert_pem,
    )
    .expect("disallowed SNI should still be able to produce HTTP 403 when handshake denial is off");

    assert_eq!(
        parse_status_code(&resp),
        Some(403),
        "deny_handshake_on_disallowed_sni=false should preserve HTTP-level deny semantics (403)"
    );
}
