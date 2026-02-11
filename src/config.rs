use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use tracing::warn;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen_addr: Option<String>,
    pub listen_port: Option<u16>,
    pub metrics_port: Option<u16>,
    pub secrets_dir: Option<String>,
    pub max_connections: Option<u32>,
    pub allow_non_loopback: Option<bool>,
    pub egress_policy: EgressPolicy,
    pub mitm: Option<MitmConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EgressPolicy {
    pub default_action: Option<Action>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub host: String,
    pub action: Action,
    pub header_rewrites: Option<Vec<HeaderRewrite>>,
    #[serde(default)]
    pub allowed_ports: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeaderRewrite {
    pub name: String,
    pub value: String,
    pub secret_ref: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MitmConfig {
    pub enabled: bool,
    pub listen_addr: Option<String>,
    pub listen_port: Option<u16>,
    pub ca_cert_path: String,
    pub ca_key_path: String,
    pub enforce_sni_host_match: Option<bool>,
    pub deny_handshake_on_disallowed_sni: Option<bool>,
    pub cert_ttl_seconds: Option<u64>,
    pub cert_cache_size: Option<u64>,
    pub cert_cache_ttl_seconds: Option<u64>,
    pub handshake_timeout_ms: Option<u64>,
}

impl MitmConfig {
    pub fn listen_addr(&self) -> &str {
        self.listen_addr.as_deref().unwrap_or("127.0.0.1")
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(8443)
    }

    pub fn enforce_sni_host_match(&self) -> bool {
        self.enforce_sni_host_match.unwrap_or(true)
    }

    pub fn deny_handshake_on_disallowed_sni(&self) -> bool {
        self.deny_handshake_on_disallowed_sni.unwrap_or(false)
    }

    pub fn cert_ttl_seconds(&self) -> u64 {
        self.cert_ttl_seconds.unwrap_or(86400)
    }

    pub fn cert_cache_size(&self) -> u64 {
        self.cert_cache_size.unwrap_or(1024)
    }

    pub fn cert_cache_ttl_seconds(&self) -> u64 {
        self.cert_cache_ttl_seconds.unwrap_or(3600)
    }

    pub fn handshake_timeout_ms(&self) -> u64 {
        self.handshake_timeout_ms.unwrap_or(5000)
    }
}

pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 with brackets: [::1]:port -> ::1
        match host.find(']') {
            Some(i) => &host[1..i],
            None => host,
        }
    } else if host.matches(':').count() > 1 {
        // Bare IPv6 (multiple colons, no brackets): return as-is
        host
    } else {
        // IPv4/hostname: strip port after the single colon
        host.rsplit_once(':')
            .and_then(|(h, p)| p.parse::<u16>().ok().map(|_| h))
            .unwrap_or(host)
    }
}

pub fn normalize_policy_host(host: &str) -> String {
    let normalized = host.trim().to_lowercase();
    strip_port(&normalized).to_string()
}

/// Extract the port from a host string, if present. Returns None if no explicit port.
pub fn extract_port(host: &str) -> Option<u16> {
    if host.starts_with('[') {
        // Bracketed IPv6: [::1]:port
        let after_bracket = host.find(']')?;
        let rest = &host[after_bracket + 1..];
        rest.strip_prefix(':')?.parse::<u16>().ok()
    } else if host.matches(':').count() > 1 {
        // Bare IPv6, no port
        None
    } else {
        // IPv4/hostname
        host.rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading config: {:?}", path))?;
        let config: Config =
            serde_yaml::from_str(&content).with_context(|| "parsing config YAML")?;
        config.validate()?;
        Ok(config)
    }

    pub fn listen_addr(&self) -> &str {
        self.listen_addr.as_deref().unwrap_or("127.0.0.1")
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(8080)
    }

    pub fn metrics_port(&self) -> u16 {
        self.metrics_port.unwrap_or(9090)
    }

    pub fn secrets_dir(&self) -> &str {
        self.secrets_dir
            .as_deref()
            .unwrap_or("/var/run/secrets/botbox")
    }

    pub fn max_connections(&self) -> u32 {
        self.max_connections.unwrap_or(1024)
    }

    pub fn allow_non_loopback(&self) -> bool {
        self.allow_non_loopback.unwrap_or(false)
    }

    pub fn default_action(&self) -> Action {
        self.egress_policy
            .default_action
            .clone()
            .unwrap_or(Action::Deny)
    }

    /// Collect all secret_ref names referenced in header rewrites.
    pub fn required_secret_refs(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for rule in &self.egress_policy.rules {
            if let Some(rewrites) = &rule.header_rewrites {
                for rewrite in rewrites {
                    if let Some(secret_ref) = &rewrite.secret_ref {
                        refs.push(secret_ref.clone());
                    }
                }
            }
        }
        refs.sort();
        refs.dedup();
        refs
    }

    fn validate(&self) -> Result<()> {
        let listen_addr = self.listen_addr();
        let listen_ip: IpAddr = listen_addr
            .parse()
            .with_context(|| format!("listen_addr must be an IP literal, got '{}'", listen_addr))?;
        if !listen_ip.is_loopback() && !self.allow_non_loopback() {
            bail!(
                "listen_addr '{}' is not loopback; set allow_non_loopback: true to permit non-loopback binding",
                listen_addr
            );
        }

        let mut seen_hosts = HashSet::new();

        for rule in &self.egress_policy.rules {
            if rule.host.trim().is_empty() {
                bail!("empty host in egress policy rule");
            }
            if rule.host != rule.host.trim() {
                bail!(
                    "host '{}' has leading/trailing whitespace in egress policy rule",
                    rule.host
                );
            }

            let normalized = normalize_policy_host(&rule.host);
            if !seen_hosts.insert(normalized) {
                bail!(
                    "duplicate host in egress policy after normalization: {}",
                    rule.host
                );
            }

            // Validate allowed_ports is not empty if specified
            if let Some(ports) = &rule.allowed_ports {
                if ports.is_empty() {
                    bail!(
                        "allowed_ports cannot be empty for host '{}' (use None/omit to default to 443-only)",
                        rule.host
                    );
                }
            }

            if let Some(rewrites) = &rule.header_rewrites {
                const DENIED_REWRITE_HEADERS: &[&str] = &[
                    "host",
                    "connection",
                    "keep-alive",
                    "proxy-connection",
                    "proxy-authenticate",
                    "proxy-authorization",
                    "te",
                    "trailer",
                    "transfer-encoding",
                    "upgrade",
                ];

                for rewrite in rewrites {
                    if rewrite.name.is_empty() {
                        bail!("empty header name in rewrite for host '{}'", rule.host);
                    }
                    // Validate header name is valid per HTTP spec
                    if http::header::HeaderName::from_bytes(rewrite.name.as_bytes()).is_err() {
                        bail!(
                            "invalid header name '{}' in rewrite for host '{}'",
                            rewrite.name,
                            rule.host
                        );
                    }
                    // Check against denylist of reserved/hop-by-hop headers
                    let lower_name = rewrite.name.to_lowercase();
                    if DENIED_REWRITE_HEADERS.contains(&lower_name.as_str()) {
                        bail!(
                            "header '{}' cannot be used in rewrites (reserved/hop-by-hop) for host '{}'",
                            rewrite.name,
                            rule.host
                        );
                    }
                }
            }
        }

        // MITM validation
        if let Some(mitm) = &self.mitm {
            if mitm.enabled {
                // MITM listen_addr must be loopback (hard requirement, even with allow_non_loopback)
                let mitm_addr = mitm.listen_addr();
                let mitm_ip: IpAddr = mitm_addr.parse().with_context(|| {
                    format!(
                        "mitm.listen_addr must be an IP literal, got '{}'",
                        mitm_addr
                    )
                })?;
                if !mitm_ip.is_loopback() {
                    bail!(
                        "mitm.listen_addr '{}' must be loopback; MITM listener must bind to loopback only",
                        mitm_addr
                    );
                }

                // Port collision checks
                let mitm_port = mitm.listen_port();
                if mitm_port == self.listen_port() {
                    bail!(
                        "mitm.listen_port {} collides with listen_port {}",
                        mitm_port,
                        self.listen_port()
                    );
                }
                if mitm_port == self.metrics_port() {
                    bail!(
                        "mitm.listen_port {} collides with metrics_port {}",
                        mitm_port,
                        self.metrics_port()
                    );
                }

                // CA path validation
                let cert_empty = mitm.ca_cert_path.trim().is_empty();
                let key_empty = mitm.ca_key_path.trim().is_empty();
                if cert_empty && key_empty {
                    bail!("mitm.ca_cert_path and mitm.ca_key_path must not be empty");
                } else if cert_empty {
                    bail!("mitm.ca_cert_path must not be empty");
                } else if key_empty {
                    bail!("mitm.ca_key_path must not be empty");
                }

                // cert_cache_size > 0
                if mitm.cert_cache_size() == 0 {
                    bail!("mitm.cert_cache_size must be greater than 0");
                }

                // cert_ttl_seconds in 60..604800
                let ttl = mitm.cert_ttl_seconds();
                if !(60..=604800).contains(&ttl) {
                    bail!(
                        "mitm.cert_ttl_seconds {} must be between 60 and 604800",
                        ttl
                    );
                }

                // handshake_timeout_ms in 100..60000
                let hs_timeout = mitm.handshake_timeout_ms();
                if !(100..=60000).contains(&hs_timeout) {
                    bail!(
                        "mitm.handshake_timeout_ms {} must be between 100 and 60000",
                        hs_timeout
                    );
                }

                // cert_cache_ttl_seconds must not exceed cert_ttl_seconds
                // (otherwise expired certificates could be served from cache)
                let cache_ttl = mitm.cert_cache_ttl_seconds();
                if cache_ttl > ttl {
                    bail!(
                        "mitm.cert_cache_ttl_seconds ({}) must not exceed mitm.cert_ttl_seconds ({})",
                        cache_ttl,
                        ttl
                    );
                }
            }
        }

        if self.allow_non_loopback() {
            warn!(
                listen_addr = %self.listen_addr(),
                "allow_non_loopback is enabled; ensure compensating controls (NetworkPolicy, mTLS) are in place"
            );
        }

        if self.default_action() == Action::Allow {
            warn!(
                "default_action is 'allow'; this is discouraged for production use (SEC-009: unbounded metrics cardinality, SEC-003: open proxy risk)"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_config() {
        let yaml = r#"
listen_addr: "127.0.0.1"
listen_port: 8080
metrics_port: 9090
secrets_dir: "/var/run/secrets"
egress_policy:
  default_action: deny
  rules:
    - host: api.openai.com
      action: allow
      header_rewrites:
        - name: Authorization
          value: "Bearer {value}"
          secret_ref: openai-api-key
    - host: api.anthropic.com
      action: allow
      header_rewrites:
        - name: x-api-key
          value: "{value}"
          secret_ref: anthropic-api-key
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.listen_port(), 8080);
        assert_eq!(config.metrics_port(), 9090);
        assert_eq!(config.egress_policy.rules.len(), 2);
    }

    #[test]
    fn test_reject_empty_host() {
        let yaml = r#"
egress_policy:
  rules:
    - host: ""
      action: allow
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("empty host"));
    }

    #[test]
    fn test_reject_duplicate_host() {
        let yaml = r#"
egress_policy:
  rules:
    - host: api.openai.com
      action: allow
    - host: API.OPENAI.COM
      action: allow
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate host"));
    }

    #[test]
    fn test_reject_duplicate_host_when_only_port_differs() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
    - host: EXAMPLE.COM:443
      action: allow
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate host"));
    }

    #[test]
    fn test_reject_invalid_action() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: maybe
"#;
        let result: Result<Config, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_header_name() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
      header_rewrites:
        - name: "invalid header name with spaces"
          value: "test"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("invalid header name"));
    }

    #[test]
    fn test_defaults() {
        let yaml = r#"
egress_policy:
  rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.listen_addr(), "127.0.0.1");
        assert_eq!(config.listen_port(), 8080);
        assert_eq!(config.metrics_port(), 9090);
        assert_eq!(config.secrets_dir(), "/var/run/secrets/botbox");
        assert_eq!(config.max_connections(), 1024);
        assert!(!config.allow_non_loopback());
        assert_eq!(config.default_action(), Action::Deny);
    }

    #[test]
    fn test_reject_non_loopback_bind_without_override() {
        let yaml = r#"
listen_addr: "0.0.0.0"
egress_policy:
  rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("allow_non_loopback"));
    }

    #[test]
    fn test_allow_non_loopback_bind_with_override() {
        let yaml = r#"
listen_addr: "0.0.0.0"
allow_non_loopback: true
egress_policy:
  rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert!(config.allow_non_loopback());
    }

    #[test]
    fn test_reject_empty_allowed_ports() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
      allowed_ports: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("allowed_ports cannot be empty"));
    }

    #[test]
    fn test_reject_host_header_rewrite() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
      header_rewrites:
        - name: Host
          value: "evil.com"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("cannot be used in rewrites"));
    }

    #[test]
    fn test_required_secret_refs() {
        let yaml = r#"
egress_policy:
  rules:
    - host: api.openai.com
      action: allow
      header_rewrites:
        - name: Authorization
          value: "Bearer {value}"
          secret_ref: openai-api-key
    - host: api.anthropic.com
      action: allow
      header_rewrites:
        - name: x-api-key
          value: "{value}"
          secret_ref: anthropic-api-key
        - name: anthropic-version
          value: "2023-06-01"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let refs = config.required_secret_refs();
        assert_eq!(refs, vec!["anthropic-api-key", "openai-api-key"]);
    }

    #[test]
    fn test_required_secret_refs_empty() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.required_secret_refs().is_empty());
    }

    #[test]
    fn test_non_loopback_with_default_allow_validates_ok() {
        let yaml = r#"
listen_addr: "0.0.0.0"
allow_non_loopback: true
egress_policy:
  default_action: allow
  rules: []
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        // Should not error, just warn
        config.validate().unwrap();
    }

    #[test]
    fn test_reject_connection_header_rewrite() {
        let yaml = r#"
egress_policy:
  rules:
    - host: example.com
      action: allow
      header_rewrites:
        - name: Connection
          value: "keep-alive"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("cannot be used in rewrites"));
    }

    // --- MITM design contract tests (WIP docs/wip/mitm/*) ---

    #[test]
    fn test_mitm_enabled_rejects_non_loopback_listener_even_with_global_override() {
        let yaml = r#"
allow_non_loopback: true
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "0.0.0.0"
  listen_port: 8443
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mitm.listen_addr"));
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn test_mitm_enabled_rejects_port_collision_with_http_listener() {
        let yaml = r#"
listen_port: 8080
metrics_port: 9090
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 8080
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mitm.listen_port"));
        assert!(err.to_string().contains("listen_port"));
    }

    #[test]
    fn test_mitm_enabled_rejects_port_collision_with_metrics_listener() {
        let yaml = r#"
listen_port: 8080
metrics_port: 9090
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 9090
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mitm.listen_port"));
        assert!(err.to_string().contains("metrics_port"));
    }

    #[test]
    fn test_mitm_enabled_requires_non_empty_ca_paths() {
        let yaml = r#"
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 8443
  ca_cert_path: ""
  ca_key_path: ""
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("mitm.ca_cert_path"));
        assert!(err.to_string().contains("mitm.ca_key_path"));
    }

    #[test]
    fn test_mitm_enabled_rejects_zero_cert_cache_size() {
        let yaml = r#"
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 8443
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
  cert_cache_size: 0
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("cert_cache_size"));
    }

    #[test]
    fn test_mitm_enabled_rejects_out_of_range_cert_ttl_seconds() {
        let yaml = r#"
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 8443
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
  cert_ttl_seconds: 30
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("cert_ttl_seconds"));
    }

    #[test]
    fn test_mitm_enabled_rejects_out_of_range_handshake_timeout_ms() {
        let yaml = r#"
egress_policy:
  rules: []
mitm:
  enabled: true
  listen_addr: "127.0.0.1"
  listen_port: 8443
  ca_cert_path: "/etc/botbox/mitm/ca.crt"
  ca_key_path: "/etc/botbox/mitm/ca.key"
  handshake_timeout_ms: 5
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("handshake_timeout_ms"));
    }
}
