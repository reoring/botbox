use crate::config::{
    extract_port, normalize_policy_host, strip_port as config_strip_port, Action, Rule,
};
use std::collections::HashMap;

pub struct Allowlist {
    rules: HashMap<String, Rule>,
    default_action: Action,
}

pub enum Decision {
    Allow(Rule),
    DefaultAllow(Rule),
    Deny,
}

pub fn strip_port(host: &str) -> &str {
    config_strip_port(host)
}

impl Allowlist {
    pub fn new(rules: &[Rule], default_action: Action) -> Self {
        let mut map = HashMap::new();
        for rule in rules {
            let key = normalize_policy_host(&rule.host);
            map.insert(key, rule.clone());
        }
        Allowlist {
            rules: map,
            default_action,
        }
    }

    pub fn check(&self, host: &str) -> Decision {
        let host_only = normalize_policy_host(host);
        let request_port = extract_port(&host.trim().to_lowercase()).unwrap_or(443);

        match self.rules.get(&host_only) {
            Some(rule) if rule.action == Action::Allow => {
                // Check port against allowed_ports (default: 443 only)
                let port_allowed = match &rule.allowed_ports {
                    Some(ports) => ports.contains(&request_port),
                    None => request_port == 443,
                };
                if port_allowed {
                    Decision::Allow(rule.clone())
                } else {
                    Decision::Deny
                }
            }
            Some(_) => Decision::Deny,
            None => {
                if self.default_action == Action::Allow {
                    // Default-allow: only permit port 443
                    if request_port != 443 {
                        return Decision::Deny;
                    }
                    // No specific rule but default is allow; create a bare allow rule
                    Decision::DefaultAllow(Rule {
                        host: host_only,
                        action: Action::Allow,
                        header_rewrites: None,
                        allowed_ports: None,
                    })
                } else {
                    Decision::Deny
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, HeaderRewrite, Rule};

    fn make_rule(host: &str, action: Action) -> Rule {
        Rule {
            host: host.to_string(),
            action,
            header_rewrites: None,
            allowed_ports: None,
        }
    }

    fn make_rule_with_rewrite(host: &str) -> Rule {
        Rule {
            host: host.to_string(),
            action: Action::Allow,
            header_rewrites: Some(vec![HeaderRewrite {
                name: "Authorization".to_string(),
                value: "Bearer {value}".to_string(),
                secret_ref: Some("my-secret".to_string()),
            }]),
            allowed_ports: None,
        }
    }

    #[test]
    fn test_allow_known_host() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("api.openai.com"), Decision::Allow(_)));
    }

    #[test]
    fn test_deny_unknown_host() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("evil.com"), Decision::Deny));
    }

    #[test]
    fn test_case_insensitive() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("API.OPENAI.COM"), Decision::Allow(_)));
        assert!(matches!(al.check("Api.OpenAI.Com"), Decision::Allow(_)));
    }

    #[test]
    fn test_strip_port() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        // Port 443 is the default allowed port
        assert!(matches!(al.check("api.openai.com:443"), Decision::Allow(_)));
    }

    #[test]
    fn test_explicit_deny_rule() {
        let rules = vec![make_rule("blocked.com", Action::Deny)];
        let al = Allowlist::new(&rules, Action::Allow);
        assert!(matches!(al.check("blocked.com"), Decision::Deny));
    }

    #[test]
    fn test_allow_returns_rule_with_rewrites() {
        let rules = vec![make_rule_with_rewrite("api.openai.com")];
        let al = Allowlist::new(&rules, Action::Deny);
        if let Decision::Allow(rule) = al.check("api.openai.com") {
            assert!(rule.header_rewrites.is_some());
            let rewrites = rule.header_rewrites.unwrap();
            assert_eq!(rewrites.len(), 1);
            assert_eq!(rewrites[0].name, "Authorization");
        } else {
            panic!("expected Allow");
        }
    }

    #[test]
    fn test_default_allow_returns_bare_rule() {
        let al = Allowlist::new(&[], Action::Allow);
        if let Decision::DefaultAllow(rule) = al.check("any-host.com") {
            assert!(rule.header_rewrites.is_none());
        } else {
            panic!("expected DefaultAllow with default allow policy");
        }
    }

    #[test]
    fn test_ipv6_host() {
        let rules = vec![Rule {
            host: "::1".to_string(),
            action: Action::Allow,
            header_rewrites: None,
            allowed_ports: Some(vec![443, 8080]),
        }];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("[::1]:8080"), Decision::Allow(_)));
        // Bare IPv6 without port implies 443
        assert!(matches!(al.check("::1"), Decision::Allow(_)));
    }

    // --- SEC-002: Port-aware allowlist tests ---

    #[test]
    fn test_non_443_port_denied_by_default() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("api.openai.com:8443"), Decision::Deny));
    }

    #[test]
    fn test_443_port_allowed_by_default() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("api.openai.com:443"), Decision::Allow(_)));
    }

    #[test]
    fn test_explicit_port_allowance() {
        let rules = vec![Rule {
            host: "api.openai.com".to_string(),
            action: Action::Allow,
            header_rewrites: None,
            allowed_ports: Some(vec![443, 8443]),
        }];
        let al = Allowlist::new(&rules, Action::Deny);
        assert!(matches!(al.check("api.openai.com:8443"), Decision::Allow(_)));
        assert!(matches!(al.check("api.openai.com:9999"), Decision::Deny));
    }

    #[test]
    fn test_no_port_means_443() {
        let rules = vec![make_rule("api.openai.com", Action::Allow)];
        let al = Allowlist::new(&rules, Action::Deny);
        // No port specified = 443 implied
        assert!(matches!(al.check("api.openai.com"), Decision::Allow(_)));
    }

    #[test]
    fn test_default_allow_denies_non_443() {
        let al = Allowlist::new(&[], Action::Allow);
        assert!(matches!(al.check("any-host.com:8443"), Decision::Deny));
    }
}
