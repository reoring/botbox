use crate::config::HeaderRewrite;
use crate::error::ProxyError;
use crate::secrets::SecretString;
use http::header::HeaderName;
use http::HeaderValue;
use hyper::Request;
use std::collections::HashMap;

/// Apply header rewrites to a request using the delete-then-add pattern.
/// This prevents header smuggling by removing all existing values of a header
/// before setting the new value.
pub fn apply_rewrites<B>(
    req: &mut Request<B>,
    rewrites: &[HeaderRewrite],
    secrets: &HashMap<String, SecretString>,
) -> Result<Vec<String>, ProxyError> {
    let mut rewritten = Vec::new();

    for rewrite in rewrites {
        let header_name = HeaderName::from_bytes(rewrite.name.to_lowercase().as_bytes())
            .map_err(|_| ProxyError::InvalidHeaderName(rewrite.name.clone()))?;

        // Resolve the value, potentially from secrets
        let resolved_value = resolve_value(&rewrite.value, &rewrite.secret_ref, secrets)?;

        // Delete-then-add: remove ALL existing values of this header
        req.headers_mut().remove(&header_name);

        // Add exactly one value
        let header_value =
            HeaderValue::from_str(&resolved_value).map_err(|_| ProxyError::InvalidHeaderValue)?;
        req.headers_mut().insert(&header_name, header_value);

        rewritten.push(rewrite.name.clone());
    }

    Ok(rewritten)
}

/// Resolve the value of a header rewrite.
/// If secret_ref is set, load from secrets and apply the format string.
/// The format string uses `{value}` as placeholder.
fn resolve_value(
    format: &str,
    secret_ref: &Option<String>,
    secrets: &HashMap<String, SecretString>,
) -> Result<String, ProxyError> {
    match secret_ref {
        Some(key) => {
            let secret = secrets
                .get(key)
                .ok_or_else(|| ProxyError::SecretNotFound(key.clone()))?;
            Ok(format.replace("{value}", secret.expose()))
        }
        None => Ok(format.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretString;
    use http::Request;

    fn make_secrets() -> HashMap<String, SecretString> {
        let mut m = HashMap::new();
        m.insert(
            "openai-key".to_string(),
            SecretString::new("sk-12345".to_string()),
        );
        m.insert(
            "anthropic-key".to_string(),
            SecretString::new("ant-secret".to_string()),
        );
        m
    }

    #[test]
    fn test_bearer_format_string() {
        let secrets = make_secrets();
        let rewrites = vec![HeaderRewrite {
            name: "Authorization".to_string(),
            value: "Bearer {value}".to_string(),
            secret_ref: Some("openai-key".to_string()),
        }];

        let mut req = Request::builder()
            .uri("http://api.openai.com/v1/models")
            .body(())
            .unwrap();

        let rewritten = apply_rewrites(&mut req, &rewrites, &secrets).unwrap();
        assert_eq!(rewritten, vec!["Authorization"]);
        assert_eq!(
            req.headers().get("authorization").unwrap(),
            "Bearer sk-12345"
        );
    }

    #[test]
    fn test_plain_value_format() {
        let secrets = make_secrets();
        let rewrites = vec![HeaderRewrite {
            name: "x-api-key".to_string(),
            value: "{value}".to_string(),
            secret_ref: Some("anthropic-key".to_string()),
        }];

        let mut req = Request::builder()
            .uri("http://api.anthropic.com/v1/messages")
            .body(())
            .unwrap();

        apply_rewrites(&mut req, &rewrites, &secrets).unwrap();
        assert_eq!(req.headers().get("x-api-key").unwrap(), "ant-secret");
    }

    #[test]
    fn test_delete_then_add_removes_smuggled_headers() {
        let secrets = make_secrets();
        let rewrites = vec![HeaderRewrite {
            name: "Authorization".to_string(),
            value: "Bearer {value}".to_string(),
            secret_ref: Some("openai-key".to_string()),
        }];

        let mut req = Request::builder()
            .uri("http://api.openai.com/v1/models")
            .header("Authorization", "smuggled-value-1")
            .header("Authorization", "smuggled-value-2")
            .body(())
            .unwrap();

        // Verify the smuggled headers exist
        assert_eq!(
            req.headers().get_all("authorization").into_iter().count(),
            2
        );

        apply_rewrites(&mut req, &rewrites, &secrets).unwrap();

        // After rewrite: exactly 1 value, the correct one
        let values: Vec<_> = req.headers().get_all("authorization").into_iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "Bearer sk-12345");
    }

    #[test]
    fn test_missing_secret_returns_error() {
        let secrets = HashMap::new();
        let rewrites = vec![HeaderRewrite {
            name: "Authorization".to_string(),
            value: "Bearer {value}".to_string(),
            secret_ref: Some("missing-key".to_string()),
        }];

        let mut req = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        let err = apply_rewrites(&mut req, &rewrites, &secrets).unwrap_err();
        assert!(matches!(err, ProxyError::SecretNotFound(_)));
    }

    #[test]
    fn test_static_value_no_secret_ref() {
        let secrets = HashMap::new();
        let rewrites = vec![HeaderRewrite {
            name: "X-Custom".to_string(),
            value: "static-value".to_string(),
            secret_ref: None,
        }];

        let mut req = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        apply_rewrites(&mut req, &rewrites, &secrets).unwrap();
        assert_eq!(req.headers().get("x-custom").unwrap(), "static-value");
    }

    #[test]
    fn test_multiple_rewrites() {
        let secrets = make_secrets();
        let rewrites = vec![
            HeaderRewrite {
                name: "Authorization".to_string(),
                value: "Bearer {value}".to_string(),
                secret_ref: Some("openai-key".to_string()),
            },
            HeaderRewrite {
                name: "X-Custom-Header".to_string(),
                value: "custom-{value}-suffix".to_string(),
                secret_ref: Some("anthropic-key".to_string()),
            },
        ];

        let mut req = Request::builder()
            .uri("http://example.com")
            .body(())
            .unwrap();

        let rewritten = apply_rewrites(&mut req, &rewrites, &secrets).unwrap();
        assert_eq!(rewritten.len(), 2);
        assert_eq!(
            req.headers().get("authorization").unwrap(),
            "Bearer sk-12345"
        );
        assert_eq!(
            req.headers().get("x-custom-header").unwrap(),
            "custom-ant-secret-suffix"
        );
    }
}
