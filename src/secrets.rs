use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// A secret value that never leaks through Debug or Display.
/// The inner value is zeroized on drop.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        SecretString(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

pub type SecretStore = Arc<ArcSwap<HashMap<String, SecretString>>>;

// 1 MB limit for individual secret files
const MAX_SECRET_FILE_SIZE: u64 = 1_048_576;

/// Load secrets from a directory where each file is one key.
/// Filenames become keys, file contents become values.
/// Symlinks are followed if they resolve within the secrets directory.
pub fn load_secrets_from_dir(dir: &Path) -> Result<HashMap<String, SecretString>> {
    let mut secrets = HashMap::new();

    if !dir.exists() {
        warn!(dir = %dir.display(), "secrets directory does not exist, starting with empty secrets");
        return Ok(secrets);
    }

    // Canonicalize the base directory for prefix checking
    let canonical_dir = dir
        .canonicalize()
        .with_context(|| format!("canonicalizing secrets directory: {:?}", dir))?;

    let entries =
        std::fs::read_dir(dir).with_context(|| format!("reading secrets directory: {:?}", dir))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Get the filename
        let filename = match path.file_name().and_then(|f| f.to_str()) {
            Some(name) if !name.starts_with('.') => name.to_string(),
            _ => continue, // Skip dotfiles and files with non-UTF8 names
        };

        // Resolve the real path (follows symlinks)
        let real_path = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skipping unresolvable path in secrets directory");
                continue;
            }
        };

        // Security check: ensure resolved path is under the secrets directory
        if !real_path.starts_with(&canonical_dir) {
            warn!(
                path = %path.display(),
                resolved = %real_path.display(),
                "skipping symlink that escapes secrets directory"
            );
            continue;
        }

        // Check it's a regular file (after following symlinks)
        let metadata = std::fs::metadata(&real_path)
            .with_context(|| format!("reading metadata for secret file: {:?}", real_path))?;

        if !metadata.file_type().is_file() {
            continue;
        }

        // Check file size limit
        if metadata.len() > MAX_SECRET_FILE_SIZE {
            warn!(
                path = %path.display(),
                size = metadata.len(),
                max = MAX_SECRET_FILE_SIZE,
                "skipping oversized secret file"
            );
            continue;
        }

        let content = std::fs::read_to_string(&real_path)
            .with_context(|| format!("reading secret file: {:?}", path))?;

        // Trim trailing newline (common in K8s secrets)
        let value = content.strip_suffix('\n').unwrap_or(&content).to_string();
        info!(key = %filename, "loaded secret");
        secrets.insert(filename, SecretString::new(value));
    }

    Ok(secrets)
}

/// Create a new SecretStore loaded from disk.
pub fn new_secret_store(dir: &Path) -> Result<SecretStore> {
    let secrets = load_secrets_from_dir(dir)?;
    Ok(Arc::new(ArcSwap::new(Arc::new(secrets))))
}

/// Check if all required secrets are present in the store.
/// Returns a list of missing secret names.
pub fn check_required_secrets(store: &SecretStore, required: &[String]) -> Vec<String> {
    let guard = store.load();
    required
        .iter()
        .filter(|name| !guard.contains_key(name.as_str()))
        .cloned()
        .collect()
}

/// Start watching the secrets directory for changes and hot-reload.
/// Returns a handle that keeps the watcher alive; drop it to stop watching.
pub fn start_secret_watcher(dir: PathBuf, store: SecretStore) -> Result<RecommendedWatcher> {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    let mut watcher =
        notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) {
                    let _ = tx.blocking_send(());
                }
            }
            Err(e) => {
                error!(error = %e, "secret watcher error");
            }
        })?;

    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching secrets directory: {:?}", dir))?;

    let store_clone = store;
    let dir_clone = dir;

    tokio::spawn(async move {
        // Debounce: wait for events, then reload after a short delay
        loop {
            if rx.recv().await.is_none() {
                break;
            }
            // Drain any additional events within the debounce window
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            while rx.try_recv().is_ok() {}

            info!("reloading secrets due to file change");
            match load_secrets_from_dir(&dir_clone) {
                Ok(new_secrets) => {
                    store_clone.store(Arc::new(new_secrets));
                    info!("secrets reloaded successfully");
                }
                Err(e) => {
                    error!(error = %e, "failed to reload secrets, keeping previous values");
                }
            }
        }
    });

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secret_string_redacted() {
        let s = SecretString::new("super-secret-key".to_string());
        assert_eq!(format!("{}", s), "[REDACTED]");
        assert_eq!(format!("{:?}", s), "[REDACTED]");
        assert_eq!(s.expose(), "super-secret-key");
    }

    #[test]
    fn test_load_secrets_from_dir() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("openai-api-key"), "sk-12345\n").unwrap();
        std::fs::write(dir.path().join("anthropic-api-key"), "ant-secret").unwrap();
        // Dotfile should be skipped
        std::fs::write(dir.path().join(".hidden"), "ignored").unwrap();

        let secrets = load_secrets_from_dir(dir.path()).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets["openai-api-key"].expose(), "sk-12345");
        assert_eq!(secrets["anthropic-api-key"].expose(), "ant-secret");
    }

    #[test]
    fn test_load_secrets_nonexistent_dir() {
        let secrets = load_secrets_from_dir(Path::new("/nonexistent/dir")).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_new_secret_store() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("key1"), "value1").unwrap();

        let store = new_secret_store(dir.path()).unwrap();
        let guard = store.load();
        assert_eq!(guard.get("key1").unwrap().expose(), "value1");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_secrets_follows_symlink_within_dir() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("real-key"), "value1").unwrap();
        std::fs::write(dir.path().join("source-key"), "value2").unwrap();
        std::os::unix::fs::symlink(dir.path().join("source-key"), dir.path().join("link-key"))
            .unwrap();

        let secrets = load_secrets_from_dir(dir.path()).unwrap();
        assert_eq!(secrets.get("real-key").unwrap().expose(), "value1");
        assert_eq!(secrets.get("source-key").unwrap().expose(), "value2");
        // Symlink within dir should now be followed
        assert_eq!(secrets.get("link-key").unwrap().expose(), "value2");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_secrets_rejects_symlink_escaping_dir() {
        let dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        std::fs::write(outside_dir.path().join("escaped-secret"), "should-not-load").unwrap();
        std::os::unix::fs::symlink(
            outside_dir.path().join("escaped-secret"),
            dir.path().join("escape-link"),
        )
        .unwrap();

        let secrets = load_secrets_from_dir(dir.path()).unwrap();
        assert!(!secrets.contains_key("escape-link"));
    }

    #[cfg(unix)]
    #[test]
    fn test_load_secrets_k8s_style_symlink_layout() {
        // K8s Secret volumes use: secret-name -> ..data/secret-name -> ..2024_xxx/secret-name
        let dir = TempDir::new().unwrap();

        // Create the K8s-style directory structure
        let data_dir = dir.path().join("..2024_01_01");
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::write(data_dir.join("api-key"), "my-secret-value").unwrap();

        // ..data -> ..2024_01_01
        std::os::unix::fs::symlink(&data_dir, dir.path().join("..data")).unwrap();

        // api-key -> ..data/api-key
        std::os::unix::fs::symlink(
            dir.path().join("..data").join("api-key"),
            dir.path().join("api-key"),
        )
        .unwrap();

        let secrets = load_secrets_from_dir(dir.path()).unwrap();
        // The api-key symlink should be followed (resolves within dir)
        assert_eq!(secrets.get("api-key").unwrap().expose(), "my-secret-value");
        // Dotfile entries (..data, ..2024_01_01) should be skipped
        assert!(!secrets.contains_key("..data"));
        assert!(!secrets.contains_key("..2024_01_01"));
    }

    #[test]
    fn test_load_secrets_skips_oversized_file() {
        let dir = TempDir::new().unwrap();
        // Create a file larger than MAX_SECRET_FILE_SIZE (1MB)
        let large_content = "x".repeat(1_048_577);
        std::fs::write(dir.path().join("large-secret"), &large_content).unwrap();
        std::fs::write(dir.path().join("normal-secret"), "small").unwrap();

        let secrets = load_secrets_from_dir(dir.path()).unwrap();
        assert!(!secrets.contains_key("large-secret"));
        assert_eq!(secrets.get("normal-secret").unwrap().expose(), "small");
    }

    #[tokio::test]
    async fn test_secret_hot_reload() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("key1"), "initial").unwrap();

        let store = new_secret_store(dir.path()).unwrap();

        // Verify initial value
        assert_eq!(store.load().get("key1").unwrap().expose(), "initial");

        // Start watcher
        let _watcher = start_secret_watcher(dir.path().to_path_buf(), store.clone()).unwrap();

        // Modify the secret
        std::fs::write(dir.path().join("key1"), "updated").unwrap();

        // Wait for debounce (2s) + margin
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        // Verify updated value
        assert_eq!(store.load().get("key1").unwrap().expose(), "updated");
    }
}
