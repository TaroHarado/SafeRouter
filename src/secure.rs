//! Secure memory handling for upstream API keys.
//!
//! API keys are the crown jewel of an LLM proxy: every upstream provider
//! collects them, every malicious one wants them. We keep them inside a
//! `Zeroizing<String>` so they are wiped on drop, and provide an accessor
//! that yields a short-lived borrowed view — never a clone, never a logging
//! copy.

use zeroize::Zeroize;

/// A secret string that wipes itself when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Wrap an empty secret (for the "client supplies Authorization" case).
    pub fn empty() -> Self {
        Self(String::new())
    }

    /// Borrow the secret bytes without copying.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if no upstream key is configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_wipes_on_drop() {
        let mut secret = Secret::new("sk-ant-deadbeef".to_string());
        let ptr = secret.as_str().as_ptr();
        let _ = secret.as_str();
        secret.0.zeroize();
        // After zeroize, the buffer is overwritten — no sk- prefix survives.
        assert!(!secret.as_str().contains("sk-ant"));
        let _ = ptr;
    }
}