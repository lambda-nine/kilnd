//! Exec cwd and env (API additions design 4): what history keeps instead of values
//! (design 4.2), and the stored form of a sandbox's default env.
//!
//! Validation, the merge and kiln's frame are in `kilnd_exec_core::exec_options`, shared
//! with the root helper.

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

pub use kilnd_exec_core::exec_options::{
    EnvLimits, EnvVar, ExecOptions, FEATURE_EXEC_OPTIONS, MAX_CWD_BYTES, merge_env, sorted_env,
    validate_cwd, validate_env,
};

/// `env_sha256`'s domain separator. A later encoding gets a new version suffix.
pub const ENV_DIGEST_DOMAIN: &[u8] = b"kilnd.v1.exec-env.1";

/// Design 4.2: lowercase hex SHA-256 of `"kilnd.v1.exec-env.1" || 0x00` followed by
/// each entry, sorted by name bytes, as `u32be len || name || u32be len || value`.
/// `None` for no entries. An unkeyed integrity fingerprint, not confidentiality.
pub fn env_sha256(env: &[EnvVar]) -> Option<String> {
    if env.is_empty() {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(ENV_DIGEST_DOMAIN);
    hash.update([0]);
    for entry in sorted_env(env) {
        hash.update((entry.name.len() as u32).to_be_bytes());
        hash.update(entry.name.as_bytes());
        hash.update((entry.value.len() as u32).to_be_bytes());
        hash.update(entry.value.as_bytes());
    }
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The names of `env`, sorted by bytes. Never the values.
pub fn env_names(env: &[EnvVar]) -> Vec<String> {
    sorted_env(env).into_iter().map(|e| e.name).collect()
}

/// `sandboxes.default_env`: the sorted `[name, value]` pairs as JSON.
pub fn encode_stored(env: &[EnvVar]) -> Result<String> {
    Ok(serde_json::to_string(&sorted_env(env))?)
}

/// The inverse of [`encode_stored`]. A stored list must be valid at the code ceilings
/// and sorted, or the sandbox's executions refuse rather than run without it.
pub fn decode_stored(text: &str) -> Result<Vec<EnvVar>> {
    // serde's own message can quote the stored text, which holds values: never chain it.
    let env: Vec<EnvVar> = serde_json::from_str(text)
        .map_err(|_| anyhow::anyhow!("stored default env is not JSON pairs"))?;
    ExecOptions {
        cwd: None,
        env: env.clone(),
    }
    .validate_strict(&EnvLimits::CEILINGS, MAX_CWD_BYTES)
    .map_err(anyhow::Error::msg)
    .context("stored default env is invalid")?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Goldens an independent encoder (Python's hashlib) produced; clients recompute them.
    #[test]
    fn env_digest_goldens_and_order_independence() {
        assert_eq!(env_sha256(&[]), None);
        assert_eq!(
            env_sha256(&[EnvVar::new("A", "1")]).unwrap(),
            "2603f468ba3210c56637236b3bb4fa2c637b59c2bc4cab419908ebdeddf1938f"
        );
        assert_eq!(
            env_sha256(&[EnvVar::new("A", ""), EnvVar::new("B", "2")]).unwrap(),
            "c91d8149e5b845070bef2ab16f824e9cd307c6029b35347aa70412b8bea9de46"
        );
        let ab = env_sha256(&[EnvVar::new("A", ""), EnvVar::new("B", "2")]);
        let ba = env_sha256(&[EnvVar::new("B", "2"), EnvVar::new("A", "")]);
        assert_eq!(ab, ba);
        // Length prefixes keep boundaries: A="B1" differs from AB="1".
        assert_ne!(
            env_sha256(&[EnvVar::new("A", "B1")]),
            env_sha256(&[EnvVar::new("AB", "1")])
        );
        assert_eq!(
            env_names(&[EnvVar::new("b", "x"), EnvVar::new("A", "y")]),
            ["A", "b"]
        );
    }

    #[test]
    fn stored_default_env_round_trips_and_refuses_corruption() {
        let env = vec![EnvVar::new("Z", "z"), EnvVar::new("A", "a")];
        let text = encode_stored(&env).unwrap();
        assert_eq!(text, r#"[["A","a"],["Z","z"]]"#);
        assert_eq!(decode_stored(&text).unwrap(), sorted_env(&env));
        let error = format!("{:#}", decode_stored(r#"[["A",{"x":"CANARY-stored"}]]"#).unwrap_err());
        assert!(!error.contains("CANARY"), "{error}");
        let error = format!("{:#}", decode_stored(r#"[["1A","CANARY-stored"]]"#).unwrap_err());
        assert!(!error.contains("CANARY"), "{error}");
        for bad in [
            r#"[["Z","z"],["A","a"]]"#,
            r#"[["1","a"]]"#,
            "{}",
            r#"[["A","a"],["A","b"]]"#,
        ] {
            assert!(decode_stored(bad).is_err(), "{bad}");
        }
    }
}
