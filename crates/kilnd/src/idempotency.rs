//! Idempotent create (API additions design, section 3): the request ID grammar and the
//! canonical request digest. The in-flight map and the pending quota live in the
//! manager; the request records and their retention live in the store.

use kilnd_api::v1 as pb;
use serde_json::{Map, Value, json};

use crate::model::Digest;

/// The longest `CreateSandboxRequest.request_id`, in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 64;

/// The digest's domain separator. A later layout gets a new version suffix.
pub const DIGEST_DOMAIN: &[u8] = b"kilnd.v1.create-request.1";

/// Design 3: 1-64 bytes, each printable ASCII without space (0x21-0x7e).
pub fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_BYTES {
        return Err(format!(
            "request_id must be 1 to {MAX_REQUEST_ID_BYTES} bytes, not {}",
            request_id.len()
        ));
    }
    if let Some(byte) = request_id.bytes().find(|b| !(0x21..=0x7e).contains(b)) {
        return Err(format!(
            "request_id may hold only printable ASCII without space (0x21-0x7e); found byte 0x{byte:02x}"
        ));
    }
    Ok(())
}

/// The canonical JSON the digest covers: the request *as sent*, before any default,
/// with `request_id` itself left out. An object with exactly three keys:
///
/// - `default_env`: `[name, value]` pairs sorted by name. Always empty until the
///   sandbox default env exists (milestone 3), so today's digests stay valid then.
/// - `expiry`: `null` when the message is absent, else both fields. Absent and
///   present-with-zeros mean different things, so they hash differently.
/// - `spec`: every `SandboxSpec` field, labels as an object, the network mode as its
///   enum number. An absent spec, limits or network message hashes as its zeros:
///   proto3 cannot tell an unset scalar from zero, and neither can the digest.
///
/// The bytes follow the Phase 1b canonical JSON contract (sorted keys, fixed escapes,
/// integers only), through the same encoder the spec digests use.
pub fn canonical_request(req: &pb::CreateSandboxRequest) -> Vec<u8> {
    let spec = req.spec.clone().unwrap_or_default();
    let limits = spec.limits.unwrap_or_default();
    let network = spec.network.unwrap_or_default();
    let labels: Map<String, Value> = spec
        .labels
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
    let expiry = match &req.expiry {
        None => Value::Null,
        Some(e) => json!({
            "idle_timeout_ms": e.idle_timeout_ms,
            "max_lifetime_ms": e.max_lifetime_ms,
        }),
    };
    let value = json!({
        "default_env": Value::Array(Vec::new()),
        "expiry": expiry,
        "spec": {
            "image": spec.image,
            "labels": Value::Object(labels),
            "limits": {
                "cpu_millis": limits.cpu_millis,
                "disk_bytes": limits.disk_bytes,
                "memory_bytes": limits.memory_bytes,
                "pids": limits.pids,
            },
            "network": {
                "allow": network.allow,
                "mode": network.mode,
            },
            "read_only_root": spec.read_only_root,
            "writable_paths": spec.writable_paths,
        },
    });
    // Strings, booleans and integers well within range at depth 3: the encoder's
    // only refusals (floats, depth past 32) cannot happen here.
    crate::firecracker::canonical(&value).expect("a create request always has canonical JSON")
}

/// `request_sha256`: SHA-256 over the domain, one zero byte and the canonical JSON.
pub fn request_digest(req: &pb::CreateSandboxRequest) -> Digest {
    let json = canonical_request(req);
    let mut input = Vec::with_capacity(DIGEST_DOMAIN.len() + 1 + json.len());
    input.extend_from_slice(DIGEST_DOMAIN);
    input.push(0);
    input.extend_from_slice(&json);
    Digest::of(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest goldens, shared with clients that recompute them (the harness):
    /// `tests/data/create-request-digests.json` in this repository.
    const GOLDENS: &str = include_str!("../tests/data/create-request-digests.json");

    fn request(case: &Value) -> pb::CreateSandboxRequest {
        let r = &case["request"];
        let spec = r.get("spec").filter(|s| !s.is_null()).map(|s| {
            let limits = s.get("limits").filter(|l| !l.is_null()).map(|l| pb::ResourceLimits {
                memory_bytes: l["memory_bytes"].as_u64().unwrap_or(0),
                cpu_millis: l["cpu_millis"].as_u64().unwrap_or(0) as u32,
                pids: l["pids"].as_u64().unwrap_or(0) as u32,
                disk_bytes: l["disk_bytes"].as_u64().unwrap_or(0),
            });
            let network = s.get("network").filter(|n| !n.is_null()).map(|n| pb::NetworkPolicy {
                mode: n["mode"].as_i64().unwrap_or(0) as i32,
                allow: n["allow"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
                    .unwrap_or_default(),
            });
            pb::SandboxSpec {
                image: s["image"].as_str().unwrap_or("").into(),
                limits,
                network,
                read_only_root: s["read_only_root"].as_bool().unwrap_or(false),
                writable_paths: s["writable_paths"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
                    .unwrap_or_default(),
                labels: s["labels"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        });
        let expiry = r.get("expiry").filter(|e| !e.is_null()).map(|e| pb::ExpiryPolicy {
            max_lifetime_ms: e["max_lifetime_ms"].as_u64().unwrap_or(0),
            idle_timeout_ms: e["idle_timeout_ms"].as_u64().unwrap_or(0),
        });
        pb::CreateSandboxRequest {
            spec,
            expiry,
            request_id: r["request_id"].as_str().unwrap_or("").into(),
        }
    }

    #[test]
    fn digest_goldens_are_stable() {
        let goldens: Value = serde_json::from_str(GOLDENS).unwrap();
        assert_eq!(goldens["domain"], "kilnd.v1.create-request.1");
        let cases = goldens["cases"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let req = request(case);
            assert_eq!(
                String::from_utf8(canonical_request(&req)).unwrap(),
                case["canonical_json"].as_str().unwrap(),
                "{name}: canonical JSON"
            );
            assert_eq!(
                request_digest(&req).to_string(),
                case["request_sha256"].as_str().unwrap(),
                "{name}: digest"
            );
        }
    }

    #[test]
    fn request_id_is_excluded_and_unsent_messages_hash_as_zeros() {
        let mut a = pb::CreateSandboxRequest {
            request_id: "a".into(),
            ..Default::default()
        };
        let b = pb::CreateSandboxRequest {
            request_id: "b".into(),
            spec: Some(pb::SandboxSpec {
                limits: Some(pb::ResourceLimits::default()),
                network: Some(pb::NetworkPolicy::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(request_digest(&a), request_digest(&b));
        // Absent expiry and present all-zero expiry mean different things.
        a.expiry = Some(pb::ExpiryPolicy::default());
        assert_ne!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn every_spec_field_and_order_is_covered() {
        let base = pb::CreateSandboxRequest {
            spec: Some(pb::SandboxSpec {
                image: "alpine".into(),
                writable_paths: vec!["/a".into(), "/b".into()],
                network: Some(pb::NetworkPolicy {
                    mode: 3,
                    allow: vec!["x.example".into(), "y.example".into()],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let digest = request_digest(&base);
        type Mutation = Box<dyn Fn(&mut pb::SandboxSpec)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|s| s.image = "debian".into()),
            Box::new(|s| s.limits = Some(pb::ResourceLimits { memory_bytes: 1, ..Default::default() })),
            Box::new(|s| s.limits = Some(pb::ResourceLimits { cpu_millis: 1, ..Default::default() })),
            Box::new(|s| s.limits = Some(pb::ResourceLimits { pids: 1, ..Default::default() })),
            Box::new(|s| s.limits = Some(pb::ResourceLimits { disk_bytes: 1, ..Default::default() })),
            Box::new(|s| s.network.as_mut().unwrap().mode = 2),
            Box::new(|s| s.network.as_mut().unwrap().allow.reverse()),
            Box::new(|s| s.read_only_root = true),
            Box::new(|s| s.writable_paths.reverse()),
            Box::new(|s| {
                s.labels.insert("k".into(), "v".into());
            }),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut changed = base.clone();
            mutate(changed.spec.as_mut().unwrap());
            assert_ne!(request_digest(&changed), digest, "mutation {i}");
        }
        // Label insertion order never matters.
        let mut x = base.clone();
        let mut y = base.clone();
        x.spec.as_mut().unwrap().labels = [("a", "1"), ("b", "2")]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        y.spec.as_mut().unwrap().labels = [("b", "2"), ("a", "1")]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        assert_eq!(request_digest(&x), request_digest(&y));
    }

    #[test]
    fn request_id_grammar() {
        for ok in ["a", "!", "~", &"x".repeat(64), "run-1/task:7@model#3"] {
            assert!(validate_request_id(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", " ", "a b", "tab\t", "\u{7f}", "é", &"x".repeat(65), "nul\0"] {
            assert!(validate_request_id(bad).is_err(), "{bad:?}");
        }
    }
}
