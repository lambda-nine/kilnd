//! API additions M2 at the gRPC boundary: request ID refusals, the create request
//! counts in Health, and old clients that set nothing new.

use std::sync::Arc;

use pb::kilnd_service_server::KilndService;

use super::*;
use crate::admission::ConnectionLane;
use crate::expiry::ManualClock;
use crate::manager::{CreateRequestLimits, Limits};
use crate::runtime::fake::FakeRuntime;
use crate::store::Store;

fn as_uid<T>(message: T, uid: u32) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

fn service(limits: Limits) -> (FakeRuntime, Service<FakeRuntime>) {
    let fake = FakeRuntime::default();
    let manager = Arc::new(Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_node_memory_bytes: 1 << 40,
            ..limits
        },
        Arc::new(ManualClock::default()),
    ));
    (fake, Service::new(manager))
}

fn keyed(request_id: &str) -> pb::CreateSandboxRequest {
    pb::CreateSandboxRequest {
        request_id: request_id.into(),
        ..Default::default()
    }
}

fn reason(status: &Status) -> Option<&str> {
    status.metadata().get(REASON_KEY).map(|v| v.to_str().unwrap())
}

#[tokio::test]
async fn quota_refusals_are_typed_and_counted_per_caller() {
    let (fake, s) = service(Limits {
        create_requests: CreateRequestLimits {
            max_per_uid: 1,
            max_node: 4,
        },
        ..Limits::default()
    });
    s.create_sandbox(as_uid(keyed("a"), 1000)).await.unwrap();
    let refused = s.create_sandbox(as_uid(keyed("b"), 1000)).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
    assert_eq!(reason(&refused), Some("request_id_quota"));
    assert!(refused.message().starts_with("request_id_quota: "));
    s.create_sandbox(as_uid(keyed("a"), 1001)).await.unwrap();
    assert_eq!(fake.state().created.len(), 2);
    for (uid, caller) in [(1000, 1), (1001, 1), (1002, 0)] {
        let admission = s
            .health(as_uid(pb::HealthRequest {}, uid))
            .await
            .unwrap()
            .into_inner()
            .admission
            .unwrap();
        assert_eq!(admission.caller_create_requests, caller, "uid {uid}");
        assert_eq!(admission.current_create_requests, 2);
        assert_eq!(admission.max_create_requests_per_uid, 1);
        assert_eq!(admission.max_create_requests, 4);
        assert_eq!(admission.rejected_create_requests, 1);
    }
}

#[tokio::test]
async fn bad_request_ids_are_invalid_and_allocate_nothing() {
    let (fake, s) = service(Limits::default());
    for bad in ["has space".to_string(), "x".repeat(65), "é".into(), "\t".into()] {
        let status = s.create_sandbox(as_uid(keyed(&bad), 1000)).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "{bad:?}");
        assert_eq!(reason(&status), None);
    }
    // A keyed request with an invalid spec is refused after the lookups, as
    // INVALID_ARGUMENT, and records nothing.
    let invalid_spec = pb::CreateSandboxRequest {
        request_id: "k".into(),
        spec: Some(pb::SandboxSpec {
            network: Some(pb::NetworkPolicy {
                mode: 99,
                allow: vec![],
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let status = s
        .create_sandbox(as_uid(invalid_spec, 1000))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(fake.state().created.is_empty());
    s.create_sandbox(as_uid(keyed("k"), 1000)).await.unwrap();
}

/// An old client sets nothing new and sees exactly what it saw before: a fresh
/// sandbox per create, and new response fields at their zero values, which proto3
/// does not encode.
#[tokio::test]
async fn an_old_client_sees_no_new_bytes() {
    let (fake, s) = service(Limits::default());
    let mut created = Vec::new();
    for _ in 0..2 {
        created.push(
            s.create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1000))
                .await
                .unwrap()
                .into_inner()
                .sandbox
                .unwrap(),
        );
    }
    let (a, b) = (created[0].clone(), created[1].clone());
    assert_ne!(a.id, b.id);
    assert_eq!(fake.state().created.len(), 2);
    assert!(a.request_id.is_empty() && !a.request_id_released);
    let mut without = a.clone();
    without.request_id = "x".into();
    without.request_id_released = true;
    assert!(without.encoded_len() > a.encoded_len());
    let deleted = s
        .delete_sandbox(as_uid(
            pb::DeleteSandboxRequest {
                id: a.id.clone(),
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert!(!deleted.request_id_released);
}

#[test]
fn grpc_timeouts_parse_strictly() {
    use std::time::Duration;
    assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
    assert_eq!(parse_grpc_timeout("2M"), Some(Duration::from_secs(120)));
    assert_eq!(parse_grpc_timeout("3S"), Some(Duration::from_secs(3)));
    assert_eq!(parse_grpc_timeout("400m"), Some(Duration::from_millis(400)));
    assert_eq!(parse_grpc_timeout("5u"), Some(Duration::from_micros(5)));
    assert_eq!(parse_grpc_timeout("99999999n"), Some(Duration::from_nanos(99_999_999)));
    for bad in ["", "S", "123456789S", "1s", "-1S", "1.5S", "1 S", "1x"] {
        assert_eq!(parse_grpc_timeout(bad), None, "{bad:?}");
    }
    let start = tokio::time::Instant::now();
    let mut req = Request::new(());
    req.metadata_mut()
        .insert("grpc-timeout", "1000m".parse().unwrap());
    assert_eq!(
        rpc_deadline(&req, start),
        Some(start + Duration::from_millis(950))
    );
    req.metadata_mut().insert("grpc-timeout", "1H".parse().unwrap());
    assert_eq!(
        rpc_deadline(&req, start),
        Some(start + Duration::from_secs(3600) - Duration::from_millis(250))
    );
    assert_eq!(rpc_deadline(&Request::new(()), start), None);
}
