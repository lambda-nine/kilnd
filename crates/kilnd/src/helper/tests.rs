// Approved (design 7.1): test fixtures, compiled only under cfg(test). They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#![allow(clippy::disallowed_methods)]
use super::protocol::*;
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[tokio::test]
async fn exit1_deadline_does_not_race_response_eof_with_a_redundant_cancel_byte() {
    use tokio::io::AsyncReadExt;
    use tokio::time::{Instant, timeout};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(fds::receive(&stream).await.unwrap().is_empty());
        let request: Request = read_frame(&mut stream).await.unwrap();
        request.validate(0).unwrap();
        fds::send(&stream, &[]).await.unwrap();
        // Withhold the reply beyond the wire deadline. The server owns that timer;
        // a redundant client byte would race its response close on Linux.
        assert!(
            timeout(Duration::from_millis(150), stream.read_u8())
                .await
                .is_err()
        );
        write_frame(
            &mut stream,
            &Response::Firecracker(FirecrackerResponse::Error(GroupError::new(
                GroupErrorKind::Unavailable,
                "original deadline expired",
            ))),
        )
        .await
        .unwrap();
        stream.shutdown().await.unwrap();
    });
    let reply = Client {
        path,
        expected_uid: unsafe { libc::geteuid() },
    }
    .firecracker(
        FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: crate::model::Id128::random(),
            connection_epoch: Some(crate::model::Id128::random()),
            operation: FirecrackerOperation::Capabilities,
        },
        Instant::now() + Duration::from_millis(100),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(matches!(reply, FirecrackerResponse::Error(error)
        if error.kind == GroupErrorKind::Unavailable));
    server.await.unwrap();
}

#[test]
fn typed_requests_reject_unknown_fields_and_validate_before_dispatch() {
    let valid: serde_json::Value = serde_json::json!({"version":3,"timeout_ms":1000,"deadline_ns":1,"operation":{"kiln":{"rm":{"id":"ab"}}}});
    assert!(serde_json::from_value::<Request>(valid.clone()).is_ok());
    let mut unknown_top = valid.clone();
    unknown_top["program"] = "/bin/sh".into();
    let mut unknown_nested = valid.clone();
    unknown_nested["operation"]["kiln"]["rm"]["extra"] = 1.into();
    let mut unknown_verb = valid;
    unknown_verb["operation"] = serde_json::json!({"shell":"true"});
    for json in [unknown_top, unknown_nested, unknown_verb] {
        assert!(
            serde_json::from_value::<Request>(json.clone()).is_err(),
            "{json}"
        );
    }
    let mut req = Request {
        version: VERSION,
        deadline_ns: 1,
        timeout_ms: 1000,
        operation: Operation::Kiln(KilnRequest::Ls),
    };
    assert!(req.validate(0).is_ok());
    assert!(req.validate(1).is_err());
    req.timeout_ms = 120001;
    assert!(req.validate(0).is_err());
    req.timeout_ms = 1;
    req.operation = Operation::Kiln(KilnRequest::Gc {
        ids: vec!["../x".into()],
    });
    assert!(req.validate(0).is_err());
    req.operation = Operation::Kiln(KilnRequest::Gc {
        ids: vec!["ab".into(), "ab".into()],
    });
    assert!(req.validate(0).is_err());
    req.operation = Operation::Kiln(KilnRequest::Exec {
        cwd: None,
        env: Vec::new(),
        id: "ab".into(),
        argv: vec!["sh\0".into()],
        stdin_bytes: 0,
        max_output: 1,
        live: false,
    });
    assert!(req.validate(0).is_err());
    req.operation = Operation::Kiln(KilnRequest::Exec {
        cwd: None,
        env: Vec::new(),
        id: "ab".into(),
        argv: vec!["true".into()],
        stdin_bytes: 32,
        max_output: 1024,
        live: false,
    });
    assert!(req.validate(0).is_ok());
    assert!(req.validate(3).is_err());
    for version in [1, 2] {
        req.version = version;
        assert!(req.validate(0).is_err());
    }
}

/// Break-it M3b LOW 2: serde's parse error quotes the frame's values, and the serve
/// loop logged it verbatim. The error it logs now names only the category and position.
#[test]
fn a_malformed_frame_error_never_quotes_its_values() {
    let canary = "CANARY-malformed-helper-env";
    let frames = [
        format!(
            r#"{{"version":3,"timeout_ms":1000,"deadline_ns":1,"operation":{{"kiln":{{"exec":{{"id":"ab","argv":["true"],"stdin_bytes":0,"max_output":1,"env":["{canary}"]}}}}}}}}"#
        ),
        format!(r#"{{"version":3,"{canary}":1}}"#),
        format!(r#"{{"version":"{canary}"}}"#),
    ];
    for frame in frames {
        // serde's own text quotes it: what the serve loop used to log.
        let detail = serde_json::from_str::<Request>(&frame)
            .unwrap_err()
            .to_string();
        assert!(detail.contains(canary), "{detail}");
        let logged = super::server::parse_request_for_test(frame.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(!logged.contains(canary), "{logged}");
        assert!(
            logged.starts_with("malformed helper request frame: "),
            "{logged}"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn received_peer_flag_mutation_cannot_stall_listener_or_deadline() {
    use tokio::io::AsyncReadExt;
    use tokio::time::{Instant, timeout};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let uid = unsafe { libc::geteuid() };
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(serve(
        listener,
        uid,
        temp.path().join("missing"),
        stop.clone(),
    ));
    let mut control = UnixStream::connect(&path).await.unwrap();
    fds::send(&control, &[]).await.unwrap();
    let request = Request {
        version: VERSION,
        timeout_ms: 300,
        deadline_ns: monotonic_ns().unwrap() + 300_000_000,
        operation: Operation::Kiln(KilnRequest::Exec {
            id: "abcd".into(),
            argv: vec!["true".into()],
            stdin_bytes: 32,
            max_output: 1024,
            live: false,
            cwd: None,
            env: Vec::new(),
        }),
    };
    write_frame(&mut control, &request).await.unwrap();
    let descriptors = fds::receive(&control).await.unwrap();
    control.write_u8(STDIO_RECEIVED).await.unwrap();
    assert_eq!(descriptors.len(), 3);
    for fd in &descriptors {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
            0
        );
    }
    assert_eq!(
        unsafe {
            libc::send(
                descriptors[0].as_raw_fd(),
                [b'A'; 32].as_ptr().cast(),
                32,
                libc::MSG_DONTWAIT,
            )
        },
        32
    );
    let client = Client {
        path,
        expected_uid: uid,
    };
    timeout(
        Duration::from_millis(200),
        client.call(
            KilnRequest::Ls,
            Instant::now() + Duration::from_secs(1),
            &tokio_util::sync::CancellationToken::new(),
        ),
    )
    .await
    .expect("another request stalled")
    .unwrap();
    assert!(
        timeout(Duration::from_millis(700), control.read_u8())
            .await
            .expect("stdin deadline stalled")
            .is_err()
    );
    // The malicious peers remain open through both assertions.
    drop(descriptors);
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn per_syscall_io_survives_even_shared_endpoint_flag_mutation() {
    use tokio::io::AsyncReadExt;
    let (helper, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    helper.set_nonblocking(true).unwrap();
    let retained = helper.try_clone().unwrap();
    let mut socket = socket::Socket(UnixStream::from_std(helper).unwrap());
    // A watchdog releases any accidentally blocking syscall so a regression
    // fails the test instead of hanging the test runner indefinitely.
    let release = peer.try_clone().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if rx.recv_timeout(Duration::from_secs(3)).is_err() {
            release.shutdown(std::net::Shutdown::Both).unwrap();
        }
    });
    retained.set_nonblocking(false).unwrap();
    std::io::Write::write_all(&mut peer, &[b'A'; 32]).unwrap();
    socket.read_exact(&mut [0; 32]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), socket.read_u8())
            .await
            .is_err()
    );
    // Saturate the outgoing queue without consuming any bytes at the peer.
    let bytes = [0u8; 8192];
    loop {
        let n = unsafe {
            libc::send(
                retained.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), socket.write_all(&bytes))
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_millis(50), socket.shutdown())
        .await
        .unwrap()
        .unwrap();
    tx.send(()).unwrap();
    watchdog.join().unwrap();
}

#[tokio::test]
async fn descriptor_envelope_is_exact_and_refuses_regular_files() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let tempfile = tempfile::tempfile().unwrap();
    fds::send(&sender, &[tempfile.as_raw_fd()]).await.unwrap();
    let received = fds::receive(&receiver).await.unwrap();
    assert_eq!(received.len(), 1);
    assert!(
        fds::socket(received.into_iter().next().unwrap(), unsafe {
            libc::geteuid()
        })
        .is_err()
    );
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(b"X").await.unwrap();
    assert!(fds::receive(&receiver).await.is_err());
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (peer, sent) = UnixStream::pair().unwrap();
    let sent: OwnedFd = sent.into_std().unwrap().into();
    fds::send(&sender, &[sent.as_raw_fd()]).await.unwrap();
    drop(sent);
    let received = fds::receive(&receiver).await.unwrap();
    let socket = fds::socket(received.into_iter().next().unwrap(), unsafe {
        libc::geteuid()
    })
    .unwrap();
    assert!(socket.peer_cred().is_ok());
    drop(peer);
}

#[tokio::test]
async fn wrong_peer_and_malformed_frames_never_run_kiln() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(serve(
        listener,
        unsafe { libc::geteuid() } + 1,
        temp.path().join("missing-kiln"),
        stop.clone(),
    ));
    let mut client = UnixStream::connect(&socket).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read_u8(&mut client)
        )
        .await
        .unwrap()
        .is_err()
    );
    stop.cancel();
    task.await.unwrap().unwrap();
    let listener = tokio::net::UnixListener::bind(temp.path().join("other.sock")).unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(serve(
        listener,
        unsafe { libc::geteuid() },
        temp.path().join("missing-kiln"),
        stop.clone(),
    ));
    let mut client = UnixStream::connect(temp.path().join("other.sock"))
        .await
        .unwrap();
    fds::send(&client, &[]).await.unwrap();
    client.write_u32((MAX_FRAME + 1) as u32).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read_u8(&mut client)
        )
        .await
        .unwrap()
        .is_err()
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn helper_roundtrip_carries_binary_stdio_via_fds_and_truthful_totals() {
    use crate::model::CommandStatus;
    use crate::runtime::{ExecFinish, ExecSpec};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("kiln");
    std::fs::write(&bin, r#"#!/usr/bin/python3
import os,sys,socket
CAPS=bytes.fromhex('4b494c4e45584f00010002001d0000001f000000010001000500080000000000302e312e306769742074657374')
STATUS=bytes.fromhex('4b494c4e45584f000100010018000000010102007d00000000000000000000000000000000000000')
if sys.argv[1]=='capabilities':
    os.write(1,CAPS); sys.exit(0)
if sys.argv[1:]==['gc','--help']:
    print('Usage: kiln gc [ID]...'); sys.exit(0)
fds={a.split('=')[0]:int(a.split('=')[1]) for a in sys.argv[2:7]}
s=socket.socket(fileno=fds['--stdin-fd'])
data=b''
while True:
    part=s.recv(65536)
    if not part: break
    data+=part
os.write(fds['--stdout-fd'],data)
os.write(fds['--stderr-fd'],b'\x00\xfferr')
os.write(fds['--status-fd'],STATUS)
sys.exit(125)
"#).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let uid = unsafe { libc::geteuid() };
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(serve(listener, uid, bin, stop.clone()));
    let client = Client {
        path,
        expected_uid: uid,
    };
    let input = [0, 255, 9, 10].repeat(256);
    let argv = vec!["echo".into(), "literal\n--flag=$()".into()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: &input,
        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
        max_output: 64,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(8),
        client.exec("abcd", &spec, &tokio_util::sync::CancellationToken::new()),
    )
    .await
    .unwrap();
    assert_eq!(outcome.finish, Ok(ExecFinish::Completed));
    assert_eq!(outcome.command_status, Some(CommandStatus::Exited(125)));
    assert_eq!(outcome.stdout.data, input[..64]);
    assert_eq!(outcome.stdout.total_bytes, input.len() as u64);
    assert!(outcome.stdout.total_bytes_known && outcome.stdout.truncated());
    assert_eq!(outcome.stderr.data, b"\x00\xfferr");
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn pre_canceled_or_expired_exec_never_connects_to_helper() {
    use crate::runtime::{ExecFinish, ExecSpec};
    let client = Client {
        path: "/nonexistent/kilnd-helper.sock".into(),
        expected_uid: 0,
    };
    let argv = vec!["true".to_owned()];
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"",
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        max_output: 1024,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let result = client.exec("abcd", &spec, &cancel).await;
    assert_eq!(result.finish, Ok(ExecFinish::Canceled));
    assert!(result.stdout.total_bytes_known);
    assert_eq!(
        result.disposition,
        crate::model::SandboxDisposition::Reusable
    );
    assert_eq!(
        result.cleanup,
        crate::model::CleanupEvidence::NoChildStarted
    );
    let spec = ExecSpec {
        deadline: tokio::time::Instant::now() - Duration::from_secs(1),
        ..spec
    };
    let result = client
        .exec("abcd", &spec, &tokio_util::sync::CancellationToken::new())
        .await;
    assert_eq!(result.finish, Ok(ExecFinish::TimedOut));
}

#[tokio::test]
async fn an_unconfirmed_helper_exec_quarantines_the_sandbox() {
    use crate::model::{CleanupEvidence, RuntimeErrorKind, SandboxDisposition};
    use crate::runtime::ExecSpec;
    let client = Client {
        path: "/nonexistent/kilnd-helper.sock".into(),
        expected_uid: 0,
    };
    let argv = vec!["true".to_owned()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"",
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        max_output: 1024,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let result = client
        .exec("abcd", &spec, &tokio_util::sync::CancellationToken::new())
        .await;
    assert_eq!(
        result.finish.unwrap_err().kind,
        RuntimeErrorKind::CleanupFailed
    );
    assert_eq!(result.disposition, SandboxDisposition::Quarantined);
    assert_eq!(result.cleanup, CleanupEvidence::Unknown);
}

#[tokio::test]
async fn stalled_capability_exchange_has_a_control_cleanup_bound() {
    use tokio::io::AsyncReadExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("stalled.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (canceled_tx, canceled_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(fds::receive(&stream).await.unwrap().is_empty());
        let _: Request = read_frame(&mut stream).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 1);
        canceled_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let client = Client {
        path,
        expected_uid: unsafe { libc::geteuid() },
    };
    let result = tokio::time::timeout(
        Duration::from_millis(1500),
        client.call(
            KilnRequest::Capabilities { id: None },
            tokio::time::Instant::now() + Duration::from_millis(100),
            &tokio_util::sync::CancellationToken::new(),
        ),
    )
    .await;
    assert!(
        result
            .expect("capability probe inherited the Exec cleanup allowance")
            .is_err()
    );
    canceled_rx.await.unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn stdio_handoff_waits_for_installed_descriptors_before_closing_sent_endpoints() {
    use std::future::Future;
    use std::task::Poll;
    use tokio::io::AsyncReadExt;
    let (helper, mut client) = UnixStream::pair().unwrap();
    helper.writable().await.unwrap();
    let mut control = socket::Socket(helper);
    let handoff = server::handoff_stdio(&mut control);
    tokio::pin!(handoff);
    // Force send-before-receive: polling to Pending sends the envelope, then
    // must retain all peers while waiting for receipt. No sleeps or scheduling
    // assumptions, and a missing receipt barrier fails on every OS.
    std::future::poll_fn(|cx| {
        assert!(
            handoff.as_mut().poll(cx).is_pending(),
            "handoff closed peers before receipt"
        );
        Poll::Ready(())
    })
    .await;
    let received = fds::receive(&client).await.unwrap();
    assert_eq!(received.len(), 3);
    std::future::poll_fn(|cx| {
        assert!(
            handoff.as_mut().poll(cx).is_pending(),
            "handoff accepted no receipt"
        );
        Poll::Ready(())
    })
    .await;
    client.write_u8(STDIO_RECEIVED).await.unwrap();
    let [mut input, mut output, mut error] = handoff.await.unwrap();
    let mut received = received
        .into_iter()
        .map(|fd| fds::socket(fd, unsafe { libc::geteuid() }).unwrap());
    let mut input_peer = received.next().unwrap();
    let mut output_peer = received.next().unwrap();
    let mut error_peer = received.next().unwrap();
    input_peer.write_all(b"in").await.unwrap();
    input_peer.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"in");
    output.write_all(b"out").await.unwrap();
    output.shutdown().await.unwrap();
    error.write_all(b"err").await.unwrap();
    error.shutdown().await.unwrap();
    bytes.clear();
    output_peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"out");
    bytes.clear();
    error_peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"err");
}

#[tokio::test]
async fn non_exec_wire_deadlines_and_cancellation_reap_children_without_false_evidence() {
    use crate::model::{Network, SandboxSpec};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncReadExt;
    use tokio::time::{Instant, timeout};
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("kiln");
    let pid_file = temp.path().join("pid");
    let trace = temp.path().join("calls");
    std::fs::write(&bin, format!(r#"#!/usr/bin/python3
import os,sys,time
CAPS=bytes.fromhex('4b494c4e45584f00010002001d0000001f000000010001000500080000000000302e312e306769742074657374')
if sys.argv[1]=='capabilities':
    os.write(1,CAPS); sys.exit(0)
if sys.argv[1:]==['gc','--help']:
    print('Usage: kiln gc [ID]...'); sys.exit(0)
open({trace:?},'a').write(sys.argv[1]+'\n')
open({pid_file:?},'w').write(str(os.getpid()))
time.sleep(30)
"#)).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.path().join("helper.sock");
    let uid = unsafe { libc::geteuid() };
    let stop = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(serve(
        tokio::net::UnixListener::bind(&path).unwrap(),
        uid,
        bin,
        stop.clone(),
    ));
    let spec = SandboxSpec {
        image: "alpine".into(),
        memory_bytes: 64 << 20,
        cpu_millis: 1000,
        pids: 64,
        disk_bytes: 16 << 20,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: Default::default(),
    };
    for cancel in [false, true] {
        for operation in [
            KilnRequest::Create { spec: spec.clone() },
            KilnRequest::Rm { id: "abcd".into() },
            KilnRequest::Ls,
            KilnRequest::Gc {
                ids: vec!["abcd".into()],
            },
        ] {
            let create = matches!(operation, KilnRequest::Create { .. });
            let timeout_ms = if cancel { 5000 } else { 1000 };
            let request = Request {
                version: VERSION,
                timeout_ms,
                deadline_ns: monotonic_ns().unwrap() + u64::from(timeout_ms) * 1_000_000,
                operation: Operation::Kiln(operation),
            };
            let mut control = UnixStream::connect(&path).await.unwrap();
            fds::send(&control, &[]).await.unwrap();
            write_frame(&mut control, &request).await.unwrap();
            assert!(fds::receive(&control).await.unwrap().is_empty());
            let began = timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(pid) = std::fs::read_to_string(&pid_file)
                        && let Ok(pid) = pid.parse::<i32>()
                    {
                        break pid;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            if cancel {
                control.write_u8(1).await.unwrap();
            }
            let end = Instant::now() + Duration::from_secs(2);
            // In the deadline case the raw client deliberately sends NO cancel
            // and keeps control open. The wire deadline itself must stop work.
            let response: Response = timeout(Duration::from_secs(2), read_frame(&mut control))
                .await
                .expect("wire bound was replaced by internal timeout")
                .unwrap();
            match response {
                Response::Error {
                    definitely_not_created,
                    ..
                } => assert!(
                    !definitely_not_created || !create,
                    "invoked create falsely proved pre-allocation failure"
                ),
                response => panic!("interrupted operation claimed success: {response:?}"),
            }
            assert_eq!(
                unsafe { libc::kill(began, 0) },
                -1,
                "child survived its response"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            assert!(
                timeout(
                    end.saturating_duration_since(Instant::now()),
                    control.read_u8()
                )
                .await
                .unwrap()
                .is_err()
            );
            std::fs::remove_file(&pid_file).unwrap();
        }
    }
    assert_eq!(
        std::fs::read_to_string(trace).unwrap(),
        "create\nrm\nls\ngc\n".repeat(2)
    );
    stop.cancel();
    server.await.unwrap().unwrap();
}

/// B6: a helper that answers one Firecracker Exec. It takes the frame, hands the three
/// stdio endpoints over, reads stdin, writes both outputs and replies `reply`.
async fn serve_one_firecracker_exec(
    listener: tokio::net::UnixListener,
    stdout: &'static [u8],
    stderr: &'static [u8],
    reply: ExecReply,
) -> (FirecrackerRequest, Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let (stream, _) = listener.accept().await.unwrap();
    assert!(fds::receive(&stream).await.unwrap().is_empty());
    let mut control = socket::Socket(stream);
    let request: Request = read_frame(&mut control.0).await.unwrap();
    request.validate(0).unwrap();
    let Operation::Firecracker(request) = request.operation else {
        panic!("not a Firecracker request");
    };
    let [mut input, mut output, mut error] = server::handoff_stdio(&mut control).await.unwrap();
    let mut stdin = Vec::new();
    input.read_to_end(&mut stdin).await.unwrap();
    output.write_all(stdout).await.unwrap();
    output.shutdown().await.unwrap();
    error.write_all(stderr).await.unwrap();
    error.shutdown().await.unwrap();
    write_frame(
        &mut control.0,
        &Response::Firecracker(FirecrackerResponse::Exec(Box::new(reply))),
    )
    .await
    .unwrap();
    control.0.shutdown().await.unwrap();
    (request, stdin)
}

fn fc_exec_request() -> FirecrackerRequest {
    FirecrackerRequest {
        group_version: FIRECRACKER_GROUP_VERSION,
        instance_id: crate::model::Id128::random(),
        connection_epoch: Some(crate::model::Id128::random()),
        operation: FirecrackerOperation::Exec {
            allocation_id: crate::model::Id128::random(),
            expected_boot_id: "00000000-0000-4000-8000-000000000001".into(),
            execution_token: crate::model::Id128::random(),
            execution_id: "ex-0123456789abcdef".into(),
            argv: vec!["cat".into()],
            stdin_bytes: 5,
            max_output: 1024,
        },
    }
}

fn capture(bytes: &[u8]) -> CaptureInfo {
    CaptureInfo {
        kept: bytes.len(),
        total: bytes.len() as u64,
        known: true,
        truncated: false,
    }
}

#[tokio::test]
async fn b6_firecracker_exec_carries_stdio_and_keeps_a_completed_session_reusable() {
    use crate::model::{CleanupEvidence, CommandStatus, SandboxDisposition};
    use crate::runtime::{ExecFinish, ExecSpec};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(serve_one_firecracker_exec(
        listener,
        b"hello",
        b"warn",
        ExecReply {
            finish: WireFinishFc::Completed,
            status: Some(CommandStatus::Exited(0)),
            stdout: capture(b"hello"),
            stderr: capture(b"warn"),
            cleanup: ExecCleanup::GuestCgroupDrained,
            reusable: true,
            dispatched: true,
        },
    ));
    let client = Client {
        path,
        expected_uid: unsafe { libc::geteuid() },
    };
    let argv = vec!["cat".to_owned()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"input",
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        max_output: 1024,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let request = fc_exec_request();
    let outcome = client
        .firecracker_exec(
            request.clone(),
            &spec,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
    let (received, stdin) = server.await.unwrap();
    assert_eq!(
        serde_json::to_value(&received).unwrap(),
        serde_json::to_value(&request).unwrap()
    );
    assert_eq!(stdin, b"input");
    assert_eq!(outcome.finish, Ok(ExecFinish::Completed));
    assert_eq!(outcome.command_status, Some(CommandStatus::Exited(0)));
    assert_eq!(outcome.stdout.data, b"hello");
    assert_eq!(outcome.stderr.data, b"warn");
    assert_eq!(outcome.disposition, SandboxDisposition::Reusable);
    assert_eq!(outcome.cleanup, CleanupEvidence::RuntimeDrained);
}

#[tokio::test]
async fn b6_a_timed_out_firecracker_exec_retires_the_session_with_host_proof() {
    use crate::model::{CleanupEvidence, SandboxDisposition};
    use crate::runtime::{ExecFinish, ExecSpec};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(serve_one_firecracker_exec(
        listener,
        b"",
        b"",
        ExecReply {
            finish: WireFinishFc::TimedOut,
            status: None,
            stdout: CaptureInfo {
                kept: 0,
                total: 0,
                known: false,
                truncated: false,
            },
            stderr: CaptureInfo {
                kept: 0,
                total: 0,
                known: false,
                truncated: false,
            },
            cleanup: ExecCleanup::VmStopped,
            reusable: false,
            dispatched: true,
        },
    ));
    let client = Client {
        path,
        expected_uid: unsafe { libc::geteuid() },
    };
    let argv = vec!["sleep".to_owned(), "60".to_owned()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"input",
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        max_output: 1024,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let outcome = client
        .firecracker_exec(
            fc_exec_request(),
            &spec,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
    server.await.unwrap();
    assert_eq!(outcome.finish, Ok(ExecFinish::TimedOut));
    assert_eq!(outcome.disposition, SandboxDisposition::Stopped);
    assert_eq!(outcome.cleanup, CleanupEvidence::SandboxStopped);
    assert!(!outcome.stdout.total_bytes_known);
}

#[test]
fn b6_firecracker_replies_are_reusable_only_with_their_own_evidence() {
    use crate::model::{CleanupEvidence, SandboxDisposition};
    use crate::runtime::ExecSpec;
    let argv = vec!["true".to_owned()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"",
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        max_output: 8,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let reply = |reusable, cleanup| ExecReply {
        finish: WireFinishFc::Completed,
        status: Some(crate::model::CommandStatus::Exited(0)),
        stdout: capture(b""),
        stderr: capture(b""),
        cleanup,
        reusable,
        dispatched: true,
    };
    for (reusable, cleanup, disposition, evidence) in [
        (
            true,
            ExecCleanup::GuestCgroupDrained,
            SandboxDisposition::Reusable,
            CleanupEvidence::RuntimeDrained,
        ),
        (
            true,
            ExecCleanup::NoChildStarted,
            SandboxDisposition::Reusable,
            CleanupEvidence::NoChildStarted,
        ),
        // A reusable claim without guest drain evidence, or a retirement without the
        // host's stop barrier, proves nothing: quarantined.
        (
            true,
            ExecCleanup::VmStopped,
            SandboxDisposition::Quarantined,
            CleanupEvidence::SandboxStopped,
        ),
        (
            true,
            ExecCleanup::Unknown,
            SandboxDisposition::Quarantined,
            CleanupEvidence::Unknown,
        ),
        (
            false,
            ExecCleanup::GuestCgroupDrained,
            SandboxDisposition::Quarantined,
            CleanupEvidence::RuntimeDrained,
        ),
        (
            false,
            ExecCleanup::Unknown,
            SandboxDisposition::Quarantined,
            CleanupEvidence::Unknown,
        ),
        (
            false,
            ExecCleanup::VmStopped,
            SandboxDisposition::Stopped,
            CleanupEvidence::SandboxStopped,
        ),
    ] {
        let outcome = client::firecracker_outcome(
            reply(reusable, cleanup),
            Vec::new(),
            Vec::new(),
            &spec,
            &cancel,
        )
        .unwrap();
        assert_eq!(
            (outcome.disposition, outcome.cleanup),
            (disposition, evidence),
            "{reusable} {cleanup:?}"
        );
    }
    // Capture evidence must describe exactly the bytes delivered.
    let mut lying = reply(true, ExecCleanup::GuestCgroupDrained);
    lying.stdout = capture(b"four");
    assert!(
        client::firecracker_outcome(lying, b"two".to_vec(), Vec::new(), &spec, &cancel).is_err()
    );
}

#[tokio::test]
async fn b6_an_unconfirmed_firecracker_exec_quarantines_the_sandbox() {
    use crate::model::{CleanupEvidence, RuntimeErrorKind, SandboxDisposition};
    use crate::runtime::ExecSpec;
    let client = Client {
        path: "/nonexistent/kilnd-helper.sock".into(),
        expected_uid: 0,
    };
    let argv = vec!["true".to_owned()];
    let spec = ExecSpec {
        argv: &argv,
        stdin: b"",
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        max_output: 1024,
        options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        live: None,
    };
    let outcome = client
        .firecracker_exec(
            fc_exec_request(),
            &spec,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
    assert_eq!(
        outcome.finish.unwrap_err().kind,
        RuntimeErrorKind::CleanupFailed
    );
    assert_eq!(outcome.disposition, SandboxDisposition::Quarantined);
    assert_eq!(outcome.cleanup, CleanupEvidence::Unknown);
}

/// API additions M3b (design 4.1): the exec options fields and the features probe on
/// the helper wire. A request without options stays byte-identical (the B2 goldens in
/// `firecracker::tests` pin it); with them, the helper accepts only the one strict form.
mod exec_options {
    use super::*;
    use kilnd_exec_core::exec_options::{EnvVar, MAX_CWD_BYTES};

    fn exec(cwd: Option<&str>, env: Vec<EnvVar>) -> Request {
        Request {
            version: VERSION,
            timeout_ms: 1000,
            deadline_ns: 5,
            operation: Operation::Kiln(KilnRequest::Exec {
                id: "abcd".into(),
                argv: vec!["true".into()],
                stdin_bytes: 0,
                max_output: 1,
                live: false,
                cwd: cwd.map(Into::into),
                env,
            }),
        }
    }

    #[test]
    fn options_frames_and_the_features_probe_have_fixed_encodings() {
        let golden = |r: &Request| serde_json::to_string(r).unwrap();
        assert_eq!(
            golden(&exec(
                Some("/w"),
                vec![EnvVar::new("A", ""), EnvVar::new("B", "2")]
            )),
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1,"cwd":"/w","env":[["A",""],["B","2"]]}}}}"#
        );
        assert_eq!(
            golden(&exec(None, vec![EnvVar::new("A", "1")])),
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1,"env":[["A","1"]]}}}}"#
        );
        // Empty options are the B2 bytes exactly.
        assert_eq!(
            golden(&exec(None, vec![])),
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1}}}}"#
        );
        for (request, json) in [
            (
                KilnRequest::Features { id: None },
                r#"{"features":{"id":null}}"#,
            ),
            (
                KilnRequest::Features {
                    id: Some("abcd".into()),
                },
                r#"{"features":{"id":"abcd"}}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&request).unwrap(), json);
            assert!(request.is_recovery());
        }
        assert_eq!(
            serde_json::to_string(&Response::Features {
                features: 0x3f,
                exec_options: true,
                exec_stream: false,
            })
            .unwrap(),
            r#"{"features":{"features":63,"exec_options":true}}"#
        );
        assert!(
            Request {
                operation: Operation::Kiln(KilnRequest::Features {
                    id: Some("../x".into())
                }),
                ..exec(None, vec![])
            }
            .validate(0)
            .is_err()
        );
    }

    #[test]
    fn the_helper_revalidates_options_at_its_ceilings_in_one_strict_form() {
        exec(Some("/"), vec![EnvVar::new("A", ""), EnvVar::new("A0", "")])
            .validate(0)
            .unwrap();
        let max_cwd = format!("/{}", "c".repeat(MAX_CWD_BYTES - 1));
        exec(Some(&max_cwd), vec![]).validate(0).unwrap();
        let entries = |n: usize| {
            (0..n)
                .map(|i| EnvVar::new(format!("V{i:02}"), ""))
                .collect()
        };
        exec(None, entries(64)).validate(0).unwrap();
        for bad in [
            exec(Some(""), vec![]),
            exec(Some("relative"), vec![]),
            exec(Some(&format!("{max_cwd}c")), vec![]),
            exec(Some("/a\0b"), vec![]),
            exec(None, entries(65)),
            exec(None, vec![EnvVar::new("B", ""), EnvVar::new("A", "")]),
            exec(None, vec![EnvVar::new("A", ""), EnvVar::new("A", "")]),
            exec(None, vec![EnvVar::new("1A", "")]),
            exec(None, vec![EnvVar::new("A", "x\0")]),
            exec(None, vec![EnvVar::new("A", "v".repeat(4097))]),
        ] {
            assert!(bad.validate(0).is_err(), "{bad:?}");
        }
        // Unknown fields are still refused, and an entry is exactly a pair.
        for text in [
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1,"cwd":"/w","flags":["-x"]}}}}"#,
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1,"env":[["A","1","x"]]}}}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn request_debug_never_shows_an_env_value() {
        let request = exec(
            Some("/w"),
            vec![EnvVar::new("TOKEN", "CANARY-helper-debug")],
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("TOKEN") && debug.contains("/w"), "{debug}");
        assert!(!debug.contains("CANARY"), "{debug}");
    }
}

/// ExecStream's helper surface (API additions design 5.1): the `live` flag, its fourth
/// descriptor, its four-hour ceiling and the features probe's `exec_stream`.
mod live_channel {
    use super::*;

    fn live_exec(live: bool, timeout_ms: u32) -> Request {
        Request {
            version: VERSION,
            timeout_ms,
            deadline_ns: 5,
            operation: Operation::Kiln(KilnRequest::Exec {
                id: "abcd".into(),
                argv: vec!["true".into()],
                stdin_bytes: 0,
                max_output: 1,
                cwd: None,
                env: Vec::new(),
                live,
            }),
        }
    }

    #[test]
    fn live_is_omitted_when_false_and_raises_only_its_own_ceiling() {
        assert_eq!(
            serde_json::to_string(&live_exec(false, 1000)).unwrap(),
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1}}}}"#
        );
        assert_eq!(
            serde_json::to_string(&live_exec(true, 1000)).unwrap(),
            r#"{"version":3,"timeout_ms":1000,"deadline_ns":5,"operation":{"kiln":{"exec":{"id":"abcd","argv":["true"],"stdin_bytes":0,"max_output":1,"live":true}}}}"#
        );
        // Decision 4: a unary exec keeps its hour; a live one may run four.
        assert!(live_exec(false, MAX_EXEC_MS).validate(0).is_ok());
        assert!(live_exec(false, MAX_EXEC_MS + 1).validate(0).is_err());
        assert!(live_exec(true, MAX_EXEC_MS + 1).validate(0).is_ok());
        assert!(live_exec(true, MAX_LIVE_EXEC_MS).validate(0).is_ok());
        assert!(live_exec(true, MAX_LIVE_EXEC_MS + 1).validate(0).is_err());
        assert_eq!(MAX_LIVE_EXEC_MS, 4 * 3600 * 1000);
        // A caller-supplied descriptor is still refused.
        assert!(live_exec(true, 1000).validate(1).is_err());
        assert_eq!(
            serde_json::to_string(&Response::Features {
                features: 0x3f,
                exec_options: true,
                exec_stream: true,
            })
            .unwrap(),
            r#"{"features":{"features":63,"exec_options":true,"exec_stream":true}}"#
        );
        let old: Response =
            serde_json::from_str(r#"{"features":{"features":63,"exec_options":true}}"#).unwrap();
        assert!(matches!(
            old,
            Response::Features {
                exec_stream: false,
                ..
            }
        ));
    }

    #[cfg(target_os = "linux")]
    fn fixture(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("kiln");
        std::fs::write(&bin, format!(r#"#!/usr/bin/python3
import os,sys,socket,time
CAPS=bytes.fromhex('4b494c4e45584f00010002001d0000001f000000010001000500080000000000302e312e306769742074657374')
STATUS=bytes.fromhex('4b494c4e45584f000100010018000000010102007d00000000000000000000000000000000000000')
if sys.argv[1]=='capabilities':
    os.write(1,CAPS); sys.exit(0)
if sys.argv[1:]==['gc','--help']:
    print('Usage: kiln gc [ID]...'); sys.exit(0)
fds={{a.split('=')[0]:int(a.split('=')[1]) for a in sys.argv[2:7]}}
OUT=fds['--stdout-fd']; ERR=fds['--stderr-fd']
{body}
os.write(fds['--status-fd'],STATUS)
sys.exit(125)
"#)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct Recording(std::sync::Mutex<Vec<(crate::exec_stream::LiveStream, u64, Vec<u8>)>>);

    #[cfg(target_os = "linux")]
    impl crate::exec_stream::LiveTap for Recording {
        fn offer(&self, stream: crate::exec_stream::LiveStream, offset: u64, bytes: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push((stream, offset, bytes.to_vec()));
        }
    }

    /// The real helper's live path: the command's bytes reach kilnd's tap at the capture
    /// readers' offsets, while the unary prefix transfer and totals are unchanged.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_live_exec_delivers_offsets_and_keeps_the_authoritative_prefix() {
        use crate::exec_stream::LiveStream;
        use crate::runtime::{ExecFinish, ExecSpec};
        let temp = tempfile::tempdir().unwrap();
        let bin = fixture(
            temp.path(),
            "for i in range(20):\n    os.write(OUT,bytes([i])*5000)\n    os.write(ERR,b'e%d' % i)\n    time.sleep(0.005)",
        );
        let path = temp.path().join("helper.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let stop = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(serve(listener, uid, bin, stop.clone()));
        let client = Client {
            path,
            expected_uid: uid,
        };
        let recording = std::sync::Arc::new(Recording::default());
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: tokio::time::Instant::now() + Duration::from_secs(10),
            max_output: 1000,
            options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            live: Some(recording.clone()),
        };
        let outcome = client
            .exec("abcd", &spec, &tokio_util::sync::CancellationToken::new())
            .await;
        assert_eq!(outcome.finish, Ok(ExecFinish::Completed));
        assert_eq!(outcome.stdout.total_bytes, 100_000);
        assert!(outcome.stdout.total_bytes_known && outcome.stdout.truncated());
        assert_eq!(outcome.stdout.data.len(), 1000);
        let seen = recording.0.lock().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for (stream, offset, bytes) in seen.iter() {
            let into = if *stream == LiveStream::Stdout {
                &mut stdout
            } else {
                &mut stderr
            };
            // Nothing reads slowly here, so nothing was dropped.
            assert_eq!(*offset, into.len() as u64);
            into.extend_from_slice(bytes);
        }
        let expected: Vec<u8> = (0..20u8).flat_map(|i| [i; 5000]).collect();
        assert_eq!(stdout, expected);
        assert_eq!(&stdout[..1000], &outcome.stdout.data[..]);
        assert_eq!(stderr.len() as u64, outcome.stderr.total_bytes);
        stop.cancel();
        task.await.unwrap().unwrap();
    }

    /// Design 8: a helper that dies after an EAGAIN drop and before settlement. The
    /// interior gap is exact by offsets, but the capture total is not known, so the
    /// tail gap and the stream's delivery say `dropped_bytes_known = false`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_helper_that_dies_after_a_drop_leaves_the_tail_unknown() {
        use crate::exec_stream::{CaptureTotal, LiveEvent, LiveQueue, LiveStream, StreamFinal};
        use crate::runtime::ExecSpec;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("helper.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let helper = tokio::spawn(async move {
            let (control, _) = listener.accept().await.unwrap();
            assert!(fds::receive(&control).await.unwrap().is_empty());
            let mut control = socket::Socket(control);
            let _request = super::super::read_frame_bytes(&mut control).await.unwrap();
            let (input, input_peer) = UnixStream::pair().unwrap();
            let (output, output_peer) = UnixStream::pair().unwrap();
            let (error, error_peer) = UnixStream::pair().unwrap();
            let (sender, receiver) = live::pair().unwrap();
            fds::send(
                &control.0,
                &[
                    input_peer.as_raw_fd(),
                    output_peer.as_raw_fd(),
                    error_peer.as_raw_fd(),
                    receiver.as_raw_fd(),
                ],
            )
            .await
            .unwrap();
            use tokio::io::AsyncReadExt;
            assert_eq!(control.read_u8().await.unwrap(), STDIO_RECEIVED);
            let sender = live::LiveSender::new(sender);
            use crate::exec_stream::LiveTap;
            sender.offer(LiveStream::Stdout, 0, b"0123456789");
            // Bytes 10..30 were dropped on EAGAIN.
            sender.offer(LiveStream::Stdout, 30, b"abc");
            let mut output = output;
            output.write_all(b"0123456789").await.unwrap();
            // The helper dies: no reply, no EOF on purpose, every descriptor closed.
            drop((control, input, output, error, sender));
        });
        let client = Client {
            path,
            expected_uid: uid,
        };
        let queue = LiveQueue::new(Default::default());
        let mut handle = queue.handle();
        let argv = vec!["ignored".into()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            max_output: 1000,
            options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            live: Some(queue.clone()),
        };
        let outcome = client
            .exec("abcd", &spec, &tokio_util::sync::CancellationToken::new())
            .await;
        helper.await.unwrap();
        assert!(outcome.finish.is_err());
        assert!(!outcome.stdout.total_bytes_known);
        let total = |c: &crate::model::Captured| CaptureTotal {
            total_bytes: c.total_bytes,
            known: c.total_bytes_known,
        };
        queue.finish(StreamFinal {
            execution: Err(crate::manager::Error::NotFound("test".into())),
            stdout: total(&outcome.stdout),
            stderr: total(&outcome.stderr),
        });
        let mut events = Vec::new();
        while let Some(event) = std::future::poll_fn(|cx| handle.poll_event(cx)).await {
            events.push(event);
        }
        let gaps: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                LiveEvent::Gap {
                    stream: LiveStream::Stdout,
                    offset,
                    dropped_bytes,
                    dropped_bytes_known,
                } => Some((*offset, *dropped_bytes, *dropped_bytes_known)),
                _ => None,
            })
            .collect();
        // The interior gap is exact; the tail after byte 33 is not known.
        assert_eq!(gaps[0], (10, 20, true));
        assert_eq!(gaps[1].0, 33);
        assert!(!gaps[1].2);
        let Some(LiveEvent::Finished { stdout, .. }) = events.last() else {
            panic!("no final message");
        };
        assert_eq!(stdout.delivered_bytes, 13);
        assert!(!stdout.dropped_bytes_known);
    }
}
