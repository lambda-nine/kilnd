use super::protocol::*;
use super::*;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

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
        id: "ab".into(),
        argv: vec!["sh\0".into()],
        stdin_bytes: 0,
        max_output: 1,
    });
    assert!(req.validate(0).is_err());
    req.operation = Operation::Kiln(KilnRequest::Exec {
        id: "ab".into(),
        argv: vec!["true".into()],
        stdin_bytes: 32,
        max_output: 1024,
    });
    assert!(req.validate(0).is_ok());
    assert!(req.validate(3).is_err());
    for version in [1, 2] {
        req.version = version;
        assert!(req.validate(0).is_err());
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
