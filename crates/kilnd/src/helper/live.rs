//! The helper's live output channel (API additions design 5.1).
//!
//! With `live` set, a kiln `exec` hands kilnd a fourth descriptor: one end of an
//! anonymous `SOCK_SEQPACKET` pair. The helper's capture readers offer every read to a
//! [`LiveSender`], which sends it as one message `[stream u8][offset u64be][bytes]` with
//! `MSG_DONTWAIT` and drops it on `EAGAIN`. The message boundary makes a drop atomic, so
//! offsets alone tell kilnd what is missing; the retained-prefix transfer after
//! settlement is unchanged and stays authoritative. kilnd's [`read_live`] validates each
//! message and offers it to the execution's queue, which never waits either.
//!
//! The channel is Linux-only: Darwin has no `SOCK_SEQPACKET` Unix sockets, so there the
//! helper proves no live output and refuses a live exec.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kilnd_exec_core::live::{LiveStream, LiveTap};

/// `[stream u8][offset u64be]`.
pub const HEADER_BYTES: usize = 9;
/// Design 7: at most 16 KiB of data per message, one capture read.
pub const MAX_LIVE_DATA: usize = 16 * 1024;
pub const MAX_LIVE_MESSAGE: usize = HEADER_BYTES + MAX_LIVE_DATA;

/// Whether this build can carry live output at all.
pub fn supported() -> bool {
    cfg!(target_os = "linux")
}

/// One message. `data` is 1 to [`MAX_LIVE_DATA`] bytes.
pub fn encode(stream: LiveStream, offset: u64, data: &[u8]) -> Vec<u8> {
    debug_assert!(!data.is_empty() && data.len() <= MAX_LIVE_DATA);
    let mut message = Vec::with_capacity(HEADER_BYTES + data.len());
    message.push(stream.code());
    message.extend_from_slice(&offset.to_be_bytes());
    message.extend_from_slice(data);
    message
}

/// Strict: a known stream byte, at least one data byte and at most [`MAX_LIVE_DATA`],
/// and an end offset that fits `u64`.
pub fn decode(message: &[u8]) -> Result<(LiveStream, u64, &[u8]), &'static str> {
    if message.len() <= HEADER_BYTES || message.len() > MAX_LIVE_MESSAGE {
        return Err("live message size outside its bounds");
    }
    let stream = LiveStream::from_code(message[0]).ok_or("unknown live stream")?;
    let offset = u64::from_be_bytes(message[1..HEADER_BYTES].try_into().expect("eight bytes"));
    let data = &message[HEADER_BYTES..];
    offset
        .checked_add(data.len() as u64)
        .ok_or("live offset overflows")?;
    Ok((stream, offset, data))
}

/// A connected anonymous `SOCK_SEQPACKET` pair, both ends close-on-exec: (the helper's
/// sending end, the end passed to kilnd).
#[cfg(target_os = "linux")]
pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two newly owned descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair succeeded and transfers each descriptor once.
    let (sender, receiver) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // The helper only sends and kilnd only receives.
    // SAFETY: shutdown only changes these owned sockets' directions.
    if unsafe { libc::shutdown(sender.as_raw_fd(), libc::SHUT_RD) } != 0
        || unsafe { libc::shutdown(receiver.as_raw_fd(), libc::SHUT_WR) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((sender, receiver))
}

#[cfg(not(target_os = "linux"))]
pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "live output needs Linux SOCK_SEQPACKET sockets",
    ))
}

/// The helper's tap. Every send is `MSG_DONTWAIT`: a full socket drops the message and
/// the reader moves on; a closed peer stops all further sends. Nothing here waits.
pub struct LiveSender {
    fd: OwnedFd,
    closed: AtomicBool,
    sent: AtomicU64,
    dropped: AtomicU64,
}

impl LiveSender {
    pub fn new(fd: OwnedFd) -> Arc<Self> {
        Arc::new(Self {
            fd,
            closed: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    /// Ends the channel: kilnd's reader sees EOF once every sent message is read, even
    /// if a reader task still holds this sender.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // SAFETY: shutdown only changes this owned socket's direction.
        unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) };
    }

    /// Messages sent and dropped so far.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    fn send(&self, message: &[u8]) {
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MSG_DONTWAIT;
        // SAFETY: the buffer is live and exactly sized; the descriptor is owned.
        let rc = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                flags,
            )
        };
        if rc == message.len() as isize {
            self.sent.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let error = io::Error::last_os_error();
        if rc < 0
            && !matches!(
                error.raw_os_error(),
                Some(libc::EAGAIN | libc::ENOBUFS | libc::EINTR)
            )
        {
            // kilnd closed its end (EPIPE, ECONNRESET): nothing more can be delivered.
            self.closed.store(true, Ordering::Relaxed);
        }
    }
}

impl LiveTap for LiveSender {
    fn offer(&self, stream: LiveStream, offset: u64, bytes: &[u8]) {
        for (n, piece) in bytes.chunks(MAX_LIVE_DATA).enumerate() {
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            self.send(&encode(stream, offset + (n * MAX_LIVE_DATA) as u64, piece));
        }
    }
}

/// kilnd's check of the fourth descriptor: an anonymous connected `AF_UNIX`
/// `SOCK_SEQPACKET` socket whose peer is `uid`.
#[cfg(target_os = "linux")]
pub fn live_socket(fd: OwnedFd, uid: u32) -> io::Result<OwnedFd> {
    let int_opt = |level, name| -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: output pointers are live and exactly sized for an int option.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    };
    if int_opt(libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
        || int_opt(libc::SOL_SOCKET, libc::SO_DOMAIN)? != libc::AF_UNIX
    {
        return Err(io::Error::other(
            "live output requires an AF_UNIX SOCK_SEQPACKET socket",
        ));
    }
    for peer in [false, true] {
        // SAFETY: zero is a valid sockaddr_un; the length matches it.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        let rc = unsafe {
            if peer {
                libc::getpeername(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_un).cast(),
                    &mut length,
                )
            } else {
                libc::getsockname(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_un).cast(),
                    &mut length,
                )
            }
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of::<libc::sa_family_t>() {
            return Err(io::Error::other(
                "live output requires an anonymous connected socket",
            ));
        }
    }
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: output pointers are live and exactly sized for SO_PEERCRED.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if credentials.uid != uid {
        return Err(io::Error::other("live output peer UID mismatch"));
    }
    // SAFETY: F_GETFL and F_SETFL only change this owned descriptor's status flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
pub fn live_socket(_fd: OwnedFd, _uid: u32) -> io::Result<OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "live output needs Linux SOCK_SEQPACKET sockets",
    ))
}

/// Reads validated live messages until EOF and offers each to `tap`. Offsets per stream
/// must not go backwards or overlap; a gap is a drop the helper made. Any violation ends
/// the channel with an error, and the rest of the output is a tail gap.
pub async fn read_live(fd: OwnedFd, tap: Arc<dyn LiveTap>) -> io::Result<()> {
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;
    // SAFETY: an owned socket stays open and names the same description for the
    // AsyncFd's whole life.
    let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut buffer = vec![0u8; MAX_LIVE_MESSAGE + 1];
    let mut next = [0u64; 2];
    loop {
        let mut ready = fd.readable().await?;
        let read = ready.try_io(|fd| {
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_DONTWAIT | libc::MSG_TRUNC;
            #[cfg(not(target_os = "linux"))]
            let flags = libc::MSG_DONTWAIT;
            // SAFETY: the buffer is live and exactly sized; the descriptor is owned.
            let n = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    flags,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        let n = match read {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        };
        if n > MAX_LIVE_MESSAGE {
            return Err(io::Error::other("oversized live message"));
        }
        let (stream, offset, data) = decode(&buffer[..n]).map_err(io::Error::other)?;
        let i = usize::from(stream == LiveStream::Stderr);
        if offset < next[i] {
            return Err(io::Error::other("live offsets went backwards"));
        }
        next[i] = offset + data.len() as u64;
        tap.offer(stream, offset, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    struct Noop;

    #[cfg(target_os = "linux")]
    impl LiveTap for Noop {
        fn offer(&self, _: LiveStream, _: u64, _: &[u8]) {}
    }

    #[test]
    fn messages_are_exact_and_strict() {
        let message = encode(LiveStream::Stderr, 0x0102_0304_0506_0708, b"hi");
        assert_eq!(message, b"\x02\x01\x02\x03\x04\x05\x06\x07\x08hi");
        assert_eq!(
            decode(&message).unwrap(),
            (LiveStream::Stderr, 0x0102_0304_0506_0708, &b"hi"[..])
        );
        let full = encode(LiveStream::Stdout, 7, &[0; MAX_LIVE_DATA]);
        assert_eq!(full.len(), MAX_LIVE_MESSAGE);
        assert!(decode(&full).is_ok());
        let mut over = full.clone();
        over.push(0);
        for bad in [
            &b""[..],
            &b"\x01\0\0\0\0\0\0\0\0"[..],
            &b"\x03\0\0\0\0\0\0\0\0x"[..],
            &b"\x00\0\0\0\0\0\0\0\0x"[..],
            &b"\x01\xff\xff\xff\xff\xff\xff\xff\xffx"[..],
            &over[..],
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct Recording(std::sync::Mutex<Vec<(LiveStream, u64, Vec<u8>)>>);

    #[cfg(target_os = "linux")]
    impl LiveTap for Recording {
        fn offer(&self, stream: LiveStream, offset: u64, bytes: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push((stream, offset, bytes.to_vec()));
        }
    }

    /// The helper's sends never wait: a full socket drops whole messages, and kilnd's
    /// reader sees the survivors in order with their own offsets, then EOF at close.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_full_channel_drops_whole_messages_without_waiting() {
        let (sender, receiver) = pair().unwrap();
        let receiver = live_socket(receiver, unsafe { libc::geteuid() }).unwrap();
        let sender = LiveSender::new(sender);
        let started = std::time::Instant::now();
        let chunk = vec![7u8; MAX_LIVE_DATA];
        let mut offset = 0u64;
        // Far more than any socket buffer holds, with nobody reading.
        for _ in 0..4096 {
            sender.offer(LiveStream::Stdout, offset, &chunk);
            offset += chunk.len() as u64;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let (sent, dropped) = sender.counts();
        assert!(sent > 0 && dropped > 0, "sent {sent}, dropped {dropped}");
        assert_eq!(sent + dropped, 4096);
        sender.offer(LiveStream::Stderr, 0, b"late");
        sender.close();
        let recording = Arc::new(Recording::default());
        read_live(receiver, recording.clone()).await.unwrap();
        let seen = std::mem::take(&mut *recording.0.lock().unwrap());
        let mut last = 0;
        let mut stdout = 0;
        for (stream, at, bytes) in seen.iter() {
            if *stream == LiveStream::Stdout {
                assert!(*at >= last && at % MAX_LIVE_DATA as u64 == 0);
                assert_eq!(bytes.len(), MAX_LIVE_DATA);
                last = at + bytes.len() as u64;
                stdout += 1;
            }
        }
        assert_eq!(
            stdout,
            sent - u64::from(seen.iter().any(|(s, _, _)| *s == LiveStream::Stderr))
        );
    }

    /// An oversized offer becomes several messages, each with its own offset; a peer
    /// that closed stops further sends.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn large_offers_split_and_a_closed_reader_stops_sends() {
        let (sender, receiver) = pair().unwrap();
        let sender = LiveSender::new(sender);
        sender.offer(LiveStream::Stdout, 5, &vec![1u8; MAX_LIVE_DATA * 2 + 3]);
        sender.close();
        let recording = Arc::new(Recording::default());
        read_live(receiver, recording.clone()).await.unwrap();
        let offsets: Vec<_> = recording
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(_, at, b)| (*at, b.len()))
            .collect();
        assert_eq!(
            offsets,
            [
                (5, MAX_LIVE_DATA),
                (5 + MAX_LIVE_DATA as u64, MAX_LIVE_DATA),
                (5 + 2 * MAX_LIVE_DATA as u64, 3)
            ]
        );
        let (sender, receiver) = pair().unwrap();
        let sender = LiveSender::new(sender);
        drop(receiver);
        sender.offer(LiveStream::Stdout, 0, b"a");
        sender.offer(LiveStream::Stdout, 1, b"b");
        assert_eq!(sender.counts(), (0, 1));
    }

    /// kilnd refuses a non-SEQPACKET descriptor, a foreign peer, and messages whose
    /// offsets go backwards.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_reader_refuses_wrong_sockets_and_backward_offsets() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(live_socket(OwnedFd::from(a), unsafe { libc::geteuid() }).is_err());
        let (_s, r) = pair().unwrap();
        assert!(live_socket(r, unsafe { libc::geteuid() } + 1).is_err());
        let (sender, receiver) = pair().unwrap();
        let sender = LiveSender::new(sender);
        sender.offer(LiveStream::Stdout, 10, b"abc");
        sender.offer(LiveStream::Stdout, 11, b"x");
        sender.close();
        let recording = Arc::new(Recording::default());
        assert!(read_live(receiver, recording.clone()).await.is_err());
        assert_eq!(recording.0.lock().unwrap().len(), 1);
    }

    /// From the M4 break-it: two producers keep the live socket readable without pause;
    /// the reader still yields, so a sibling task on the same current-thread runtime runs.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn continuously_readable_live_socket_does_not_monopolize_the_runtime() {
        use std::os::fd::FromRawFd;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::time::Duration;

        let (sender, receiver) = pair().unwrap();
        let receiver = live_socket(receiver, unsafe { libc::geteuid() }).unwrap();
        let duplicate = unsafe { libc::dup(sender.as_raw_fd()) };
        assert!(duplicate >= 0);
        let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let stop = Arc::new(AtomicBool::new(false));
        let producer = |fd: OwnedFd, stream: LiveStream, stop: Arc<AtomicBool>| {
            std::thread::spawn(move || {
                let mut offset = 0u64;
                let mut message = vec![0u8; MAX_LIVE_MESSAGE];
                message[0] = stream.code();
                while !stop.load(Ordering::Relaxed) {
                    message[1..HEADER_BYTES].copy_from_slice(&offset.to_be_bytes());
                    let rc = unsafe {
                        libc::send(
                            fd.as_raw_fd(),
                            message.as_ptr().cast(),
                            message.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                    if rc == message.len() as isize {
                        offset += MAX_LIVE_DATA as u64;
                    } else {
                        std::thread::yield_now();
                    }
                }
            })
        };
        let a = producer(sender, LiveStream::Stdout, stop.clone());
        let b = producer(duplicate, LiveStream::Stderr, stop.clone());
        std::thread::sleep(Duration::from_millis(20));

        let beats = Arc::new(AtomicU64::new(0));
        let heartbeat = {
            let beats = beats.clone();
            tokio::spawn(async move {
                loop {
                    beats.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
        };
        tokio::task::yield_now().await;
        let before = beats.load(Ordering::Relaxed);
        let stopper = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                stop.store(true, Ordering::Relaxed);
            })
        };
        read_live(receiver, Arc::new(Noop)).await.unwrap();
        let after = beats.load(Ordering::Relaxed);
        heartbeat.abort();
        stopper.join().unwrap();
        a.join().unwrap();
        b.join().unwrap();
        assert!(
            after > before,
            "the live reader monopolized the current-thread runtime for the entire flood"
        );
    }
}
