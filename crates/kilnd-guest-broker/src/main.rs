//! `kilnd-guest-broker`: the guest side of broker protocol version 1 (design 5).
//!
//! `/init` starts it once per cold boot as guest root, outside kiln's sandbox, with a
//! cleared environment, no new privileges, no core dumps, `/dev/null` stdin and the
//! bootstrap record on descriptor 3: the vdc identity block and `/init`'s hardening
//! results. It never restarts: `/init` powers the VM off when it exits. It listens on
//! AF_VSOCK port 5252 with a backlog of 4, accepts only the host (CID 2), keeps at most
//! two connections, and offers only typed initialization, probing and kiln execution
//! of the one persistent sandbox through `/usr/local/bin/kiln`.

// The transport and state machine are portable and unit-tested on macOS; only the
// AF_VSOCK listener and the guest's own facts are Linux.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod kiln;
mod server;
mod session;

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::main() {
        eprintln!("kilnd-guest-broker: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("kilnd-guest-broker runs only inside the Linux guest");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll, ready};

    use kilnd_broker_protocol::identity::{BOOTSTRAP_BYTES, hardening_from_mask, parse_bootstrap};
    use kilnd_broker_protocol::message::WorkMount;
    use kilnd_broker_protocol::{BROKER_PORT, BootId, HOST_CID, Hex32, WorkUuid};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::time::Instant;

    use crate::kiln::{CGROUP_ROOT, KILN, Kiln};
    use crate::server::{Shared, serve};
    use crate::session::{Facts, Session};

    const BOOTSTRAP_FD: RawFd = 3;
    const SELF: &str = "/usr/local/bin/kilnd-guest-broker";
    const WORK_MOUNT: &str = "/var/lib/kiln/runs";
    const WORK_DEVICE: &str = "/dev/vdb";
    const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
    const MOUNTINFO: &str = "/proc/self/mountinfo";
    const BACKLOG: i32 = 4;
    const MAX_CONNECTIONS: usize = 2;

    fn bounded_read(mut file: impl Read, limit: usize) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::other("input exceeds its bound"));
        }
        Ok(bytes)
    }

    /// `/init`'s record on descriptor 3, read to EOF: exactly 4104 bytes.
    fn bootstrap() -> io::Result<(kilnd_broker_protocol::message::GuestIdentity, u32)> {
        // SAFETY: /init hands this process descriptor 3 and nothing else owns it.
        let file = unsafe { std::fs::File::from_raw_fd(BOOTSTRAP_FD) };
        let bytes = bounded_read(file, BOOTSTRAP_BYTES)?;
        parse_bootstrap(&bytes).map_err(io::Error::other)
    }

    fn boot_id() -> io::Result<BootId> {
        let text = String::from_utf8(bounded_read(std::fs::File::open(BOOT_ID)?, 64)?)
            .map_err(io::Error::other)?;
        BootId::new(text.trim()).ok_or_else(|| io::Error::other("malformed boot ID"))
    }

    /// The work disk as this kernel sees it: the XFS superblock's UUID, and the mount's
    /// flags and project quota.
    fn work_mount() -> io::Result<WorkMount> {
        let mut superblock = [0u8; 48];
        std::fs::File::open(WORK_DEVICE)?.read_exact(&mut superblock)?;
        if &superblock[..4] != b"XFSB" {
            return Err(io::Error::other("the work disk is not XFS"));
        }
        let u = &superblock[32..48];
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            hex(&u[0..4]),
            hex(&u[4..6]),
            hex(&u[6..8]),
            hex(&u[8..10]),
            hex(&u[10..16])
        );
        let uuid = WorkUuid::new(uuid).ok_or_else(|| io::Error::other("work UUID shape"))?;
        let mountinfo = String::from_utf8(bounded_read(std::fs::File::open(MOUNTINFO)?, 1 << 20)?)
            .map_err(io::Error::other)?;
        let line = mountinfo
            .lines()
            .rfind(|line| line.split(' ').nth(4) == Some(WORK_MOUNT))
            .ok_or_else(|| io::Error::other("the work disk is not mounted"))?;
        let mut halves = line.splitn(2, " - ");
        let mount_options: Vec<&str> = halves
            .next()
            .and_then(|head| head.split(' ').nth(5))
            .unwrap_or("")
            .split(',')
            .collect();
        let super_options: Vec<&str> = halves
            .next()
            .and_then(|tail| tail.split(' ').nth(2))
            .unwrap_or("")
            .split(',')
            .collect();
        Ok(WorkMount {
            uuid,
            nosuid: mount_options.contains(&"nosuid"),
            nodev: mount_options.contains(&"nodev"),
            noexec: mount_options.contains(&"noexec"),
            prjquota: super_options.contains(&"prjquota") || super_options.contains(&"pquota"),
        })
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn own_digest() -> io::Result<Hex32> {
        Ok(Hex32::sha256(&bounded_read(
            std::fs::File::open(SELF)?,
            64 << 20,
        )?))
    }

    fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
        // SAFETY: an OwnedFd stays open and names the same open file description until
        // the AsyncFd that owns it drops it.
        Ok(unsafe { AsyncFd::register(fd) }?)
    }

    /// A nonblocking AF_VSOCK stream socket.
    pub struct Vsock(AsyncFd<OwnedFd>);

    impl Vsock {
        fn listen() -> io::Result<Self> {
            // SAFETY: plain socket creation; the result is checked.
            let fd = cvt(unsafe {
                libc::socket(
                    libc::AF_VSOCK,
                    libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            })?;
            // SAFETY: the kernel returned a new descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: zero is a valid sockaddr_vm before the fields are set.
            let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
            address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            address.svm_port = BROKER_PORT;
            address.svm_cid = libc::VMADDR_CID_ANY;
            // SAFETY: address is a live sockaddr_vm of the stated size.
            cvt(unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_vm).cast(),
                    std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            })?;
            // SAFETY: a bound stream socket.
            cvt(unsafe { libc::listen(fd.as_raw_fd(), BACKLOG) })?;
            Ok(Self(register(fd)?))
        }

        /// The next connection and its peer CID.
        async fn accept(&self) -> io::Result<(Self, u32)> {
            loop {
                let mut guard = self.0.readable().await?;
                // SAFETY: zero is a valid sockaddr_vm; the kernel fills it.
                let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
                let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
                // SAFETY: peer and len describe a live buffer.
                let rc = unsafe {
                    libc::accept4(
                        self.0.as_raw_fd(),
                        (&mut peer as *mut libc::sockaddr_vm).cast(),
                        &mut len,
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if rc < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    if error.kind() == io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::ECONNABORTED)
                    {
                        continue;
                    }
                    return Err(error);
                }
                // SAFETY: the kernel returned a new connected descriptor.
                let fd = unsafe { OwnedFd::from_raw_fd(rc) };
                return Ok((Self(register(fd)?), peer.svm_cid));
            }
        }
    }

    impl AsyncRead for Vsock {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.0.poll_read_ready(cx))?;
                let unfilled = buf.initialize_unfilled();
                // SAFETY: unfilled is a writable buffer of the stated length.
                let rc = unsafe {
                    libc::read(
                        self.0.as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if rc >= 0 {
                    buf.advance(rc as usize);
                    return Poll::Ready(Ok(()));
                }
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock => guard.clear_ready(),
                    io::ErrorKind::Interrupted => {}
                    _ => return Poll::Ready(Err(error)),
                }
            }
        }
    }

    impl AsyncWrite for Vsock {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.0.poll_write_ready(cx))?;
                // SAFETY: data is readable for its length; MSG_NOSIGNAL avoids SIGPIPE.
                let rc = unsafe {
                    libc::send(
                        self.0.as_raw_fd(),
                        data.as_ptr().cast(),
                        data.len(),
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };
                if rc >= 0 {
                    return Poll::Ready(Ok(rc as usize));
                }
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::WouldBlock => guard.clear_ready(),
                    io::ErrorKind::Interrupted => {}
                    _ => return Poll::Ready(Err(error)),
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            // SAFETY: half-closing this process's own socket.
            Poll::Ready(cvt(unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR) }).map(drop))
        }
    }

    pub fn main() -> io::Result<()> {
        let (identity, mask) = bootstrap()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let kiln = Kiln::new(KILN.into(), CGROUP_ROOT.into());
            let probed = kiln.probe().await;
            if let Err(error) = &probed {
                eprintln!("kilnd-guest-broker: kiln capability probe failed: {error}");
            }
            let facts = Facts {
                identity,
                boot_id: boot_id()?,
                broker_sha256: own_digest()?,
                hardening: hardening_from_mask(mask),
                work: work_mount()?,
                kiln: probed.ok(),
            };
            if facts.work.uuid != facts.identity.work_uuid {
                return Err(io::Error::other("the work disk is not this session's"));
            }
            let shared = Rc::new(Shared::new(Session::new(facts), kiln));
            let listener = Vsock::listen()?;
            eprintln!("kilnd-guest-broker: listening on vsock port {BROKER_PORT}");
            let open = Rc::new(std::cell::Cell::new(0usize));
            loop {
                let (stream, cid) = listener.accept().await?;
                // Refused before a byte is read: any peer but the host, and any
                // connection beyond two.
                if cid != HOST_CID || open.get() >= MAX_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                open.set(open.get() + 1);
                let accepted = Instant::now();
                let shared = shared.clone();
                let open = open.clone();
                tokio::task::spawn_local(async move {
                    if let Err(error) = serve(shared, stream, accepted).await {
                        eprintln!("kilnd-guest-broker: connection ended: {error}");
                    }
                    open.set(open.get() - 1);
                });
            }
        })
    }
}
