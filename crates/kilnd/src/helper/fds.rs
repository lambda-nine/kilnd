//! SCM_RIGHTS envelope. Only anonymous Unix stream sockets may cross the boundary.
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::Interest;
use tokio::net::UnixStream;

const MARKER: u8 = 0x4b;

pub async fn send(stream: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    stream
        .async_io(Interest::WRITABLE, || {
            let mut marker = MARKER;
            let mut iov = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0usize; 16];
            // SAFETY: zero is a valid initial msghdr; all pointers below are live.
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                if fds.len() > 3 {
                    return Err(io::Error::other("too many descriptors"));
                }
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen =
                    unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as _) } as _;
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as _) as _;
                    std::ptr::copy_nonoverlapping(
                        fds.as_ptr(),
                        libc::CMSG_DATA(cmsg).cast(),
                        fds.len(),
                    );
                }
            }
            let rc = unsafe {
                libc::sendmsg(
                    stream.as_raw_fd(),
                    &msg,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if rc == 1 {
                Ok(())
            } else if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Err(io::Error::other("short descriptor envelope"))
            }
        })
        .await
}

pub async fn receive(stream: &UnixStream) -> io::Result<Vec<OwnedFd>> {
    stream
        .async_io(Interest::READABLE, || {
            let mut marker = 0u8;
            let mut iov = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0usize; 16];
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = size_of::<[usize; 16]>() as _;
            #[cfg(target_os = "linux")]
            let flags = libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT;
            #[cfg(not(target_os = "linux"))]
            let flags = libc::MSG_DONTWAIT;
            let rc = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, flags) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut fds = Vec::new();
            let mut unknown = false;
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    {
                        let len =
                            ((*cmsg).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                        for i in 0..len / size_of::<RawFd>() {
                            let fd = *libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i);
                            // Own every installed descriptor even on rejected/truncated messages.
                            fds.push(OwnedFd::from_raw_fd(fd));
                            if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
                                unknown = true;
                            }
                        }
                    } else {
                        unknown = true;
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }
            if rc != 1
                || marker != MARKER
                || unknown
                || msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
                || fds.len() > 3
            {
                return Err(io::Error::other("invalid descriptor envelope"));
            }
            Ok(fds)
        })
        .await
}

pub fn socket(fd: OwnedFd, uid: u32) -> io::Result<UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: output pointers are live and exactly sized for SO_TYPE.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(io::Error::other("stdio requires SOCK_STREAM"));
    }
    // local_addr/peer_addr also reject non-socket and non-AF_UNIX descriptors.
    if !stream.local_addr()?.is_unnamed() || !stream.peer_addr()?.is_unnamed() {
        return Err(io::Error::other(
            "stdio requires anonymous connected Unix sockets",
        ));
    }
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    if stream.peer_cred()?.uid() != uid {
        return Err(io::Error::other("stdio peer UID mismatch"));
    }
    Ok(stream)
}
