//! Per-syscall nonblocking I/O, independent of mutable open-file-description flags.
use std::io;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::UnixStream;

pub(in crate::helper) struct Socket(pub UnixStream);

impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            ready!(self.0.poll_read_ready(cx))?;
            let result = self.0.try_io(Interest::READABLE, || {
                let bytes = buffer.initialize_unfilled();
                // SAFETY: bytes is writable for its length and the socket is owned.
                let n = unsafe {
                    libc::recv(
                        self.0.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Ok(n) => {
                    buffer.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            let result = self.0.try_io(Interest::WRITABLE, || {
                // SAFETY: bytes is readable for its length and the socket is owned.
                let n = unsafe {
                    libc::send(
                        self.0.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // AF_UNIX shutdown(SHUT_WR) signals EOF without draining queued bytes.
        // It does not wait on the peer or O_NONBLOCK (unlike a write or linger-close).
        let rc = unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR) };
        Poll::Ready(if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        })
    }
}
