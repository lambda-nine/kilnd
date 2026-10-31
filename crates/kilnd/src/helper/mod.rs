//! Minimal private root-helper transport; it never decodes gRPC or opens SQLite.
mod client;
mod fds;
pub mod firecracker;
pub(crate) mod protocol;
mod server;
mod socket;
pub(crate) use client::{AttachedConnection, Client};
use serde::{Serialize, de::DeserializeOwned};
pub use server::{serve, serve_with_firecracker};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn read_frame_bytes(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > protocol::MAX_FRAME {
        return Err(io::Error::other("helper frame size exceeded"));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn read_frame<T: DeserializeOwned>(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<T> {
    let bytes = read_frame_bytes(stream).await?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > protocol::MAX_FRAME {
        return Err(io::Error::other("helper frame size exceeded"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

fn io_stage(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

#[cfg(test)]
mod tests;

fn monotonic_ns() -> io::Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|n| n.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| io::Error::other("monotonic clock overflow"))
}
