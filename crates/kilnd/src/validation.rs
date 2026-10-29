//! Backend-neutral request validation at kilnd's API/runtime boundary.

use std::net::Ipv4Addr;

pub const MAX_ARGC: usize = 4096;
pub const MAX_ENCODED_ARGV_BYTES: usize = 1024 * 1024;
pub const MAX_ALLOWLIST_ENTRIES: usize = 64;
pub const MAX_ALLOWLIST_ENTRY_BYTES: usize = 260;
pub const MAX_IMAGE_BYTES: usize = 128;
pub const MAX_WRITABLE_PATHS: usize = 16;
pub const MAX_WRITABLE_PATH_BYTES: usize = 1024;

pub fn validate_image_name(image: &str) -> Result<(), String> {
    if image.is_empty()
        || image.len() > MAX_IMAGE_BYTES
        || image.starts_with(['.', '-'])
        || !image
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(format!("invalid image name {image:?}"));
    }
    Ok(())
}

/// Validates `HOST[:PORT]` or `IPv4[/PREFIX][:PORT]` without resolving it.
pub fn validate_allowlist_entry(entry: &str) -> Result<(), String> {
    let invalid = || format!("invalid allowlist entry {entry:?}");
    if entry.is_empty() || entry.len() > MAX_ALLOWLIST_ENTRY_BYTES {
        return Err(invalid());
    }
    let (destination, port) = match entry.rsplit_once(':') {
        Some((destination, port)) if !destination.contains(':') => (destination, Some(port)),
        Some(_) => return Err(invalid()),
        None => (entry, None),
    };
    if port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|port| *port != 0).is_none()
    }) {
        return Err(invalid());
    }
    if destination.is_empty() {
        return Err(invalid());
    }
    if let Some((address, prefix)) = destination.split_once('/') {
        if address.is_empty()
            || prefix.is_empty()
            || prefix.contains('/')
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            || address.parse::<Ipv4Addr>().is_err()
            || prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 32).is_none()
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if destination.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if destination.len() > 253 || destination.starts_with('.') || destination.ends_with('.') {
        return Err(invalid());
    }
    for label in destination.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn validate_writable_path(path: &str) -> Result<(), String> {
    let invalid = || format!("invalid writable path {path:?}");
    if path.len() > MAX_WRITABLE_PATH_BYTES
        || path == "/"
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    if path[1..]
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid());
    }
    Ok(())
}

/// Returns the API's argv byte accounting: UTF-8 bytes plus one separator per
/// argument. Control characters are literal argv data; only NUL is forbidden.
pub fn validate_argv(argv: &[String], max_bytes: usize) -> Result<usize, String> {
    if argv.len() > MAX_ARGC {
        return Err(format!("argv exceeds the limit of {MAX_ARGC} arguments"));
    }
    if argv.is_empty() || argv[0].is_empty() {
        return Err("argv must name a program".into());
    }
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err("argv must not contain NUL bytes".into());
    }
    let size = argv.iter().try_fold(0usize, |total, arg| {
        total.checked_add(arg.len()).and_then(|n| n.checked_add(1))
    });
    let Some(size) = size else {
        return Err("argv byte count overflow".into());
    };
    if size > max_bytes {
        return Err(format!("argv is {size} bytes; the limit is {max_bytes}"));
    }
    let encoded = argv.iter().try_fold(4usize, |total, arg| {
        total.checked_add(4).and_then(|n| n.checked_add(arg.len()))
    });
    let Some(encoded) = encoded else {
        return Err("encoded argv byte count overflow".into());
    };
    if encoded > MAX_ENCODED_ARGV_BYTES {
        return Err(format!(
            "encoded argv is {encoded} bytes; the backend-neutral limit is {MAX_ENCODED_ARGV_BYTES}"
        ));
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_names_are_ascii_basenames() {
        for valid in ["alpine", "agent_3.20-x"] {
            validate_image_name(valid).unwrap();
        }
        for invalid in ["", ".hidden", "-flag", "../etc", "snow-雪", "a/b"] {
            assert!(validate_image_name(invalid).is_err(), "{invalid:?}");
        }
        assert!(validate_image_name(&"a".repeat(MAX_IMAGE_BYTES)).is_ok());
        assert!(validate_image_name(&"a".repeat(MAX_IMAGE_BYTES + 1)).is_err());
    }

    #[test]
    fn allowlist_grammar_is_structural_and_ipv4_only() {
        let longest_host = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(longest_host.len(), 253);
        validate_allowlist_entry(&format!("{longest_host}:65535")).unwrap();
        assert!(validate_allowlist_entry(&format!("{longest_host}x")).is_err());
        assert!(validate_allowlist_entry(&format!("{}.example", "a".repeat(64))).is_err());
        for valid in [
            "example.com",
            "sub-domain.example:443",
            "127.0.0.1",
            "10.0.0.0/8",
            "10.0.0.0/8:53",
        ] {
            validate_allowlist_entry(valid).unwrap();
        }
        for invalid in [
            "",
            "/",
            "-flag",
            "bad..example",
            ".example",
            "example.",
            "example.com:0",
            "example.com:+80",
            "example.com:65536",
            "10.0.0.1/33",
            "10.0.0.1/",
            "10.0.0.1/+8",
            "::1",
            "snow.雪",
            "bad_name.example",
        ] {
            assert!(validate_allowlist_entry(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn writable_paths_are_absolute_canonical_and_not_root() {
        validate_writable_path(&format!("/{}", "a".repeat(MAX_WRITABLE_PATH_BYTES - 1)))
            .unwrap();
        assert!(
            validate_writable_path(&format!("/{}", "a".repeat(MAX_WRITABLE_PATH_BYTES))).is_err()
        );
        for valid in ["/data", "/workspace/雪", "/a/-flag"] {
            validate_writable_path(valid).unwrap();
        }
        for invalid in ["", "/", "data", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb"] {
            assert!(validate_writable_path(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn argv_counts_utf8_bytes_and_preserves_non_nul_controls() {
        let argv = ["echo".into(), "雪\n-flag".into(), String::new()];
        assert_eq!(validate_argv(&argv, 32).unwrap(), 5 + 10 + 1);
        assert!(validate_argv(&["echo".into(), "a\0b".into()], 32).is_err());
        assert!(validate_argv(&Vec::new(), 32).is_err());
        assert!(validate_argv(&[String::new()], 32).is_err());
        assert!(validate_argv(&vec!["x".into(); MAX_ARGC + 1], usize::MAX).is_err());
        let exact = ["x".repeat(MAX_ENCODED_ARGV_BYTES - 8)];
        assert_eq!(validate_argv(&exact, usize::MAX).unwrap(), exact[0].len() + 1);
        let too_large = ["x".repeat(MAX_ENCODED_ARGV_BYTES)];
        assert!(validate_argv(&too_large, usize::MAX).is_err());
    }
}
