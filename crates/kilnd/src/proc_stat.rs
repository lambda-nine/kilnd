//! `/proc/PID/stat`, read as bytes. Its second field is the process's command name in
//! parentheses, and the process chose it (`prctl(PR_SET_NAME)`, or an executable run
//! through a link of that name): the kernel copies it raw, so it may hold spaces,
//! parentheses, newlines and bytes that aren't UTF-8. Every field after it is the
//! kernel's own ASCII: a state letter, then numbers, none of which holds `)`.

use std::io;

/// The fields of `stat` from field 3 (the state) on: `fields(stat)?[n - 3]` is field
/// `n`. They follow the command name's last `") "`, the kernel's closing parenthesis
/// whatever the name holds; only they are parsed as text, so no command name fails the
/// parse.
pub fn fields(stat: &[u8]) -> io::Result<Vec<&str>> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed stat");
    let end = stat.windows(2).rposition(|w| w == b") ").ok_or_else(malformed)?;
    let rest = std::str::from_utf8(&stat[end + 2..]).map_err(|_| malformed())?;
    Ok(rest.split_whitespace().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fields_follow_the_last_parenthesis_whatever_the_name_holds() {
        let f = fields(b"4242 (\xfe) (x) \xff\n) S 3000 4242 77 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 1234 1").unwrap();
        assert_eq!((f[0], f[1], f[3], f[19]), ("S", "3000", "77", "1234"));
        assert_eq!(fields(b"1 (a)) R 0").unwrap(), ["R", "0"]);
        assert!(fields(b"4242 (kiln").is_err());
        assert!(fields(b"4242 (k) S \xff 1").is_err());
    }
}
