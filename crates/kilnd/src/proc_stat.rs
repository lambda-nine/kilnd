//! `/proc/PID/stat`, read as bytes (and [`lines`] for the other procfs files read so).
//! Its second field is the process's command name in parentheses, and the process chose
//! it (`prctl(PR_SET_NAME)`, or an executable run through a link of that name): the
//! kernel copies it raw, so it may hold spaces, parentheses, newlines and bytes that
//! aren't UTF-8. Every field after it is the kernel's own ASCII: a state letter, then
//! numbers, none of which holds `)`.

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

/// A procfs file's lines, as bytes, split exactly as `str::lines` splits text (at `\n`,
/// dropping a `\r` just before it). For the files whose text a process controls in part
/// (`status`'s `Name:`, a mount's path in `mountinfo`, a cgroup's name), read as bytes so
/// that a value that isn't UTF-8 fails only what parses it, never the whole read.
pub fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|b| *b == b'\n')
        .map(|line| match line.strip_suffix(b"\n") {
            Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
            None => line,
        })
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

    /// What the text readers this replaced (B5) took from a `stat` record: the fields
    /// after its last `)`. On every record the kernel can write (a command name of up to
    /// 15 bytes, then `") "` and its own ASCII fields) `fields` reads the same.
    #[test]
    fn fields_read_what_the_text_parsers_read_on_every_kernel_record() {
        let text_fields = |stat: &str| -> Vec<String> {
            let tail = stat.rfind(')').map_or("", |at| &stat[at + 1..]);
            tail.split_whitespace().map(str::to_owned).collect()
        };
        let alphabet = ["a", " ", "(", ")", "\n", "Z", "é", ") ", "\t"];
        let mut names = vec![String::new()];
        for _ in 0..4 {
            let longer: Vec<String> = names
                .iter()
                .flat_map(|n| alphabet.iter().map(move |c| format!("{n}{c}")))
                .filter(|n| n.len() <= 15)
                .collect();
            names.extend(longer);
        }
        names.sort();
        names.dedup();
        let mut checked = 0;
        for name in &names {
            for (state, start) in [("S", 1234u64), ("T", 1), ("Z", 0), ("R", u64::MAX)] {
                let rest: Vec<String> = (4..=52)
                    .map(|n| {
                        if n == 22 {
                            start.to_string()
                        } else {
                            n.to_string()
                        }
                    })
                    .collect();
                let stat = format!("4242 ({name}) {state} {}\n", rest.join(" "));
                let ours: Vec<String> = fields(stat.as_bytes())
                    .unwrap()
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                assert_eq!(ours, text_fields(&stat), "{stat:?}");
                assert_eq!(
                    (ours[0].as_str(), ours[19].parse::<u64>().ok()),
                    (state, Some(start))
                );
                checked += 1;
            }
        }
        assert!(checked > 20_000, "{checked}");
    }

    /// `lines` splits as `str::lines` on every text, and keeps bytes that aren't UTF-8.
    #[test]
    fn lines_split_as_str_lines_split() {
        let texts = [
            "",
            "\n",
            "\n\n",
            "a",
            "a\n",
            "a\nb",
            "a\nb\n",
            "a\r\nb\r\n",
            "a\r",
            "a\rb\n",
            "\r\n",
            "\r",
            "a\n\r\n\nb",
            "Name:\tx y\nUid:\t1\t2\t3\t4\n",
            "é\r\n€\n",
        ];
        for text in texts {
            let bytes: Vec<&[u8]> = lines(text.as_bytes()).collect();
            let expected: Vec<&[u8]> = text.lines().map(str::as_bytes).collect();
            assert_eq!(bytes, expected, "{text:?}");
        }
        let raw: Vec<&[u8]> = lines(b"Name:\t\xff\r\nUid:\t0\n\xfe").collect();
        assert_eq!(raw, [&b"Name:\t\xff"[..], b"Uid:\t0", b"\xfe"]);
    }
}
