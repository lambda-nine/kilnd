# Request validation contract

kilnd validates requests before it creates a lifecycle row or invokes a
runtime backend. kiln independently validates the values it accepts. This is
the shared contract at that boundary; invalid API values return gRPC
`INVALID_ARGUMENT` and have no backend or database side effects.

| Field | Accepted form |
|---|---|
| Sandbox ID | `sb-` followed by exactly 16 lowercase hexadecimal digits |
| Execution ID | `ex-` followed by exactly 16 lowercase hexadecimal digits |
| Image | Empty selects the daemon default; effective names are 1–128 ASCII bytes: letters, digits, `-`, `_`, or `.`; the first byte is not `-` or `.` |
| Allowlist | At most 64 entries, each at most 260 ASCII bytes: `HOST[:PORT]` or `IPv4[/PREFIX][:PORT]` |
| Writable paths | Only with a read-only root; at most 16 absolute UTF-8 paths of at most 1024 bytes |
| Labels | At most 32 entries; keys are 1–63 ASCII bytes and use alphanumeric, `-`, `_`, `.`, or `/`; values are at most 256 UTF-8 bytes and contain no controls |
| Argv | 1–4096 UTF-8 arguments; `argv[0]` is nonempty; NUL is forbidden |
| Exec `cwd` | Empty (`/`, as before) or an absolute UTF-8 path starting with `/`, at most 4,096 bytes (`--max-exec-cwd-bytes` may lower it), without NUL; not normalized |
| Exec `env`, create `default_env` | At most 64 entries; names 1–128 bytes matching `[A-Za-z_][A-Za-z0-9_]*`, each given once; values UTF-8 without NUL, at most 4,096 bytes; `len(name) + len(value) + 2` totals at most 32,768. The same bounds hold for the merge of default env and an Exec's env; flags may lower each. Errors name an entry by position, never by its contents |
| Create `request_id` | Empty (an unkeyed create) or 1–64 bytes, each printable ASCII without space (`0x21`–`0x7e`); checked before any lookup. The rest of a keyed create is validated after its request record lookup, so an accepted key is answered even if a node limit changed since |

Hostnames use ASCII labels of 1–63 bytes, begin and end with an alphanumeric
byte, and contain only alphanumeric bytes or interior hyphens. They have at
most 253 bytes. Ports are decimal 1–65535 and IPv4 prefixes are decimal 0–32.
IPv6, Unicode hostnames, empty labels, root (`/`), and flag-like leading
hyphens are rejected. Structural validation does not resolve a hostname;
resolution failure is a later backend error.

A writable path must not be `/` and must not contain an empty, `.`, or `..`
component, a repeated or trailing slash, NUL, or another control character.
Unicode and flag-like path components are valid. Rejecting `/` prevents a
read-only root request from silently becoming writable.

Argv is literal data, never host-shell text. Newlines, other non-NUL control
characters, Unicode, flag-like values, and empty arguments after `argv[0]`
are preserved. Callers that want shell parsing must explicitly request a
shell such as `sh -c`.

kilnd's configurable argv limit counts each argument's UTF-8 bytes plus one
separator byte; the default is 256 KiB. kiln's persistent-exec frame instead
contains a four-byte argc followed by a four-byte length and the bytes of each
argument, and caps that encoded body at 1 MiB. kilnd checks both limits. At the
default API limit and maximum argc, the largest possible encoded body is
`262144 + 3*4096 + 4 = 274436` bytes, safely below the backend cap.

Create limits are checked as one request before persistence or backend work.
Exec validation likewise happens before an execution row or backend spawn. An env
or cwd the backend has not proven is refused `UNIMPLEMENTED` before it is validated;
the root helper and kiln revalidate both at the code ceilings, kiln in a strict form
(env sorted by name, no duplicates) the helper always sends.
Valid-but-unresolvable destinations and failures after backend admission may
still produce ordinary lifecycle failure records.
