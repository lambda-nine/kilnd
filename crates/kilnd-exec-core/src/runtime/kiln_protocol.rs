//! Strict persistent-exec v1 codec. Workload bytes are never input here.
use crate::model::{CommandStatus, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage};

pub const MAX_FRAME: usize = 2088;
const HEADER: usize = 16;
/// `kiln create` reserves exit status 124 for failures known before allocation.
const FEATURE_CREATE_CERTAINTY: u32 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup {
    Unconfirmed,
    NoChildStarted,
    Drained,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub command_status: Option<CommandStatus>,
    pub cleanup: Cleanup,
    pub diagnostic: Option<RuntimeDiagnostic>,
}

impl Outcome {
    pub fn projection(&self) -> i32 {
        match &self.diagnostic {
            None => self
                .command_status
                .as_ref()
                .expect("validated command")
                .legacy_projection(),
            Some(d) if d.kind == RuntimeErrorKind::LaunchFailed => match d.stage {
                RuntimeStage::Admission | RuntimeStage::Stdio => 126,
                RuntimeStage::Exec => 127,
                _ => 125,
            },
            Some(_) => 125,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub features: u32,
    pub control_version: u16,
    pub private_version: u16,
    pub package: String,
    pub provenance: String,
}

impl Capabilities {
    pub fn require_v1(&self) -> Result<(), String> {
        if self.features & 15 != 15 || self.control_version != 1 || self.private_version != 1 {
            return Err(format!(
                "required features 0xf and versions 1/1; observed {:#x} {}/{} ({} {})",
                self.features,
                self.control_version,
                self.private_version,
                self.package,
                self.provenance
            ));
        }
        Ok(())
    }

    /// Required of the installed CLI, which is what allocates new sandboxes.
    /// A live sandbox's PID 1 never creates, so older ones stay compatible.
    pub fn require_create_certainty(&self) -> Result<(), String> {
        if self.features & FEATURE_CREATE_CERTAINTY == 0 {
            return Err(format!(
                "required persistent-create certainty feature {FEATURE_CREATE_CERTAINTY:#x}; observed {:#x} ({} {})",
                self.features, self.package, self.provenance
            ));
        }
        Ok(())
    }
}

fn u16_at(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(p[at..at + 2].try_into().unwrap())
}
fn u32_at(p: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(p[at..at + 4].try_into().unwrap())
}
fn i32_at(p: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(p[at..at + 4].try_into().unwrap())
}

fn payload(frame: &[u8], ty: u16) -> Result<&[u8], String> {
    if frame.is_empty() {
        return Err("missing status frame".into());
    }
    if frame.len() < HEADER {
        return Err("truncated status header (legacy replies are unsupported)".into());
    }
    if &frame[..8] != b"KILNEXO\0" {
        return Err("wrong status magic".into());
    }
    if u16_at(frame, 8) != 1 {
        return Err(format!("unsupported frame version {}", u16_at(frame, 8)));
    }
    if u16_at(frame, 10) != ty {
        return Err("unexpected frame type".into());
    }
    let len = u32_at(frame, 12) as usize;
    if len > MAX_FRAME - HEADER {
        return Err("oversized frame length".into());
    }
    if frame.len() < HEADER + len {
        return Err("truncated status payload".into());
    }
    if frame.len() != HEADER + len {
        return Err("duplicate or trailing status bytes".into());
    }
    Ok(&frame[HEADER..])
}

pub fn outcome(frame: &[u8]) -> Result<Outcome, String> {
    let p = payload(frame, 1)?;
    if p.len() < 24 {
        return Err("short outcome payload".into());
    }
    let diagnostic_len = u32_at(p, 16) as usize;
    if diagnostic_len > 2048 || p.len() != 24 + diagnostic_len {
        return Err("invalid diagnostic length".into());
    }
    if p[3] & !3 != 0 || u32_at(p, 20) != 0 {
        return Err("unknown flags or reserved bytes".into());
    }
    let message = std::str::from_utf8(&p[24..]).map_err(|_| "invalid diagnostic UTF-8")?;
    let core_dumped = p[3] & 1 != 0;
    let value = i32_at(p, 4);
    let command_status = match p[1] {
        0 if value == 0 && !core_dumped => None,
        1 if (0..=255).contains(&value) && !core_dumped => Some(CommandStatus::Exited(value)),
        2 if (1..=64).contains(&value) => Some(CommandStatus::Signaled {
            signal: value,
            core_dumped,
        }),
        _ => return Err("invalid termination".into()),
    };
    let cleanup = match p[2] {
        0 => Cleanup::Unconfirmed,
        1 if command_status.is_none() => Cleanup::NoChildStarted,
        2 => Cleanup::Drained,
        _ => return Err("invalid or contradictory cleanup".into()),
    };
    let kind = match u16_at(p, 8) {
        0 => None,
        1 => Some(RuntimeErrorKind::InvalidRequest),
        2 => Some(RuntimeErrorKind::Unavailable),
        3 => Some(RuntimeErrorKind::NotFound),
        4 => Some(RuntimeErrorKind::Incompatible),
        5 => Some(RuntimeErrorKind::Busy),
        6 => Some(RuntimeErrorKind::LaunchFailed),
        7 => Some(RuntimeErrorKind::Io),
        8 => Some(RuntimeErrorKind::Protocol),
        9 => Some(RuntimeErrorKind::CleanupFailed),
        10 => Some(RuntimeErrorKind::Internal),
        11 => Some(RuntimeErrorKind::Stopped),
        _ => return Err("unknown failure kind".into()),
    };
    let stage = match u16_at(p, 10) {
        0 => Some(RuntimeStage::None),
        1 => Some(RuntimeStage::Validate),
        2 => Some(RuntimeStage::Connect),
        3 => Some(RuntimeStage::Request),
        4 => Some(RuntimeStage::Prepare),
        5 => Some(RuntimeStage::Fork),
        6 => Some(RuntimeStage::Admission),
        7 => Some(RuntimeStage::Stdio),
        8 => Some(RuntimeStage::Exec),
        9 => Some(RuntimeStage::Wait),
        10 => Some(RuntimeStage::Cleanup),
        11 => Some(RuntimeStage::Report),
        12 => Some(RuntimeStage::Capture),
        13 => Some(RuntimeStage::Handshake),
        _ => return Err("unknown failure stage".into()),
    };
    let errno = i32_at(p, 12);
    if errno < 0 {
        return Err("negative errno".into());
    }
    let diagnostic = match p[0] {
        1 if command_status.is_some()
            && cleanup == Cleanup::Drained
            && kind.is_none()
            && stage == Some(RuntimeStage::None)
            && errno == 0
            && message.is_empty()
            && p[3] & 2 == 0 =>
        {
            None
        }
        2 if kind.is_some() && stage.is_some() => Some(RuntimeDiagnostic {
            kind: kind.unwrap(),
            stage: stage.unwrap(),
            message: message.into(),
            native_code: (errno != 0).then(|| format!("errno:{errno}")),
            message_truncated: p[3] & 2 != 0,
        }),
        _ => return Err("invalid or contradictory outcome".into()),
    };
    Ok(Outcome {
        command_status,
        cleanup,
        diagnostic,
    })
}

pub fn capabilities(frame: &[u8]) -> Result<Capabilities, String> {
    let p = payload(frame, 2)?;
    if p.len() < 16 {
        return Err("short capabilities payload".into());
    }
    let package_len = u16_at(p, 8) as usize;
    let provenance_len = u16_at(p, 10) as usize;
    if package_len > 64
        || provenance_len > 128
        || u32_at(p, 12) != 0
        || p.len() != 16 + package_len + provenance_len
    {
        return Err("invalid capabilities lengths/reserved".into());
    }
    Ok(Capabilities {
        features: u32_at(p, 0),
        control_version: u16_at(p, 4),
        private_version: u16_at(p, 6),
        package: std::str::from_utf8(&p[16..16 + package_len])
            .map_err(|_| "invalid package UTF-8")?
            .into(),
        provenance: std::str::from_utf8(&p[16 + package_len..])
            .map_err(|_| "invalid provenance UTF-8")?
            .into(),
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    pub fn exit125() -> Vec<u8> {
        hex(
            "4b494c4e45584f00 0100 0100 18000000 01010200 7d000000 0000 0000 00000000 00000000 00000000",
        )
    }
    pub fn caps() -> Vec<u8> {
        hex(
            "4b494c4e45584f00 0100 0200 1d000000 0f000000 0100 0100 0500 0800 00000000 302e312e30 6769742074657374",
        )
    }
    #[test]
    fn golden_vectors_and_every_split() {
        let frame = exit125();
        assert_eq!(
            outcome(&frame).unwrap().command_status,
            Some(CommandStatus::Exited(125))
        );
        for split in 0..frame.len() {
            assert!(outcome(&frame[..split]).is_err());
            let mut joined = frame[..split].to_vec();
            joined.extend_from_slice(&frame[split..]);
            assert_eq!(outcome(&joined).unwrap().projection(), 125);
        }
        let frame = caps();
        let c = capabilities(&frame).unwrap();
        c.require_v1().unwrap();
        assert_eq!((&*c.package, &*c.provenance), ("0.1.0", "git test"));
        for split in 0..frame.len() {
            assert!(capabilities(&frame[..split]).is_err());
        }
    }
    #[test]
    fn signal_core_and_realtime() {
        for signal in [1i32, 15, 34, 64] {
            let mut frame = exit125();
            frame[17] = 2;
            frame[19] = 1;
            frame[20..24].copy_from_slice(&signal.to_le_bytes());
            let out = outcome(&frame).unwrap();
            assert_eq!(
                out.command_status,
                Some(CommandStatus::Signaled {
                    signal,
                    core_dumped: true
                })
            );
            assert_eq!(out.projection(), 128 + signal);
        }
    }

    #[test]
    fn failure_preserves_none_stage_errno_and_truncation() {
        let mut frame = exit125();
        frame[16] = 2;
        frame[24] = 8;
        frame[19] = 2;
        frame[28] = 5;
        let d = outcome(&frame).unwrap().diagnostic.unwrap();
        assert_eq!(d.stage, RuntimeStage::None);
        assert_eq!(d.native_code.as_deref(), Some("errno:5"));
        assert!(d.message_truncated);
        assert_eq!(serde_json::to_value(&d).unwrap()["stage"], "none");
        let mut invalid = frame.clone();
        invalid[32] = 1;
        invalid[12] = 25;
        invalid.push(255);
        assert!(outcome(&invalid).is_err());
        let mut invalid = frame;
        invalid[31] = 255;
        assert!(outcome(&invalid).is_err());
    }
    #[test]
    fn rejects_mutations_without_fallback() {
        for (offset, value) in [
            (0, 0),
            (8, 2),
            (10, 2),
            (12, 255),
            (16, 0),
            (17, 0),
            (18, 1),
            (19, 4),
            (21, 255),
            (24, 12),
            (26, 14),
            (28, 255),
            (32, 1),
            (36, 1),
        ] {
            let mut frame = exit125();
            frame[offset] = value;
            assert!(outcome(&frame).is_err(), "offset {offset}");
        }
        let mut frame = exit125();
        frame.push(0);
        assert!(outcome(&frame).is_err());
        let mut frame = exit125();
        frame.extend(exit125());
        assert!(outcome(&frame).is_err());
        assert!(outcome(&125i32.to_le_bytes()).is_err());
        let mut frame = caps();
        frame[16] = 7;
        assert!(capabilities(&frame).unwrap().require_v1().is_err());
    }

    #[test]
    fn create_certainty_is_a_separate_additive_feature() {
        for (features, v1, certainty) in [
            (0x0f, true, false),
            (0x1f, true, true),
            (0x10, false, true),
            (0xff, true, true),
        ] {
            let mut f = caps();
            f[16] = features;
            let c = capabilities(&f).unwrap();
            assert_eq!(c.require_v1().is_ok(), v1, "{features:#x}");
            assert_eq!(
                c.require_create_certainty().is_ok(),
                certainty,
                "{features:#x}"
            );
        }
    }

    #[test]
    fn capability_mutations_and_unknown_additive_feature_bits() {
        for (offset, value) in [
            (8, 2),
            (10, 1),
            (12, 255),
            (24, 65),
            (26, 129),
            (28, 1),
            (32, 255),
            (40, 255),
        ] {
            let mut f = caps();
            f[offset] = value;
            assert!(capabilities(&f).is_err(), "offset {offset}");
        }
        for offset in [20, 22] {
            let mut f = caps();
            f[offset] = 2;
            assert!(capabilities(&f).unwrap().require_v1().is_err());
        }
        let mut f = caps();
        f[19] = 128;
        capabilities(&f).unwrap().require_v1().unwrap();
    }
}
