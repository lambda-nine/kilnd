//! Workspace checkpoint facts shared by the root helper and the daemon (design
//! sections 4.3, 10 and 10.1; milestone C3). Nothing here is reachable from the public
//! API: no RPC, Health field or feature names it until C5 and C6.
//!
//! The helper certifies three facts about one artifact, each as immutable
//! [`Evidence`]: a capture's COMPLETE artifact, the artifact's ABSENT storage, and a
//! reader's end. The daemon stores the canonical bytes and the evidence ID (C4) and
//! accepts a fact only through [`SealedEvidence::verify`] against what it dispatched.
use crate::model::{Digest, Id128};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The checkpoint group's own schema inside the helper's v3 envelope.
pub const GROUP_VERSION: u32 = 1;
/// kiln's artifact format (kiln `docs/checkpoint-format-v1.md`).
pub const FORMAT_VERSION: u32 = 1;
/// The evidence record's own version.
pub const EVIDENCE_VERSION: u32 = 1;
/// Design section 9: immutable helper facts are bounded to 16 KiB.
pub const MAX_EVIDENCE_BYTES: usize = 16 << 10;
const EVIDENCE_DOMAIN: &[u8] = b"kilnd.checkpoint-evidence.1";
/// kiln's bounds on a reservation R: 64 KiB to 1 TiB. The daemon's policy is lower.
pub const MIN_LIMIT_BYTES: u64 = 64 << 10;
pub const MAX_LIMIT_BYTES: u64 = 1 << 40;
/// Design 6.2: the helper's ceiling for one capture, restore or verification.
pub const HELPER_CEILING_MS: u32 = 300_000;
/// One inventory reply lists at most this many entries; more is incomplete.
pub const MAX_INVENTORY_ENTRIES: usize = 4096;
/// The artifacts one helper epoch tracks at once.
pub const MAX_TRACKED_ARTIFACTS: usize = 4096;
/// The token every backend without checkpoints answers (design 7.3 and 11.1).
pub const BACKEND_UNSUPPORTED: &str = "backend_unsupported:workspace_checkpoint";

fn lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `cp-` and 32 lowercase hexadecimal digits. The only text form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckpointId(String);

impl CheckpointId {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.strip_prefix("cp-") {
            Some(hex) if hex.len() == 32 && lower_hex(hex) => Ok(Self(text.to_string())),
            _ => Err("a checkpoint ID is cp- and 32 lowercase hexadecimal digits".into()),
        }
    }

    pub fn random() -> Self {
        Self(format!("cp-{}", Id128::random()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CheckpointId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CheckpointId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// One artifact: its owner instance, ID and immutable capture generation. The daemon
/// never reuses an ID, so a second generation for one ID is a stale or forged request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTarget {
    pub instance: Id128,
    pub checkpoint: CheckpointId,
    pub generation: u64,
}

impl ArtifactTarget {
    pub fn validate(&self) -> Result<(), String> {
        if self.generation == 0 {
            return Err("checkpoint generation must be nonzero".into());
        }
        Ok(())
    }
}

/// What the daemon binds at C1 (design 10, "Capture order") and the helper certifies at
/// C3: the artifact, this attempt's fresh operation nonce, the source backend and R.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBinding {
    pub target: ArtifactTarget,
    pub operation: Id128,
    pub source: String,
    pub limit_bytes: u64,
}

impl CaptureBinding {
    pub fn validate(&self) -> Result<(), String> {
        self.target.validate()?;
        if !crate::runtime::kiln_direct::valid_kiln_id(&self.source) {
            return Err("invalid source backend ID".into());
        }
        if !(MIN_LIMIT_BYTES..=MAX_LIMIT_BYTES).contains(&self.limit_bytes) {
            return Err("checkpoint limit outside 64 KiB to 1 TiB".into());
        }
        Ok(())
    }
}

/// The typed refusal tokens (design 7.3 and kiln's format). Serialized as the token;
/// the helper never classifies by prose, and an unknown kiln token becomes `Io`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    #[serde(rename = "sandbox_unsupported:workspace_checkpoint")]
    SandboxUnsupported,
    #[serde(rename = "checkpoint_busy")]
    Busy,
    #[serde(rename = "checkpoint_layout_unsupported")]
    LayoutUnsupported,
    #[serde(rename = "checkpoint_metadata_unsupported")]
    MetadataUnsupported,
    #[serde(rename = "checkpoint_image_unavailable")]
    ImageUnavailable,
    #[serde(rename = "checkpoint_size_limit")]
    SizeLimit,
    #[serde(rename = "checkpoint_spec_mismatch")]
    SpecMismatch,
    #[serde(rename = "checkpoint_disk_too_small")]
    DiskTooSmall,
    #[serde(rename = "checkpoint_corrupt")]
    Corrupt,
    /// kiln's generation-checked removal found another generation published
    /// under the name, and removed nothing.
    #[serde(rename = "checkpoint_generation_mismatch")]
    GenerationMismatch,
    #[serde(rename = "checkpoint_io")]
    Io,
    #[serde(rename = "checkpoint_workers")]
    Workers,
    #[serde(rename = "invalid_request")]
    InvalidRequest,
}

impl Reason {
    const ALL: [Self; 13] = [
        Self::SandboxUnsupported,
        Self::Busy,
        Self::LayoutUnsupported,
        Self::MetadataUnsupported,
        Self::ImageUnavailable,
        Self::SizeLimit,
        Self::SpecMismatch,
        Self::DiskTooSmall,
        Self::Corrupt,
        Self::GenerationMismatch,
        Self::Io,
        Self::Workers,
        Self::InvalidRequest,
    ];

    pub fn token(self) -> &'static str {
        match self {
            Self::SandboxUnsupported => "sandbox_unsupported:workspace_checkpoint",
            Self::Busy => "checkpoint_busy",
            Self::LayoutUnsupported => "checkpoint_layout_unsupported",
            Self::MetadataUnsupported => "checkpoint_metadata_unsupported",
            Self::ImageUnavailable => "checkpoint_image_unavailable",
            Self::SizeLimit => "checkpoint_size_limit",
            Self::SpecMismatch => "checkpoint_spec_mismatch",
            Self::DiskTooSmall => "checkpoint_disk_too_small",
            Self::Corrupt => "checkpoint_corrupt",
            Self::GenerationMismatch => "checkpoint_generation_mismatch",
            Self::Io => "checkpoint_io",
            Self::Workers => "checkpoint_workers",
            Self::InvalidRequest => "invalid_request",
        }
    }

    /// Exactly one of kiln's tokens, or nothing.
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.token() == token)
    }
}

/// Whether a restore finished reading its artifact. Only `Complete` and `NotStarted`
/// can release a fork's pin; `Unknown` keeps it until ABSENT evidence (design 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyOutcome {
    /// `kiln create` exited 124 before forking anything, or the helper refused the
    /// restore before starting it: nothing ever opened the artifact for it.
    NotStarted,
    /// `kiln create` reported the new sandbox: its shim had restored the upper and
    /// released the artifact before readiness.
    Complete,
    /// Killed, timed out or failed otherwise: a detached shim may still be reading.
    Unknown,
}

/// kiln's `kiln-checkpoint-record 1`, parsed strictly (kiln `docs/checkpoint-format-v1.md`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub instance: Id128,
    pub checkpoint: CheckpointId,
    pub generation: u64,
    pub content_sha256: Digest,
    pub binding_sha256: Digest,
    pub image: String,
    pub image_sha256: Digest,
    pub entries: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub charge_bytes: u64,
    pub limit_bytes: u64,
}

/// A canonical decimal: digits only, no leading zero but `0` itself.
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("malformed number".into());
    }
    text.parse().map_err(|_| "number out of range".into())
}

/// The lines of a strict record: every key in order, one space, a value, a final
/// newline, nothing else.
fn record_fields<'a, const N: usize>(
    text: &'a str,
    header: &str,
    keys: [&str; N],
) -> Result<[&'a str; N], String> {
    let body = text
        .strip_suffix('\n')
        .ok_or("record without a final newline")?;
    let mut lines = body.split('\n');
    if lines.next() != Some(header) {
        return Err("unexpected record header".into());
    }
    let mut values = [""; N];
    for (slot, key) in values.iter_mut().zip(keys) {
        let line = lines.next().ok_or("truncated record")?;
        *slot = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(' '))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("expected record key {key}"))?;
    }
    if lines.next().is_some() {
        return Err("trailing record lines".into());
    }
    Ok(values)
}

impl ArtifactRecord {
    pub fn parse(text: &str) -> Result<Self, String> {
        let [
            instance,
            checkpoint,
            generation,
            content,
            binding,
            image,
            image_sha256,
            entries,
            logical,
            allocated,
            charge,
            limit,
        ] = record_fields(
            text,
            "kiln-checkpoint-record 1",
            [
                "instance",
                "checkpoint",
                "generation",
                "content-sha256",
                "binding-sha256",
                "image",
                "image-sha256",
                "entries",
                "logical-bytes",
                "allocated-bytes",
                "charge-bytes",
                "limit-bytes",
            ],
        )?;
        crate::validation::validate_image_name(image)?;
        let record = Self {
            instance: Id128::parse(instance)?,
            checkpoint: CheckpointId::parse(checkpoint)?,
            generation: decimal(generation)?,
            content_sha256: Digest::parse(content)?,
            binding_sha256: Digest::parse(binding)?,
            image: image.to_string(),
            image_sha256: Digest::parse(image_sha256)?,
            entries: decimal(entries)?,
            logical_bytes: decimal(logical)?,
            allocated_bytes: decimal(allocated)?,
            charge_bytes: decimal(charge)?,
            limit_bytes: decimal(limit)?,
        };
        // kiln's own invariants: a root entry, and 0 < S <= R.
        if record.generation == 0
            || record.entries == 0
            || record.charge_bytes == 0
            || record.charge_bytes > record.limit_bytes
            || record.allocated_bytes > record.charge_bytes
        {
            return Err("record outside the format's invariants".into());
        }
        Ok(record)
    }

    /// The record names exactly this artifact.
    pub fn names(&self, target: &ArtifactTarget) -> bool {
        self.instance == target.instance
            && self.checkpoint == target.checkpoint
            && self.generation == target.generation
    }
}

/// kiln's `kiln-checkpoint-failure 1`: the typed reason and its redacted detail.
/// An unknown token is `Io`: the helper never guesses a more specific class.
pub fn parse_failure(text: &str) -> Result<(Reason, String), String> {
    let body = text
        .strip_suffix('\n')
        .ok_or("failure without a final newline")?;
    let mut lines = body.split('\n');
    let (Some("kiln-checkpoint-failure 1"), Some(reason), Some(detail), None) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Err("malformed failure record".into());
    };
    let reason = reason.strip_prefix("reason ").ok_or("malformed failure")?;
    // kiln writes `detail ` and nothing more when the detail is empty.
    let detail = detail.strip_prefix("detail ").ok_or("malformed failure")?;
    Ok((
        Reason::from_token(reason).unwrap_or(Reason::Io),
        bounded_detail(detail),
    ))
}

/// At most 512 characters, no control characters: kiln's own bound and form.
pub fn bounded_detail(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(512)
        .collect()
}

/// The facts a COMPLETE capture certifies: kiln's record and the binding it was made
/// under. Identity and lifetime fields are outside the content digest (design 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteFact {
    pub source: String,
    pub content_sha256: Digest,
    pub binding_sha256: Digest,
    pub image: String,
    pub image_sha256: Digest,
    pub entries: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub charge_bytes: u64,
    pub limit_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Fact {
    /// A published, validated artifact for exactly this binding, made by a capture
    /// worker this helper started, reaped, and never had a removal cancel.
    Complete(Box<CompleteFact>),
    /// After every worker of this artifact was reaped, kiln removed it and its staging
    /// under their exclusive locks, the namespace lists nothing for it, and no process
    /// names it. Nothing later can publish it: its tombstone refuses every request.
    Absent { existed: bool },
    /// The restore reader with this operation nonce was reaped.
    ReaderEnded { copy: CopyOutcome },
}

impl Fact {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Complete(_) => "complete",
            Self::Absent { .. } => "absent",
            Self::ReaderEnded { .. } => "reader_ended",
        }
    }
}

/// One immutable helper fact (design 9's `checkpoint_evidence`). Its canonical bytes
/// are this struct's JSON in field order; its identity is their domain-separated
/// SHA-256. No caller-supplied string is evidence: every field is typed and was
/// checked by the helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub version: u32,
    pub instance: Id128,
    pub checkpoint: CheckpointId,
    pub generation: u64,
    /// The capture, removal or reader nonce the fact is about.
    pub operation: Id128,
    /// The helper process that certified it, and its boot.
    pub helper_epoch: Id128,
    pub boot_id: Id128,
    pub fact: Fact,
}

/// Evidence on the wire and in the daemon: the record and the ID it must hash to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedEvidence {
    pub evidence: Evidence,
    pub id: Digest,
}

/// What the daemon expects a fact to be about, and who must have certified it: the
/// helper epoch and boot the operation was dispatched under (C4 adversarial review
/// HIGH 1). A fact about the right nonce from any other helper process or boot is not
/// this dispatch's fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected<'a> {
    pub target: &'a ArtifactTarget,
    pub operation: Id128,
    pub kind: &'static str,
    pub helper_epoch: Id128,
    pub boot_id: Id128,
}

/// The helper process and boot an operation was dispatched under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatched {
    pub helper_epoch: Id128,
    pub boot_id: Id128,
}

impl Evidence {
    /// The canonical bytes. serde_json writes struct fields in declaration order and
    /// integers and digests in one form, so the bytes are a function of the value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err("checkpoint evidence exceeds 16 KiB".into());
        }
        Ok(bytes)
    }

    pub fn seal(self) -> Result<SealedEvidence, String> {
        let id = evidence_id(&self.canonical_bytes()?);
        Ok(SealedEvidence { evidence: self, id })
    }
}

fn evidence_id(bytes: &[u8]) -> Digest {
    let mut input = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 1 + bytes.len());
    input.extend_from_slice(EVIDENCE_DOMAIN);
    input.push(0);
    input.extend_from_slice(bytes);
    Digest::of(&input)
}

impl SealedEvidence {
    /// Decodes stored bytes: canonical, bounded, and with the stored ID.
    pub fn decode(bytes: &[u8], id: Digest) -> Result<Self, String> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err("checkpoint evidence exceeds 16 KiB".into());
        }
        let evidence: Evidence = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if evidence.canonical_bytes()? != bytes {
            return Err("checkpoint evidence is not canonical".into());
        }
        let sealed = Self { evidence, id };
        sealed.verify_shape()?;
        Ok(sealed)
    }

    fn verify_shape(&self) -> Result<Vec<u8>, String> {
        let bytes = self.evidence.canonical_bytes()?;
        if evidence_id(&bytes) != self.id {
            return Err("checkpoint evidence ID does not match its bytes".into());
        }
        let e = &self.evidence;
        if e.version != EVIDENCE_VERSION || e.generation == 0 {
            return Err("unsupported checkpoint evidence".into());
        }
        if let Fact::Complete(fact) = &e.fact
            && (fact.charge_bytes == 0
                || fact.charge_bytes > fact.limit_bytes
                || fact.entries == 0
                || !crate::runtime::kiln_direct::valid_kiln_id(&fact.source))
        {
            return Err("COMPLETE evidence outside the format's invariants".into());
        }
        Ok(bytes)
    }

    /// Accepts this fact only for what the daemon dispatched: the same artifact,
    /// generation, operation nonce and kind, certified by the helper epoch and boot it
    /// was dispatched under. Returns the canonical bytes to store.
    pub fn verify(&self, expected: &Expected<'_>) -> Result<Vec<u8>, String> {
        let bytes = self.verify_about(expected.target, expected.operation, expected.kind)?;
        let e = &self.evidence;
        if e.helper_epoch != expected.helper_epoch || e.boot_id != expected.boot_id {
            return Err("checkpoint evidence from another helper epoch or boot".into());
        }
        Ok(bytes)
    }

    /// The runtime adapter's check of one reply (C3), which knows the helper epoch it
    /// sent the request under but not the helper's boot: everything [`Self::verify`]
    /// checks but the boot. Never enough to store a fact: the store binds both.
    pub fn verify_reply(
        &self,
        target: &ArtifactTarget,
        operation: Id128,
        kind: &'static str,
        helper_epoch: Id128,
    ) -> Result<Vec<u8>, String> {
        let bytes = self.verify_about(target, operation, kind)?;
        if self.evidence.helper_epoch != helper_epoch {
            return Err("checkpoint evidence from another helper epoch".into());
        }
        Ok(bytes)
    }

    fn verify_about(
        &self,
        target: &ArtifactTarget,
        operation: Id128,
        kind: &'static str,
    ) -> Result<Vec<u8>, String> {
        let bytes = self.verify_shape()?;
        let e = &self.evidence;
        if e.instance != target.instance
            || e.checkpoint != target.checkpoint
            || e.generation != target.generation
            || e.operation != operation
            || e.fact.kind() != kind
        {
            return Err("checkpoint evidence is about something else".into());
        }
        Ok(bytes)
    }

    /// COMPLETE evidence for this exact binding (source and R included), from the
    /// helper epoch and boot the capture was dispatched under.
    pub fn verify_complete(
        &self,
        binding: &CaptureBinding,
        dispatched: Dispatched,
    ) -> Result<&CompleteFact, String> {
        self.verify(&Expected {
            target: &binding.target,
            operation: binding.operation,
            kind: "complete",
            helper_epoch: dispatched.helper_epoch,
            boot_id: dispatched.boot_id,
        })?;
        self.complete_fact(binding)
    }

    /// The adapter's COMPLETE check: [`Self::verify_reply`] plus the binding's source and R.
    pub fn verify_complete_reply(
        &self,
        binding: &CaptureBinding,
        helper_epoch: Id128,
    ) -> Result<&CompleteFact, String> {
        self.verify_reply(&binding.target, binding.operation, "complete", helper_epoch)?;
        self.complete_fact(binding)
    }

    fn complete_fact(&self, binding: &CaptureBinding) -> Result<&CompleteFact, String> {
        match &self.evidence.fact {
            Fact::Complete(fact)
                if fact.source == binding.source && fact.limit_bytes == binding.limit_bytes =>
            {
                Ok(fact)
            }
            _ => Err("COMPLETE evidence for another binding".into()),
        }
    }
}

pub mod wire;

#[cfg(test)]
pub(crate) mod tests;
