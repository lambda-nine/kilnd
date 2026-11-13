// Schema 15 (workspace checkpoint design section 9; milestone C4): every table and
// column the checkpoint feature will need, reserved at once so C5 and C6 never reshape
// a migrated row. The feature stays off: nothing writes these tables until C5, and an
// empty `checkpoints` table adds zero to every charge.
//
// Charge: a checkpoint row is charged until it references matching ABSENT evidence
// (`release_evidence_id`), whatever its state: R (`max_size_bytes`) until the READY seal,
// then S (`charge_bytes`, 0 < S <= R), fixed once. FAILED and DELETED are exactly the
// released states. QUARANTINED and every intermediate state keep their charge.
//
// Like schemas 8-12, the triggers are defense in depth against malformed direct SQL by
// a writer with the database's own file authority; they are not a tamperproof ledger.
// `trusted_schema` stays OFF: the triggers use only innocuous built-ins (json_extract,
// json_valid) and the innocuous evidence validator, registered before any statement.
// The JSON fact fields are read with CAST(... AS TEXT): SQLite reads a BLOB argument as
// JSONB.
//
// The three cached aggregates (`checkpoint_counts`, `checkpoint_membership` and the
// `checkpoint_unsettled` set) follow schema 12's pattern: triggers keep the counts and
// note releases, only Store transactions write the membership sums, and every accounting
// decision audits the cache against the rows it depends on before trusting it.
pub(super) const MIGRATE_V15: &str = "
CREATE TABLE checkpoint_sequence (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL CHECK (typeof(value) = 'integer' AND value >= 0)
);
INSERT INTO checkpoint_sequence VALUES (1, 0);
CREATE TABLE checkpoint_evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(evidence_id) = 'text' AND length(evidence_id) = 64 AND evidence_id NOT GLOB '*[^0-9a-f]*'),
    instance_id TEXT NOT NULL CHECK (typeof(instance_id) = 'text' AND length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*'),
    checkpoint_id TEXT NOT NULL CHECK (typeof(checkpoint_id) = 'text' AND length(checkpoint_id) = 35 AND substr(checkpoint_id, 1, 3) = 'cp-' AND substr(checkpoint_id, 4) NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    operation TEXT NOT NULL CHECK (typeof(operation) = 'text' AND length(operation) = 32 AND operation NOT GLOB '*[^0-9a-f]*'),
    helper_epoch TEXT NOT NULL CHECK (typeof(helper_epoch) = 'text' AND length(helper_epoch) = 32 AND helper_epoch NOT GLOB '*[^0-9a-f]*'),
    boot_id TEXT NOT NULL CHECK (typeof(boot_id) = 'text' AND length(boot_id) = 32 AND boot_id NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK (typeof(kind) = 'text' AND kind IN ('complete', 'absent', 'reader_ended')),
    evidence BLOB NOT NULL CHECK (typeof(evidence) = 'blob' AND length(evidence) BETWEEN 1 AND 16384),
    recorded_at_ms INTEGER NOT NULL CHECK (typeof(recorded_at_ms) = 'integer'),
    UNIQUE (evidence_id, checkpoint_id, generation, operation, kind),
    UNIQUE (evidence_id, checkpoint_id, generation, kind),
    UNIQUE (evidence_id, checkpoint_id, generation)
);
CREATE TABLE checkpoints (
    id TEXT PRIMARY KEY NOT NULL CHECK (typeof(id) = 'text' AND length(id) = 35 AND substr(id, 1, 3) = 'cp-' AND substr(id, 4) NOT GLOB '*[^0-9a-f]*'),
    creation_seq INTEGER NOT NULL UNIQUE CHECK (typeof(creation_seq) = 'integer' AND creation_seq >= 1),
    owner_uid INTEGER NOT NULL CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    instance_id TEXT NOT NULL CHECK (typeof(instance_id) = 'text' AND length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    format_version INTEGER NOT NULL CHECK (typeof(format_version) = 'integer' AND format_version = 1),
    source_sandbox_id TEXT NOT NULL CHECK (typeof(source_sandbox_id) = 'text' AND length(CAST(source_sandbox_id AS BLOB)) BETWEEN 1 AND 128),
    source_backend TEXT NOT NULL CHECK (typeof(source_backend) = 'text' AND length(CAST(source_backend AS BLOB)) BETWEEN 1 AND 64),
    source_backend_id TEXT NOT NULL CHECK (typeof(source_backend_id) = 'text' AND length(CAST(source_backend_id AS BLOB)) BETWEEN 1 AND 128),
    capture_operation TEXT NOT NULL UNIQUE CHECK (typeof(capture_operation) = 'text' AND length(capture_operation) = 32 AND capture_operation NOT GLOB '*[^0-9a-f]*'),
    capture_helper_epoch TEXT NOT NULL CHECK (typeof(capture_helper_epoch) = 'text' AND length(capture_helper_epoch) = 32 AND capture_helper_epoch NOT GLOB '*[^0-9a-f]*'),
    capture_boot_id TEXT NOT NULL CHECK (typeof(capture_boot_id) = 'text' AND length(capture_boot_id) = 32 AND capture_boot_id NOT GLOB '*[^0-9a-f]*'),
    max_size_bytes INTEGER NOT NULL CHECK (typeof(max_size_bytes) = 'integer' AND max_size_bytes BETWEEN 65536 AND 1099511627776),
    image TEXT NOT NULL CHECK (typeof(image) = 'text' AND length(CAST(image AS BLOB)) BETWEEN 1 AND 256),
    image_content_sha256 TEXT NOT NULL CHECK (typeof(image_content_sha256) = 'text' AND length(image_content_sha256) = 64 AND image_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    read_only_root INTEGER NOT NULL CHECK (typeof(read_only_root) = 'integer' AND read_only_root IN (0, 1)),
    writable_paths TEXT NOT NULL CHECK (typeof(writable_paths) = 'text' AND json_valid(writable_paths) AND json_type(writable_paths) = 'array' AND json_array_length(writable_paths) <= 64),
    excluded_paths TEXT NOT NULL CHECK (typeof(excluded_paths) = 'text' AND json_valid(excluded_paths) AND json_type(excluded_paths) = 'array' AND json_array_length(excluded_paths) <= 64),
    expiry_lifetime_ms INTEGER NOT NULL CHECK (typeof(expiry_lifetime_ms) = 'integer' AND expiry_lifetime_ms BETWEEN 10000 AND 604800000),
    expiry_idle_ms INTEGER NOT NULL CHECK (typeof(expiry_idle_ms) = 'integer' AND expiry_idle_ms BETWEEN 10000 AND 86400000),
    state TEXT NOT NULL CHECK (typeof(state) = 'text' AND state IN ('capturing', 'ready', 'deleting', 'deleted', 'failed', 'quarantined')),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer'),
    updated_at_ms INTEGER NOT NULL CHECK (typeof(updated_at_ms) = 'integer'),
    deleted_at_ms INTEGER CHECK (deleted_at_ms IS NULL OR typeof(deleted_at_ms) = 'integer'),
    complete_evidence_id TEXT,
    complete_evidence_kind TEXT NOT NULL DEFAULT 'complete' CHECK (complete_evidence_kind = 'complete'),
    content_sha256 TEXT CHECK (content_sha256 IS NULL OR (typeof(content_sha256) = 'text' AND length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*')),
    binding_sha256 TEXT CHECK (binding_sha256 IS NULL OR (typeof(binding_sha256) = 'text' AND length(binding_sha256) = 64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*')),
    charge_bytes INTEGER CHECK (charge_bytes IS NULL OR (typeof(charge_bytes) = 'integer' AND charge_bytes >= 1 AND charge_bytes <= max_size_bytes)),
    logical_bytes INTEGER CHECK (logical_bytes IS NULL OR (typeof(logical_bytes) = 'integer' AND logical_bytes >= 0)),
    allocated_bytes INTEGER CHECK (allocated_bytes IS NULL OR (typeof(allocated_bytes) = 'integer' AND allocated_bytes >= 0)),
    entry_count INTEGER CHECK (entry_count IS NULL OR (typeof(entry_count) = 'integer' AND entry_count BETWEEN 1 AND 4294967295)),
    ready_at_ms INTEGER CHECK (ready_at_ms IS NULL OR typeof(ready_at_ms) = 'integer'),
    ready_boottime_ms INTEGER CHECK (ready_boottime_ms IS NULL OR typeof(ready_boottime_ms) = 'integer'),
    activity_at_ms INTEGER CHECK (activity_at_ms IS NULL OR typeof(activity_at_ms) = 'integer'),
    activity_boottime_ms INTEGER CHECK (activity_boottime_ms IS NULL OR typeof(activity_boottime_ms) = 'integer'),
    clock_boot_id TEXT CHECK (clock_boot_id IS NULL OR (typeof(clock_boot_id) = 'text' AND length(clock_boot_id) BETWEEN 1 AND 64)),
    activity_seq INTEGER NOT NULL DEFAULT 0 CHECK (typeof(activity_seq) = 'integer' AND activity_seq >= 0),
    deletion_reason TEXT CHECK (deletion_reason IS NULL OR deletion_reason IN ('requested', 'expired_idle', 'expired_lifetime')),
    expiry_intent_at_ms INTEGER CHECK (expiry_intent_at_ms IS NULL OR typeof(expiry_intent_at_ms) = 'integer'),
    expiry_intent_boottime_ms INTEGER CHECK (expiry_intent_boottime_ms IS NULL OR typeof(expiry_intent_boottime_ms) = 'integer'),
    failure_token TEXT CHECK (failure_token IS NULL OR failure_token IN ('sandbox_unsupported:workspace_checkpoint',
        'checkpoint_busy', 'checkpoint_not_ready', 'checkpoint_expired', 'checkpoint_layout_unsupported',
        'checkpoint_metadata_unsupported', 'checkpoint_image_unavailable', 'checkpoint_spec_mismatch',
        'checkpoint_disk_too_small', 'checkpoint_size_limit', 'checkpoint_corrupt', 'checkpoint_generation_mismatch',
        'checkpoint_io', 'checkpoint_workers', 'checkpoint_quota', 'invalid_request')),
    failure_reason TEXT CHECK (failure_reason IS NULL OR (typeof(failure_reason) = 'text' AND length(CAST(failure_reason AS BLOB)) BETWEEN 1 AND 1024)),
    removal_operation TEXT CHECK (removal_operation IS NULL OR (typeof(removal_operation) = 'text' AND length(removal_operation) = 32 AND removal_operation NOT GLOB '*[^0-9a-f]*')),
    removal_helper_epoch TEXT CHECK (removal_helper_epoch IS NULL OR (typeof(removal_helper_epoch) = 'text' AND length(removal_helper_epoch) = 32 AND removal_helper_epoch NOT GLOB '*[^0-9a-f]*')),
    removal_boot_id TEXT CHECK (removal_boot_id IS NULL OR (typeof(removal_boot_id) = 'text' AND length(removal_boot_id) = 32 AND removal_boot_id NOT GLOB '*[^0-9a-f]*')),
    release_evidence_id TEXT,
    release_evidence_kind TEXT NOT NULL DEFAULT 'absent' CHECK (release_evidence_kind = 'absent'),
    released_at_ms INTEGER CHECK (released_at_ms IS NULL OR typeof(released_at_ms) = 'integer'),
    request_id TEXT CHECK (request_id IS NULL OR (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*')),
    request_id_released_at_ms INTEGER CHECK (request_id_released_at_ms IS NULL OR typeof(request_id_released_at_ms) = 'integer'),
    CHECK ((complete_evidence_id IS NULL) = (content_sha256 IS NULL) AND (content_sha256 IS NULL) = (binding_sha256 IS NULL)
        AND (binding_sha256 IS NULL) = (charge_bytes IS NULL) AND (charge_bytes IS NULL) = (logical_bytes IS NULL)
        AND (logical_bytes IS NULL) = (allocated_bytes IS NULL) AND (allocated_bytes IS NULL) = (entry_count IS NULL)
        AND (entry_count IS NULL) = (ready_at_ms IS NULL) AND (ready_at_ms IS NULL) = (ready_boottime_ms IS NULL)
        AND (ready_boottime_ms IS NULL) = (clock_boot_id IS NULL)),
    CHECK (state != 'ready' OR complete_evidence_id IS NOT NULL),
    CHECK (state NOT IN ('capturing', 'failed') OR complete_evidence_id IS NULL),
    CHECK ((state IN ('failed', 'deleted')) = (release_evidence_id IS NOT NULL)),
    CHECK ((release_evidence_id IS NULL) = (released_at_ms IS NULL)),
    CHECK ((state = 'deleted') = (deleted_at_ms IS NOT NULL)),
    CHECK ((failure_token IS NULL) = (failure_reason IS NULL)),
    CHECK (state NOT IN ('failed', 'quarantined') OR failure_token IS NOT NULL),
    CHECK (state NOT IN ('deleting', 'deleted') OR deletion_reason IS NOT NULL),
    CHECK ((removal_operation IS NULL) = (removal_helper_epoch IS NULL) AND (removal_helper_epoch IS NULL) = (removal_boot_id IS NULL)),
    CHECK (release_evidence_id IS NULL OR removal_operation IS NOT NULL),
    CHECK (request_id_released_at_ms IS NULL OR (request_id IS NOT NULL AND state = 'deleted')),
    FOREIGN KEY (complete_evidence_id, id, generation, capture_operation, complete_evidence_kind)
        REFERENCES checkpoint_evidence (evidence_id, checkpoint_id, generation, operation, kind),
    FOREIGN KEY (release_evidence_id, id, generation, release_evidence_kind)
        REFERENCES checkpoint_evidence (evidence_id, checkpoint_id, generation, kind)
);
CREATE INDEX checkpoints_owner_seq ON checkpoints (owner_uid, creation_seq DESC);
CREATE INDEX checkpoints_source_seq ON checkpoints (source_sandbox_id, creation_seq DESC);
CREATE INDEX checkpoints_state ON checkpoints (state);
CREATE INDEX checkpoints_charged ON checkpoints (id) WHERE release_evidence_id IS NULL;
CREATE INDEX checkpoints_expiry ON checkpoints (id) WHERE state IN ('ready', 'quarantined', 'deleting');
CREATE TABLE checkpoint_pins (
    sandbox_id TEXT PRIMARY KEY NOT NULL REFERENCES sandboxes (id),
    checkpoint_id TEXT NOT NULL REFERENCES checkpoints (id),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 1),
    content_sha256 TEXT NOT NULL CHECK (typeof(content_sha256) = 'text' AND length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    reader_operation TEXT NOT NULL UNIQUE CHECK (typeof(reader_operation) = 'text' AND length(reader_operation) = 32 AND reader_operation NOT GLOB '*[^0-9a-f]*'),
    helper_epoch TEXT NOT NULL CHECK (typeof(helper_epoch) = 'text' AND length(helper_epoch) = 32 AND helper_epoch NOT GLOB '*[^0-9a-f]*'),
    boot_id TEXT NOT NULL CHECK (typeof(boot_id) = 'text' AND length(boot_id) = 32 AND boot_id NOT GLOB '*[^0-9a-f]*'),
    pinned_at_ms INTEGER NOT NULL CHECK (typeof(pinned_at_ms) = 'integer'),
    released_at_ms INTEGER CHECK (released_at_ms IS NULL OR typeof(released_at_ms) = 'integer'),
    released_by TEXT CHECK (released_by IS NULL OR released_by IN ('complete', 'not_started', 'absent')),
    release_evidence_id TEXT,
    CHECK ((released_at_ms IS NULL) = (released_by IS NULL) AND (released_by IS NULL) = (release_evidence_id IS NULL)),
    FOREIGN KEY (release_evidence_id, checkpoint_id, generation)
        REFERENCES checkpoint_evidence (evidence_id, checkpoint_id, generation)
) WITHOUT ROWID;
CREATE INDEX checkpoint_pins_live ON checkpoint_pins (checkpoint_id) WHERE released_at_ms IS NULL;
CREATE INDEX checkpoint_pins_checkpoint ON checkpoint_pins (checkpoint_id);
CREATE TABLE checkpoint_requests (
    owner_uid INTEGER NOT NULL CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*'),
    request_sha256 TEXT NOT NULL CHECK (typeof(request_sha256) = 'text' AND length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    digest_version INTEGER NOT NULL CHECK (typeof(digest_version) = 'integer' AND digest_version = 1),
    checkpoint_id TEXT NOT NULL UNIQUE REFERENCES checkpoints (id),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer'),
    retain_boot_id TEXT CHECK (retain_boot_id IS NULL OR (typeof(retain_boot_id) = 'text' AND length(retain_boot_id) BETWEEN 1 AND 64)),
    retain_from_boottime_ms INTEGER CHECK (retain_from_boottime_ms IS NULL OR typeof(retain_from_boottime_ms) = 'integer'),
    CHECK ((retain_boot_id IS NULL) = (retain_from_boottime_ms IS NULL)),
    PRIMARY KEY (owner_uid, request_id)
) WITHOUT ROWID;
CREATE INDEX checkpoint_requests_unanchored ON checkpoint_requests (checkpoint_id) WHERE retain_boot_id IS NULL;
CREATE TABLE checkpoint_counts (
    owner_uid INTEGER PRIMARY KEY CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN -1 AND 4294967295),
    live INTEGER NOT NULL CHECK (typeof(live) = 'integer' AND live >= 0),
    charged_bytes INTEGER NOT NULL CHECK (typeof(charged_bytes) = 'integer' AND charged_bytes >= 0),
    records INTEGER NOT NULL CHECK (typeof(records) = 'integer' AND records >= 0),
    keys INTEGER NOT NULL CHECK (typeof(keys) = 'integer' AND keys >= 0)
);
INSERT INTO checkpoint_counts VALUES (-1, 0, 0, 0, 0);
CREATE TABLE checkpoint_membership (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL CHECK (typeof(version) = 'integer' AND version = 1),
    row_count INTEGER NOT NULL CHECK (typeof(row_count) = 'integer' AND row_count >= 0),
    row_sum BLOB NOT NULL CHECK (typeof(row_sum) = 'blob' AND length(row_sum) = 32),
    settled_count INTEGER NOT NULL CHECK (typeof(settled_count) = 'integer' AND settled_count >= 0),
    settled_sum BLOB NOT NULL CHECK (typeof(settled_sum) = 'blob' AND length(settled_sum) = 32)
);
INSERT INTO checkpoint_membership VALUES (1, 1, 0, zeroblob(32), 0, zeroblob(32));
CREATE TABLE checkpoint_unsettled (id TEXT PRIMARY KEY) WITHOUT ROWID;

-- Evidence: helper facts, immutable, about a checkpoint row of this instance.
CREATE TRIGGER checkpoint_evidence_no_replace BEFORE INSERT ON checkpoint_evidence
WHEN EXISTS (SELECT 1 FROM checkpoint_evidence WHERE rowid = NEW.rowid OR evidence_id = NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint evidence is immutable'); END;
CREATE TRIGGER checkpoint_evidence_validate BEFORE INSERT ON checkpoint_evidence
WHEN kilnd_checkpoint_evidence_valid(NEW.evidence, NEW.evidence_id, NEW.instance_id, NEW.checkpoint_id,
    NEW.generation, NEW.operation, NEW.helper_epoch, NEW.boot_id, NEW.kind) IS NOT 1
BEGIN SELECT RAISE(ABORT, 'invalid encoded checkpoint evidence'); END;
CREATE TRIGGER checkpoint_evidence_bound BEFORE INSERT ON checkpoint_evidence
WHEN NEW.instance_id IS NOT (SELECT instance_id FROM daemon_identity WHERE id = 1)
    OR NOT EXISTS (SELECT 1 FROM checkpoints WHERE id = NEW.checkpoint_id AND generation = NEW.generation
        AND instance_id = NEW.instance_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint evidence is about another instance, checkpoint or generation'); END;
CREATE TRIGGER checkpoint_evidence_no_update BEFORE UPDATE ON checkpoint_evidence
BEGIN SELECT RAISE(ABORT, 'checkpoint evidence is immutable'); END;
CREATE TRIGGER checkpoint_evidence_no_delete BEFORE DELETE ON checkpoint_evidence
WHEN EXISTS (SELECT 1 FROM checkpoints WHERE id = OLD.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'checkpoint evidence is kept while its checkpoint row exists'); END;

-- Checkpoint rows.
CREATE TRIGGER checkpoints_no_replace BEFORE INSERT ON checkpoints
WHEN EXISTS (SELECT 1 FROM checkpoints WHERE rowid = NEW.rowid OR id = NEW.id OR creation_seq = NEW.creation_seq
    OR capture_operation = NEW.capture_operation)
BEGIN SELECT RAISE(ABORT, 'a checkpoint row cannot be replaced'); END;
CREATE TRIGGER checkpoints_no_replace_update BEFORE UPDATE ON checkpoints
WHEN EXISTS (SELECT 1 FROM checkpoints WHERE rowid != OLD.rowid AND (rowid = NEW.rowid OR id = NEW.id
    OR creation_seq = NEW.creation_seq OR capture_operation = NEW.capture_operation))
BEGIN SELECT RAISE(ABORT, 'a checkpoint row cannot be replaced'); END;
CREATE TRIGGER checkpoints_insert BEFORE INSERT ON checkpoints
WHEN NEW.state IS NOT 'capturing' OR NEW.complete_evidence_id IS NOT NULL OR NEW.release_evidence_id IS NOT NULL
    OR NEW.deletion_reason IS NOT NULL OR NEW.failure_token IS NOT NULL OR NEW.removal_operation IS NOT NULL
    OR NEW.activity_seq IS NOT 0 OR NEW.activity_at_ms IS NOT NULL OR NEW.activity_boottime_ms IS NOT NULL
    OR NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL
    OR NEW.request_id_released_at_ms IS NOT NULL
    OR NEW.instance_id IS NOT (SELECT instance_id FROM daemon_identity WHERE id = 1)
    OR NEW.creation_seq IS NOT (SELECT value FROM checkpoint_sequence WHERE id = 1)
BEGIN SELECT RAISE(ABORT, 'a checkpoint is inserted CAPTURING, unsealed and charged, under this instance and the next sequence'); END;
CREATE TRIGGER checkpoints_source_ready BEFORE INSERT ON checkpoints
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.source_sandbox_id AND state = 'ready'
    AND backend = NEW.source_backend AND backend_id = NEW.source_backend_id
    AND image_content_sha256 = NEW.image_content_sha256 AND checkpoint_format_version = NEW.format_version
    AND json_extract(spec, '$.image') = NEW.image AND json_extract(spec, '$.read_only_root') = NEW.read_only_root
    AND reserved_disk_bytes >= NEW.max_size_bytes)
BEGIN SELECT RAISE(ABORT, 'a checkpoint is captured from its READY, checkpoint-capable source with the same image, root policy and enough disk'); END;
CREATE TRIGGER checkpoints_immutable BEFORE UPDATE ON checkpoints
WHEN NEW.id IS NOT OLD.id OR NEW.creation_seq IS NOT OLD.creation_seq OR NEW.owner_uid IS NOT OLD.owner_uid
    OR NEW.instance_id IS NOT OLD.instance_id OR NEW.generation IS NOT OLD.generation
    OR NEW.format_version IS NOT OLD.format_version OR NEW.source_sandbox_id IS NOT OLD.source_sandbox_id
    OR NEW.source_backend IS NOT OLD.source_backend OR NEW.source_backend_id IS NOT OLD.source_backend_id
    OR NEW.capture_operation IS NOT OLD.capture_operation OR NEW.capture_helper_epoch IS NOT OLD.capture_helper_epoch
    OR NEW.capture_boot_id IS NOT OLD.capture_boot_id OR NEW.max_size_bytes IS NOT OLD.max_size_bytes
    OR NEW.image IS NOT OLD.image OR NEW.image_content_sha256 IS NOT OLD.image_content_sha256
    OR NEW.read_only_root IS NOT OLD.read_only_root OR NEW.writable_paths IS NOT OLD.writable_paths
    OR NEW.excluded_paths IS NOT OLD.excluded_paths OR NEW.expiry_lifetime_ms IS NOT OLD.expiry_lifetime_ms
    OR NEW.expiry_idle_ms IS NOT OLD.expiry_idle_ms OR NEW.created_at_ms IS NOT OLD.created_at_ms
    OR NEW.complete_evidence_kind IS NOT OLD.complete_evidence_kind
    OR NEW.release_evidence_kind IS NOT OLD.release_evidence_kind OR NEW.request_id IS NOT OLD.request_id
BEGIN SELECT RAISE(ABORT, 'checkpoint identity, owner, source, cap, format, compatibility, expiry policy and key are immutable'); END;
CREATE TRIGGER checkpoints_seal_once BEFORE UPDATE ON checkpoints
WHEN OLD.complete_evidence_id IS NOT NULL AND (NEW.complete_evidence_id IS NOT OLD.complete_evidence_id
    OR NEW.content_sha256 IS NOT OLD.content_sha256 OR NEW.binding_sha256 IS NOT OLD.binding_sha256
    OR NEW.charge_bytes IS NOT OLD.charge_bytes OR NEW.logical_bytes IS NOT OLD.logical_bytes
    OR NEW.allocated_bytes IS NOT OLD.allocated_bytes OR NEW.entry_count IS NOT OLD.entry_count
    OR NEW.ready_at_ms IS NOT OLD.ready_at_ms
    OR (NEW.ready_boottime_ms IS NOT OLD.ready_boottime_ms AND NEW.clock_boot_id IS OLD.clock_boot_id))
BEGIN SELECT RAISE(ABORT, 'a READY seal is written once: no repricing, and its anchor moves only in the cross-boot rebase'); END;
CREATE TRIGGER checkpoints_seal BEFORE UPDATE ON checkpoints
WHEN OLD.complete_evidence_id IS NULL AND (NEW.complete_evidence_id IS NOT NULL OR NEW.content_sha256 IS NOT NULL
        OR NEW.binding_sha256 IS NOT NULL OR NEW.charge_bytes IS NOT NULL OR NEW.logical_bytes IS NOT NULL
        OR NEW.allocated_bytes IS NOT NULL OR NEW.entry_count IS NOT NULL OR NEW.ready_at_ms IS NOT NULL) AND (
    OLD.state IS NOT 'capturing' OR NEW.state IS NOT 'ready' OR NEW.complete_evidence_id IS NULL
    OR NEW.charge_bytes IS NULL OR NEW.charge_bytes < 1 OR NEW.charge_bytes > NEW.max_size_bytes
    OR NOT EXISTS (SELECT 1 FROM checkpoint_evidence e
        WHERE e.evidence_id = NEW.complete_evidence_id AND e.kind = 'complete' AND e.checkpoint_id = NEW.id
          AND e.generation = NEW.generation AND e.operation = NEW.capture_operation AND e.instance_id = NEW.instance_id
          AND e.helper_epoch = NEW.capture_helper_epoch AND e.boot_id = NEW.capture_boot_id
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.charge_bytes') IS NEW.charge_bytes
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.limit_bytes') IS NEW.max_size_bytes
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.logical_bytes') IS NEW.logical_bytes
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.allocated_bytes') IS NEW.allocated_bytes
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.entries') IS NEW.entry_count
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.content_sha256') IS NEW.content_sha256
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.binding_sha256') IS NEW.binding_sha256
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.image') IS NEW.image
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.image_sha256') IS NEW.image_content_sha256
          AND json_extract(CAST(e.evidence AS TEXT), '$.fact.complete.source') IS NEW.source_backend_id)
    OR NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.source_sandbox_id AND state = 'ready'
        AND backend_id = NEW.source_backend_id))
BEGIN SELECT RAISE(ABORT, 'a READY seal needs matching COMPLETE evidence from the capture''s helper epoch and boot, from CAPTURING, while its source is still READY'); END;
CREATE TRIGGER checkpoints_transition BEFORE UPDATE OF state ON checkpoints
WHEN NEW.state IS NOT OLD.state AND (OLD.state, NEW.state) NOT IN (VALUES ('capturing', 'ready'),
    ('capturing', 'deleting'), ('capturing', 'failed'), ('capturing', 'quarantined'), ('ready', 'deleting'),
    ('ready', 'quarantined'), ('quarantined', 'deleting'), ('deleting', 'deleted'), ('failed', 'deleted'))
BEGIN SELECT RAISE(ABORT, 'illegal checkpoint state transition'); END;
CREATE TRIGGER checkpoints_release BEFORE UPDATE ON checkpoints
WHEN OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL AND (
    NEW.state NOT IN ('failed', 'deleted') OR NEW.released_at_ms IS NULL
    OR NOT EXISTS (SELECT 1 FROM checkpoint_evidence e
        WHERE e.evidence_id = NEW.release_evidence_id AND e.kind = 'absent' AND e.checkpoint_id = NEW.id
          AND e.generation = NEW.generation AND e.instance_id = NEW.instance_id AND e.operation = NEW.removal_operation
          AND e.helper_epoch = NEW.removal_helper_epoch AND e.boot_id = NEW.removal_boot_id)
    OR EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = NEW.id AND released_at_ms IS NULL))
BEGIN SELECT RAISE(ABORT, 'a checkpoint charge is released only with ABSENT evidence of its own removal, from its helper epoch and boot, and no live pin'); END;
CREATE TRIGGER checkpoints_release_permanent BEFORE UPDATE ON checkpoints
WHEN OLD.release_evidence_id IS NOT NULL AND (NEW.release_evidence_id IS NOT OLD.release_evidence_id
    OR NEW.released_at_ms IS NOT OLD.released_at_ms)
BEGIN SELECT RAISE(ABORT, 'a released checkpoint cannot be charged or released again'); END;
CREATE TRIGGER checkpoints_removal_dispatch BEFORE UPDATE ON checkpoints
WHEN (NEW.removal_operation IS NOT OLD.removal_operation OR NEW.removal_helper_epoch IS NOT OLD.removal_helper_epoch
        OR NEW.removal_boot_id IS NOT OLD.removal_boot_id)
    AND (OLD.release_evidence_id IS NOT NULL OR NEW.state NOT IN ('capturing', 'deleting')
        OR NEW.removal_operation IS NULL OR NEW.removal_operation IS OLD.removal_operation
        OR NEW.removal_operation = NEW.capture_operation)
BEGIN SELECT RAISE(ABORT, 'a removal is dispatched with a fresh nonce, while CAPTURING or DELETING and unreleased'); END;
CREATE TRIGGER checkpoints_deletion_reason_once BEFORE UPDATE ON checkpoints
WHEN (OLD.deletion_reason IS NOT NULL AND NEW.deletion_reason IS NOT OLD.deletion_reason)
    OR (OLD.deletion_reason IS NULL AND NEW.deletion_reason IS NOT NULL AND NEW.state NOT IN ('deleting', 'deleted'))
BEGIN SELECT RAISE(ABORT, 'a checkpoint deletion reason is written once, with DELETING or DELETED'); END;
CREATE TRIGGER checkpoints_failure_once BEFORE UPDATE ON checkpoints
WHEN (OLD.failure_token IS NOT NULL AND (NEW.failure_token IS NOT OLD.failure_token OR NEW.failure_reason IS NOT OLD.failure_reason))
    OR (OLD.failure_token IS NULL AND NEW.failure_token IS NOT NULL
        AND NEW.state NOT IN ('capturing', 'failed', 'quarantined', 'deleting'))
BEGIN SELECT RAISE(ABORT, 'a checkpoint failure is written once, before its row settles'); END;
CREATE TRIGGER checkpoints_activity_seq_monotonic BEFORE UPDATE ON checkpoints
WHEN NEW.activity_seq < OLD.activity_seq
BEGIN SELECT RAISE(ABORT, 'checkpoint activity_seq only increases'); END;
CREATE TRIGGER checkpoints_expiry_intent_anchor BEFORE UPDATE ON checkpoints
WHEN (OLD.expiry_intent_at_ms IS NOT NULL AND NEW.expiry_intent_at_ms IS NOT OLD.expiry_intent_at_ms)
    OR (OLD.expiry_intent_boottime_ms IS NOT NULL AND NEW.expiry_intent_boottime_ms IS NOT OLD.expiry_intent_boottime_ms
        AND NEW.clock_boot_id IS OLD.clock_boot_id)
    OR ((NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL)
        AND (NEW.deletion_reason IS NULL OR NEW.deletion_reason NOT IN ('expired_idle', 'expired_lifetime')))
BEGIN SELECT RAISE(ABORT, 'a checkpoint expiry intent anchor is written once, with its reason, and moves only in the cross-boot rebase'); END;
CREATE TRIGGER checkpoints_request_id_released BEFORE UPDATE ON checkpoints
WHEN (OLD.request_id_released_at_ms IS NOT NULL AND NEW.request_id_released_at_ms IS NOT OLD.request_id_released_at_ms)
    OR (OLD.request_id_released_at_ms IS NULL AND NEW.request_id_released_at_ms IS NOT NULL
        AND EXISTS (SELECT 1 FROM checkpoint_requests WHERE checkpoint_id = NEW.id))
BEGIN SELECT RAISE(ABORT, 'a capture request ID is released once, after its record, from DELETED'); END;
CREATE TRIGGER checkpoints_no_charged_delete BEFORE DELETE ON checkpoints
WHEN OLD.release_evidence_id IS NULL
    OR EXISTS (SELECT 1 FROM checkpoint_requests WHERE checkpoint_id = OLD.id)
    OR EXISTS (SELECT 1 FROM checkpoint_pins WHERE checkpoint_id = OLD.id)
BEGIN SELECT RAISE(ABORT, 'a charged, keyed or pinned checkpoint row cannot be deleted'); END;
CREATE TRIGGER checkpoints_released_unsettled AFTER UPDATE ON checkpoints
WHEN OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL
BEGIN INSERT OR IGNORE INTO checkpoint_unsettled VALUES (NEW.id); END;

-- Counts: node (-1) and per owner, kept by triggers on every insert, charge change and delete.
CREATE TRIGGER checkpoints_count_insert AFTER INSERT ON checkpoints
BEGIN
    INSERT INTO checkpoint_counts VALUES (NEW.owner_uid, 0, 0, 0, 0) ON CONFLICT(owner_uid) DO NOTHING;
    UPDATE checkpoint_counts SET live = live + (NEW.release_evidence_id IS NULL),
        charged_bytes = charged_bytes + CASE WHEN NEW.release_evidence_id IS NULL THEN COALESCE(NEW.charge_bytes, NEW.max_size_bytes) ELSE 0 END,
        records = records + 1
    WHERE owner_uid IN (NEW.owner_uid, -1);
END;
CREATE TRIGGER checkpoints_count_update AFTER UPDATE ON checkpoints
WHEN (OLD.release_evidence_id IS NULL) IS NOT (NEW.release_evidence_id IS NULL)
    OR OLD.charge_bytes IS NOT NEW.charge_bytes OR OLD.max_size_bytes IS NOT NEW.max_size_bytes
BEGIN
    UPDATE checkpoint_counts SET live = live - (OLD.release_evidence_id IS NULL) + (NEW.release_evidence_id IS NULL),
        charged_bytes = charged_bytes
            - CASE WHEN OLD.release_evidence_id IS NULL THEN COALESCE(OLD.charge_bytes, OLD.max_size_bytes) ELSE 0 END
            + CASE WHEN NEW.release_evidence_id IS NULL THEN COALESCE(NEW.charge_bytes, NEW.max_size_bytes) ELSE 0 END
    WHERE owner_uid IN (NEW.owner_uid, -1);
END;
CREATE TRIGGER checkpoints_count_delete AFTER DELETE ON checkpoints
BEGIN
    UPDATE checkpoint_counts SET live = live - (OLD.release_evidence_id IS NULL),
        charged_bytes = charged_bytes - CASE WHEN OLD.release_evidence_id IS NULL THEN COALESCE(OLD.charge_bytes, OLD.max_size_bytes) ELSE 0 END,
        records = records - 1
    WHERE owner_uid IN (OLD.owner_uid, -1);
    DELETE FROM checkpoint_counts WHERE owner_uid = OLD.owner_uid AND owner_uid != -1
        AND live = 0 AND charged_bytes = 0 AND records = 0 AND keys = 0;
END;
CREATE TRIGGER checkpoint_counts_identity BEFORE UPDATE OF owner_uid ON checkpoint_counts
WHEN NEW.owner_uid IS NOT OLD.owner_uid
BEGIN SELECT RAISE(ABORT, 'checkpoint count identity is immutable'); END;
CREATE TRIGGER checkpoint_sequence_no_replace BEFORE INSERT ON checkpoint_sequence
WHEN EXISTS (SELECT 1 FROM checkpoint_sequence WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'checkpoint sequence cannot be replaced'); END;
CREATE TRIGGER checkpoint_sequence_monotonic BEFORE UPDATE ON checkpoint_sequence
WHEN NEW.id IS NOT OLD.id OR NEW.value < OLD.value
BEGIN SELECT RAISE(ABORT, 'checkpoint sequence only increases'); END;
CREATE TRIGGER checkpoint_membership_no_replace BEFORE INSERT ON checkpoint_membership
WHEN EXISTS (SELECT 1 FROM checkpoint_membership WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'checkpoint membership cannot be replaced'); END;

-- Capture keys (design 7.1): M2's grammar and retention, a separate namespace.
CREATE TRIGGER checkpoint_requests_no_replace BEFORE INSERT ON checkpoint_requests
WHEN EXISTS (SELECT 1 FROM checkpoint_requests
    WHERE (owner_uid = NEW.owner_uid AND request_id = NEW.request_id) OR checkpoint_id = NEW.checkpoint_id)
BEGIN SELECT RAISE(ABORT, 'a capture request record cannot be replaced'); END;
CREATE TRIGGER checkpoint_requests_own_checkpoint BEFORE INSERT ON checkpoint_requests
WHEN NOT EXISTS (SELECT 1 FROM checkpoints WHERE id = NEW.checkpoint_id AND owner_uid = NEW.owner_uid
    AND request_id = NEW.request_id AND state = 'capturing')
BEGIN SELECT RAISE(ABORT, 'a capture request record is inserted with its own CAPTURING checkpoint'); END;
CREATE TRIGGER checkpoint_requests_unanchored_insert BEFORE INSERT ON checkpoint_requests
WHEN NEW.retain_boot_id IS NOT NULL OR NEW.retain_from_boottime_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a capture request record is inserted unanchored and anchored only after it commits'); END;
CREATE TRIGGER checkpoint_requests_fixed BEFORE UPDATE ON checkpoint_requests
WHEN NEW.owner_uid IS NOT OLD.owner_uid OR NEW.request_id IS NOT OLD.request_id
    OR NEW.request_sha256 IS NOT OLD.request_sha256 OR NEW.digest_version IS NOT OLD.digest_version
    OR NEW.checkpoint_id IS NOT OLD.checkpoint_id OR NEW.created_at_ms IS NOT OLD.created_at_ms
    OR (OLD.retain_boot_id IS NOT NULL AND NEW.retain_boot_id IS NULL)
    OR (NEW.retain_from_boottime_ms IS NOT OLD.retain_from_boottime_ms AND NEW.retain_boot_id IS OLD.retain_boot_id)
BEGIN SELECT RAISE(ABORT, 'a capture request record changes only when anchored or in the cross-boot retention rebase'); END;
CREATE TRIGGER checkpoint_requests_settled_delete BEFORE DELETE ON checkpoint_requests
WHEN NOT EXISTS (SELECT 1 FROM checkpoints WHERE id = OLD.checkpoint_id AND state IN ('deleted', 'failed')
    AND release_evidence_id IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'a capture request record is kept until its checkpoint is DELETED or FAILED'); END;
CREATE TRIGGER checkpoint_requests_count_insert AFTER INSERT ON checkpoint_requests
BEGIN
    INSERT INTO checkpoint_counts VALUES (NEW.owner_uid, 0, 0, 0, 0) ON CONFLICT(owner_uid) DO NOTHING;
    UPDATE checkpoint_counts SET keys = keys + 1 WHERE owner_uid IN (NEW.owner_uid, -1);
END;
CREATE TRIGGER checkpoint_requests_count_delete AFTER DELETE ON checkpoint_requests
BEGIN
    UPDATE checkpoint_counts SET keys = keys - 1 WHERE owner_uid IN (OLD.owner_uid, -1);
    DELETE FROM checkpoint_counts WHERE owner_uid = OLD.owner_uid AND owner_uid != -1
        AND live = 0 AND charged_bytes = 0 AND records = 0 AND keys = 0;
END;

-- Fork pins (design 7.2 and 9): a durable artifact read-pin, committed with its fork's
-- CREATING row before any dispatch, released once with validated reader evidence.
CREATE TRIGGER checkpoint_pins_no_replace BEFORE INSERT ON checkpoint_pins
WHEN EXISTS (SELECT 1 FROM checkpoint_pins WHERE sandbox_id = NEW.sandbox_id OR reader_operation = NEW.reader_operation)
BEGIN SELECT RAISE(ABORT, 'a checkpoint pin cannot be replaced'); END;
CREATE TRIGGER checkpoint_pins_insert BEFORE INSERT ON checkpoint_pins
WHEN NEW.released_at_ms IS NOT NULL OR NEW.released_by IS NOT NULL OR NEW.release_evidence_id IS NOT NULL
    OR NOT EXISTS (SELECT 1 FROM checkpoints c JOIN sandboxes s ON s.id = NEW.sandbox_id
        WHERE c.id = NEW.checkpoint_id AND c.state = 'ready' AND c.generation = NEW.generation
          AND c.content_sha256 = NEW.content_sha256 AND s.state = 'creating'
          AND s.from_checkpoint = NEW.checkpoint_id AND s.checkpoint_content_sha256 = NEW.content_sha256
          AND (s.owner_uid = c.owner_uid OR s.owner_uid = 0) AND s.reserved_disk_bytes >= c.charge_bytes
          AND json_extract(s.spec, '$.image') = c.image AND json_extract(s.spec, '$.read_only_root') = c.read_only_root)
BEGIN SELECT RAISE(ABORT, 'a pin is taken unreleased on a READY checkpoint by its own CREATING fork, with the same generation, digest and image'); END;
CREATE TRIGGER checkpoint_pins_fixed BEFORE UPDATE ON checkpoint_pins
WHEN NEW.sandbox_id IS NOT OLD.sandbox_id OR NEW.checkpoint_id IS NOT OLD.checkpoint_id
    OR NEW.generation IS NOT OLD.generation OR NEW.content_sha256 IS NOT OLD.content_sha256
    OR NEW.reader_operation IS NOT OLD.reader_operation OR NEW.helper_epoch IS NOT OLD.helper_epoch
    OR NEW.boot_id IS NOT OLD.boot_id OR NEW.pinned_at_ms IS NOT OLD.pinned_at_ms
    OR (OLD.released_at_ms IS NOT NULL AND (NEW.released_at_ms IS NOT OLD.released_at_ms
        OR NEW.released_by IS NOT OLD.released_by OR NEW.release_evidence_id IS NOT OLD.release_evidence_id))
BEGIN SELECT RAISE(ABORT, 'a pin''s target is fixed and it is released once'); END;
CREATE TRIGGER checkpoint_pins_release BEFORE UPDATE ON checkpoint_pins
WHEN OLD.released_at_ms IS NULL AND NEW.released_at_ms IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM checkpoint_evidence e
    WHERE e.evidence_id = NEW.release_evidence_id AND e.checkpoint_id = NEW.checkpoint_id AND e.generation = NEW.generation
      AND ((NEW.released_by IN ('complete', 'not_started') AND e.kind = 'reader_ended' AND e.operation = NEW.reader_operation
            AND e.helper_epoch = NEW.helper_epoch AND e.boot_id = NEW.boot_id
            AND json_extract(CAST(e.evidence AS TEXT), '$.fact.reader_ended.copy') IS NEW.released_by)
        OR (NEW.released_by = 'absent' AND e.kind = 'absent' AND EXISTS (SELECT 1 FROM checkpoints c
            WHERE c.id = NEW.checkpoint_id AND c.instance_id = e.instance_id AND c.removal_operation = e.operation
              AND c.removal_helper_epoch = e.helper_epoch AND c.removal_boot_id = e.boot_id))))
BEGIN SELECT RAISE(ABORT, 'a pin is released only with its reader''s complete or not-started evidence from the reader''s helper epoch and boot, or its checkpoint''s ABSENT evidence'); END;
CREATE TRIGGER checkpoint_pins_no_live_delete BEFORE DELETE ON checkpoint_pins
WHEN OLD.released_at_ms IS NULL
BEGIN SELECT RAISE(ABORT, 'a live checkpoint pin cannot be deleted'); END;

-- Sandboxes: immutable fork provenance, and image identity recorded once.
ALTER TABLE sandboxes ADD COLUMN from_checkpoint TEXT CHECK (from_checkpoint IS NULL OR (typeof(from_checkpoint) = 'text' AND length(from_checkpoint) = 35 AND substr(from_checkpoint, 1, 3) = 'cp-' AND substr(from_checkpoint, 4) NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE sandboxes ADD COLUMN checkpoint_content_sha256 TEXT CHECK ((checkpoint_content_sha256 IS NULL) = (from_checkpoint IS NULL) AND (checkpoint_content_sha256 IS NULL OR (typeof(checkpoint_content_sha256) = 'text' AND length(checkpoint_content_sha256) = 64 AND checkpoint_content_sha256 NOT GLOB '*[^0-9a-f]*')));
ALTER TABLE sandboxes ADD COLUMN image_content_sha256 TEXT CHECK (image_content_sha256 IS NULL OR (typeof(image_content_sha256) = 'text' AND length(image_content_sha256) = 64 AND image_content_sha256 NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE sandboxes ADD COLUMN checkpoint_format_version INTEGER CHECK ((checkpoint_format_version IS NULL) = (image_content_sha256 IS NULL) AND (checkpoint_format_version IS NULL OR (typeof(checkpoint_format_version) = 'integer' AND checkpoint_format_version = 1)));
CREATE TRIGGER sandboxes_checkpoint_insert BEFORE INSERT ON sandboxes
WHEN NEW.from_checkpoint IS NOT NULL AND NEW.state != 'creating'
BEGIN SELECT RAISE(ABORT, 'a fork records its checkpoint with its CREATING row'); END;
CREATE TRIGGER sandboxes_checkpoint_fixed BEFORE UPDATE ON sandboxes
WHEN NEW.from_checkpoint IS NOT OLD.from_checkpoint OR NEW.checkpoint_content_sha256 IS NOT OLD.checkpoint_content_sha256
    OR (OLD.image_content_sha256 IS NOT NULL AND (NEW.image_content_sha256 IS NOT OLD.image_content_sha256
        OR NEW.checkpoint_format_version IS NOT OLD.checkpoint_format_version))
BEGIN SELECT RAISE(ABORT, 'checkpoint provenance is fixed at insert and image identity is recorded once'); END;

-- Create request records: the M2 digest discriminator (design 7.2).
ALTER TABLE create_requests ADD COLUMN digest_version INTEGER NOT NULL DEFAULT 1 CHECK (typeof(digest_version) = 'integer' AND digest_version IN (1, 2));
DROP TRIGGER create_requests_fixed;
CREATE TRIGGER create_requests_fixed BEFORE UPDATE ON create_requests
WHEN NEW.owner_uid IS NOT OLD.owner_uid OR NEW.request_id IS NOT OLD.request_id
    OR NEW.request_sha256 IS NOT OLD.request_sha256 OR NEW.sandbox_id IS NOT OLD.sandbox_id
    OR NEW.created_at_ms IS NOT OLD.created_at_ms OR NEW.digest_version IS NOT OLD.digest_version
    OR (OLD.retain_boot_id IS NOT NULL AND NEW.retain_boot_id IS NULL)
    OR (NEW.retain_from_boottime_ms IS NOT OLD.retain_from_boottime_ms AND NEW.retain_boot_id IS OLD.retain_boot_id)
BEGIN SELECT RAISE(ABORT, 'a create request record changes only when anchored or in the cross-boot retention rebase'); END;
CREATE TRIGGER create_requests_digest_version BEFORE INSERT ON create_requests
WHEN NEW.digest_version IS NOT (SELECT CASE WHEN from_checkpoint IS NULL THEN 1 ELSE 2 END FROM sandboxes WHERE id = NEW.sandbox_id)
BEGIN SELECT RAISE(ABORT, 'a create request digest is version 2 exactly for a create from a checkpoint'); END;
PRAGMA user_version = 15;";

// Schema 16 (C5a-1 round 5): the checkpoint barrier's durable obligation, apart from any
// row. Reconciliation writes the one row when it blocks and only a complete clean
// inventory deletes it; retention never touches it. Startup reads it in the same single
// existence query as the checkpoint rows and keys.
pub(super) const MIGRATE_V16: &str = "
CREATE TABLE checkpoint_barrier (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    set_at_ms INTEGER NOT NULL CHECK (typeof(set_at_ms) = 'integer')
);
PRAGMA user_version = 16;";
