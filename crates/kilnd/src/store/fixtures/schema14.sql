PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE history_sequence (id INTEGER PRIMARY KEY CHECK(id = 1), value INTEGER NOT NULL);
INSERT INTO history_sequence VALUES(1,15);
CREATE TABLE daemon_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    database_uuid TEXT NOT NULL CHECK (length(database_uuid) = 32 AND database_uuid NOT GLOB '*[^0-9a-f]*'),
    instance_id TEXT NOT NULL CHECK (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*')
);
INSERT INTO daemon_identity VALUES(1,'bd916d6a380eaf0af253d758f3c4c141','4ab470195814094ff0c5cb30db39be81');
CREATE TABLE release_evidence (
    receipt_id TEXT PRIMARY KEY NOT NULL CHECK (length(receipt_id) = 32 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    node_id TEXT NOT NULL CHECK (length(node_id) = 32 AND node_id NOT GLOB '*[^0-9a-f]*'),
    instance_id TEXT NOT NULL CHECK (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*'),
    allocation_id TEXT NOT NULL UNIQUE CHECK (length(allocation_id) = 32 AND allocation_id NOT GLOB '*[^0-9a-f]*'),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
    helper_generation INTEGER NOT NULL CHECK (typeof(helper_generation) = 'integer' AND helper_generation >= 1),
    kind TEXT NOT NULL CHECK (kind = 'absent_fenced'),
    receipt BLOB NOT NULL CHECK (typeof(receipt) = 'blob' AND length(receipt) BETWEEN 1 AND 16384),
    recorded_at_ms INTEGER NOT NULL,
    UNIQUE (node_id, instance_id, allocation_id, plan_digest, helper_generation, kind),
    UNIQUE (receipt_id, node_id, instance_id, allocation_id, plan_digest, kind)
);
INSERT INTO release_evidence VALUES('ebf96d7e35fae1ae4ef22ec69334c1c6','a3b2e55d0017856f0119d790713a5c42','73592ccd17bda6baad0a5fbf7c9e4c22','dc9d800db3b490deca6e98e190880ed5','ad41e7f236f51d495e13ae0ed6b1fe0f6ef70d213af018bb54186687a6b53ee5',7,'absent_fenced',x'7b22726563656970745f6964223a226562663936643765333566616531616534656632326563363933333463316336222c226e6f64655f6964223a226133623265353564303031373835366630313139643739303731336135633432222c22696e7374616e63655f6964223a223733353932636364313762646136626161643061356662663763396534633232222c22616c6c6f636174696f6e5f6964223a226463396438303064623362343930646563613665393865313930383830656435222c22706c616e5f646967657374223a2261643431653766323336663531643439356531336165306564366231666530663665663730643231336166303138626235343138363638376136623533656535222c2268656c7065725f67656e65726174696f6e223a372c226f62736572766174696f6e73223a22227d',1794513631099);
CREATE TABLE IF NOT EXISTS "sandboxes" (
    id             TEXT PRIMARY KEY,
    backend        TEXT NOT NULL,
    backend_id     TEXT,
    state          TEXT NOT NULL,
    spec           TEXT NOT NULL,
    failure_reason TEXT,
    created_at_ms  INTEGER NOT NULL,
    updated_at_ms  INTEGER NOT NULL,
    deleted_at_ms  INTEGER,
    list_seq       INTEGER NOT NULL,
    create_certainty TEXT NOT NULL DEFAULT 'allocation_ambiguous' CHECK (create_certainty = 'allocation_ambiguous' OR (create_certainty = 'definitely_not_created' AND backend_id IS NULL AND state IN ('failed', 'deleted'))),
    owner_uid INTEGER NOT NULL DEFAULT 0 CHECK (owner_uid BETWEEN 0 AND 4294967295),
    accounting_kind TEXT NOT NULL CHECK (accounting_kind IN ('legacy', 'fenced')),
    reserved_memory_bytes INTEGER NOT NULL CHECK (typeof(reserved_memory_bytes) = 'integer' AND reserved_memory_bytes >= 0),
    reserved_disk_bytes INTEGER NOT NULL CHECK (typeof(reserved_disk_bytes) = 'integer' AND reserved_disk_bytes >= 0),
    reserved_pids INTEGER NOT NULL CHECK (typeof(reserved_pids) = 'integer' AND reserved_pids >= 0),
    reserved_host_cpu_millis INTEGER NOT NULL CHECK (typeof(reserved_host_cpu_millis) = 'integer' AND reserved_host_cpu_millis >= 0),
    reserved_virtual_cpu_slots INTEGER NOT NULL CHECK (typeof(reserved_virtual_cpu_slots) = 'integer' AND reserved_virtual_cpu_slots >= 0),
    reserved_host_pids INTEGER NOT NULL CHECK (typeof(reserved_host_pids) = 'integer' AND reserved_host_pids >= 0),
    host_spec_sha256 TEXT NOT NULL CHECK (length(host_spec_sha256) = 64 AND host_spec_sha256 NOT GLOB '*[^0-9a-f]*'),
    guest_exec_spec_sha256 TEXT NOT NULL CHECK (length(guest_exec_spec_sha256) = 64 AND guest_exec_spec_sha256 NOT GLOB '*[^0-9a-f]*'),
    runtime_profile TEXT NOT NULL DEFAULT '',
    runtime_artifact_digest TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT 'reusable' CHECK (disposition IN ('reusable', 'stopped', 'quarantined')),
    boot_id TEXT,
    runtime_receipt BLOB CHECK (runtime_receipt IS NULL OR length(runtime_receipt) <= 16384),
    legacy_release TEXT,
    node_id TEXT CHECK (node_id IS NULL OR (length(node_id) = 32 AND node_id NOT GLOB '*[^0-9a-f]*')),
    instance_id TEXT CHECK (instance_id IS NULL OR (length(instance_id) = 32 AND instance_id NOT GLOB '*[^0-9a-f]*')),
    allocation_id TEXT CHECK (allocation_id IS NULL OR (length(allocation_id) = 32 AND allocation_id NOT GLOB '*[^0-9a-f]*')),
    plan_version INTEGER CHECK (plan_version IS NULL OR plan_version BETWEEN 0 AND 4294967295),
    plan_digest TEXT CHECK (plan_digest IS NULL OR (length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*')),
    plan BLOB CHECK (plan IS NULL OR (typeof(plan) = 'blob' AND length(plan) BETWEEN 1 AND 131072)),
    release_evidence_id TEXT,
    release_evidence_kind TEXT NOT NULL DEFAULT 'absent_fenced' CHECK (release_evidence_kind = 'absent_fenced'),
    last_helper_generation INTEGER CHECK (last_helper_generation IS NULL OR (typeof(last_helper_generation) = 'integer' AND last_helper_generation >= 0)), expiry_lifetime_ms INTEGER CHECK (expiry_lifetime_ms IS NULL OR (typeof(expiry_lifetime_ms) = 'integer' AND expiry_lifetime_ms > 0)), expiry_idle_ms INTEGER CHECK (expiry_idle_ms IS NULL OR (typeof(expiry_idle_ms) = 'integer' AND expiry_idle_ms > 0)), ready_at_ms INTEGER CHECK (ready_at_ms IS NULL OR typeof(ready_at_ms) = 'integer'), ready_boottime_ms INTEGER CHECK (ready_boottime_ms IS NULL OR typeof(ready_boottime_ms) = 'integer'), activity_at_ms INTEGER CHECK (activity_at_ms IS NULL OR typeof(activity_at_ms) = 'integer'), activity_boottime_ms INTEGER CHECK (activity_boottime_ms IS NULL OR typeof(activity_boottime_ms) = 'integer'), clock_boot_id TEXT CHECK (clock_boot_id IS NULL OR (typeof(clock_boot_id) = 'text' AND length(clock_boot_id) BETWEEN 1 AND 64)), activity_seq INTEGER NOT NULL DEFAULT 0 CHECK (typeof(activity_seq) = 'integer' AND activity_seq >= 0), deletion_reason TEXT CHECK (deletion_reason IS NULL OR deletion_reason IN ('requested', 'expired_idle', 'expired_lifetime')), expiry_intent_at_ms INTEGER CHECK (expiry_intent_at_ms IS NULL OR typeof(expiry_intent_at_ms) = 'integer'), expiry_intent_boottime_ms INTEGER CHECK (expiry_intent_boottime_ms IS NULL OR typeof(expiry_intent_boottime_ms) = 'integer'), request_id TEXT CHECK (request_id IS NULL OR (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*')), request_id_released_at_ms INTEGER CHECK (request_id_released_at_ms IS NULL OR typeof(request_id_released_at_ms) = 'integer'), default_env_names TEXT CHECK (default_env_names IS NULL OR (typeof(default_env_names) = 'text' AND json_valid(default_env_names) AND json_type(default_env_names) = 'array' AND json_array_length(default_env_names) BETWEEN 1 AND 64)), default_env_sha256 TEXT CHECK ((default_env_sha256 IS NULL) = (default_env_names IS NULL) AND (default_env_sha256 IS NULL OR (typeof(default_env_sha256) = 'text' AND length(default_env_sha256) = 64 AND default_env_sha256 NOT GLOB '*[^0-9a-f]*'))), default_env TEXT CHECK (default_env IS NULL OR (typeof(default_env) = 'text' AND default_env_names IS NOT NULL AND state NOT IN ('failed', 'deleted'))), exec_features INTEGER CHECK (exec_features IS NULL OR (typeof(exec_features) = 'integer' AND exec_features BETWEEN 0 AND 4294967295)),
    CHECK (legacy_release IS NULL
        OR (legacy_release = 'deleted' AND state = 'deleted')
        OR (legacy_release = 'compensated' AND state = 'failed' AND backend_id IS NOT NULL)
        OR (legacy_release = 'definitely_not_created' AND state = 'failed' AND backend_id IS NULL AND create_certainty = 'definitely_not_created')),
    CHECK (accounting_kind = 'fenced' OR state != 'deleted' OR legacy_release IS 'deleted'),
    CHECK (accounting_kind = 'fenced' OR (release_evidence_id IS NULL AND node_id IS NULL AND instance_id IS NULL AND allocation_id IS NULL AND plan_version IS NULL AND plan_digest IS NULL AND plan IS NULL AND last_helper_generation IS NULL)),
    CHECK (accounting_kind = 'legacy' OR (legacy_release IS NULL AND create_certainty = 'allocation_ambiguous'
        AND node_id IS NOT NULL AND instance_id IS NOT NULL AND allocation_id IS NOT NULL
        AND plan_version IS NOT NULL AND plan_digest IS NOT NULL AND plan IS NOT NULL AND last_helper_generation IS NOT NULL)),
    CHECK (release_evidence_id IS NULL OR state IN ('failed', 'deleted')),
    CHECK (accounting_kind = 'legacy' OR state != 'deleted' OR release_evidence_id IS NOT NULL),
    CHECK (accounting_kind = 'legacy' OR state != 'creating' OR backend_id IS NULL),
    CHECK (accounting_kind = 'legacy' OR backend_id IS NULL OR backend_id = 'fc-' || allocation_id),
    CHECK (accounting_kind = 'legacy' OR state != 'ready' OR (backend_id IS NOT NULL AND boot_id IS NOT NULL AND runtime_receipt IS NOT NULL AND last_helper_generation >= 1)),
    FOREIGN KEY (release_evidence_id, node_id, instance_id, allocation_id, plan_digest, release_evidence_kind)
        REFERENCES release_evidence (receipt_id, node_id, instance_id, allocation_id, plan_digest, kind)
);
INSERT INTO sandboxes VALUES('sb-c4fixture0000','fake',NULL,'creating','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631078,1794513631078,NULL,1,'allocation_ambiguous',1001,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0001','fake','aa01','ready','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631080,1794513631080,NULL,2,'allocation_ambiguous',1002,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0002','fake','aa02','deleted','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631081,1794513631101,1794513631101,3,'allocation_ambiguous',1003,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'deleted',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0003','fake','aa03','lost','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631082,1794513631082,NULL,4,'allocation_ambiguous',1004,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0004','fake',NULL,'failed','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631083,1794513631083,NULL,5,'allocation_ambiguous',1005,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0005','fake',NULL,'failed','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631083,1794513631083,NULL,6,'definitely_not_created',1006,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'definitely_not_created',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0006','fake','aa04','failed','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631084,1794513631084,NULL,7,'allocation_ambiguous',1007,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'compensated',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0007','fake',NULL,'deleted','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631085,1794513631085,NULL,8,'allocation_ambiguous',1008,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'deleted',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0008','fake','aa05','quarantined','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631086,1794513631086,NULL,9,'allocation_ambiguous',1009,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,3600000,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture0009','fake','bb0a','ready','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631087,1794513631088,NULL,10,'allocation_ambiguous',1000,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,NULL,1800000009000,1009000,1800000009000,1009000,'boot-a',0,NULL,NULL,NULL,'key-ready',NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture000a','fake','bb0b','deleted','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631089,1794513631091,1794513631091,11,'allocation_ambiguous',1000,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'deleted',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,NULL,1800000010000,1010000,1800000010000,1010000,'boot-a',0,NULL,NULL,NULL,'key-released',1794513631091,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture000b','fake','bb0c','deleted','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631092,1794513631094,1794513631094,12,'allocation_ambiguous',1000,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,'deleted',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,NULL,1800000011000,1011000,1800000011000,1011000,'boot-a',0,NULL,NULL,NULL,'key-deleted',NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture000c','fake','cc01','ready','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":{"allow":["example.com:443"]},"read_only_root":true,"writable_paths":["/data"],"labels":{"owner":"tests"}}',NULL,1794513631095,1794513631096,NULL,13,'allocation_ambiguous',0,'legacy',536870912,1073741824,128,0,0,0,'ab97e0b2cc5bb885ddd9c687944bf717d3732c73494164c8b875d90b9c9b9cb6','4fcf0078d27c751ab03d2d7afaae27768947acd9717696798a8031484beb812d','','','reusable',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'absent_fenced',NULL,NULL,NULL,1800000012000,1012000,1800000012000,1012000,'boot-a',1,NULL,NULL,NULL,NULL,NULL,'["A","B"]','fdde53433a0bc0d36c5a8c4fa3c92e1591e6f309b834a606db1aada4bf4fd246','[["A","1"],["B","2"]]',NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture000d','fake',NULL,'creating','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":"none","read_only_root":false,"writable_paths":[],"labels":{}}',NULL,1794513631097,1794513631097,NULL,14,'allocation_ambiguous',0,'fenced',939524096,1476395008,192,1000,1,32,'cb049152516f3b1411f542e225b64f97dd3cfdc6d75ef3799a19af998b75e08b','24efdf3fc3f1f3a34a8100f6c894d0d117239ccc51ffa1ef7866f3775d71c0a2','offline-768-v1','','reusable',NULL,NULL,NULL,'55fd7ac8b3b05ff67a3adcee4511c676','548201c679084af8ae311b9604b865cd','2cd12b338f345e7bc206e0327324e98c',1,'ad41e7f236f51d495e13ae0ed6b1fe0f6ef70d213af018bb54186687a6b53ee5',x'696d6d757461626c6520706c616e',NULL,'absent_fenced',0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO sandboxes VALUES('sb-c4fixture000e','fake',NULL,'failed','{"image":"alpine","memory_bytes":536870912,"cpu_millis":1000,"pids":128,"disk_bytes":1073741824,"network":"none","read_only_root":false,"writable_paths":[],"labels":{}}',NULL,1794513631097,1794513631099,NULL,15,'allocation_ambiguous',0,'fenced',939524096,1476395008,192,1000,1,32,'cb049152516f3b1411f542e225b64f97dd3cfdc6d75ef3799a19af998b75e08b','24efdf3fc3f1f3a34a8100f6c894d0d117239ccc51ffa1ef7866f3775d71c0a2','offline-768-v1','','reusable',NULL,NULL,NULL,'a3b2e55d0017856f0119d790713a5c42','73592ccd17bda6baad0a5fbf7c9e4c22','dc9d800db3b490deca6e98e190880ed5',1,'ad41e7f236f51d495e13ae0ed6b1fe0f6ef70d213af018bb54186687a6b53ee5',x'696d6d757461626c6520706c616e','ebf96d7e35fae1ae4ef22ec69334c1c6','absent_fenced',7,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
CREATE TABLE IF NOT EXISTS "executions" (
    id               TEXT PRIMARY KEY,
    sandbox_id       TEXT NOT NULL REFERENCES "sandboxes" (id),
    argv             TEXT NOT NULL,
    state            TEXT NOT NULL,
    exit_code        INTEGER,
    failure_reason   TEXT,
    timeout_ms       INTEGER NOT NULL,
    stdin_bytes      INTEGER NOT NULL,
    started_at_ms    INTEGER NOT NULL,
    finished_at_ms   INTEGER,
    stdout           BLOB NOT NULL DEFAULT x'',
    stdout_bytes     INTEGER NOT NULL DEFAULT 0,
    stdout_truncated INTEGER NOT NULL DEFAULT 0,
    stdout_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    stderr           BLOB NOT NULL DEFAULT x'',
    stderr_bytes     INTEGER NOT NULL DEFAULT 0,
    stderr_truncated INTEGER NOT NULL DEFAULT 0,
    stderr_total_bytes_known INTEGER NOT NULL DEFAULT 0,
    command_status_kind TEXT,
    command_status_value INTEGER,
    command_core_dumped INTEGER,
    runtime_error TEXT,
    sandbox_reusable INTEGER CHECK (sandbox_reusable IS NULL OR sandbox_reusable IN (0, 1)),
    cleanup_evidence TEXT NOT NULL DEFAULT 'unknown' CHECK (cleanup_evidence IN ('unknown', 'no_child_started', 'runtime_drained', 'sandbox_stopped'))
, cancel_reason TEXT CHECK (cancel_reason IS NULL OR cancel_reason IN ('client_disconnected', 'sandbox_deleted', 'daemon_shutdown', 'sandbox_expired_lifetime')), cwd TEXT CHECK (cwd IS NULL OR (typeof(cwd) = 'text' AND substr(cwd, 1, 1) = '/' AND length(CAST(cwd AS BLOB)) <= 4096)), env_names TEXT CHECK (env_names IS NULL OR (typeof(env_names) = 'text' AND json_valid(env_names) AND json_type(env_names) = 'array' AND json_array_length(env_names) BETWEEN 1 AND 64)), env_sha256 TEXT CHECK ((env_sha256 IS NULL) = (env_names IS NULL) AND (env_sha256 IS NULL OR (typeof(env_sha256) = 'text' AND length(env_sha256) = 64 AND env_sha256 NOT GLOB '*[^0-9a-f]*'))), mode TEXT CHECK (mode IS NULL OR (typeof(mode) = 'text' AND mode IN ('unary', 'stream'))));
INSERT INTO executions VALUES('ex-c4fixture0000','sb-c4fixture000c','["sh","-c","echo ''hi''"]','running',NULL,NULL,1000,3,1794513631096,NULL,x'',0,0,0,x'',0,0,0,NULL,NULL,NULL,NULL,NULL,'unknown',NULL,NULL,NULL,NULL,NULL);
CREATE TABLE create_requests (
    owner_uid INTEGER NOT NULL CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN 0 AND 4294967295),
    request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 64 AND request_id NOT GLOB '*[^!-~]*'),
    request_sha256 TEXT NOT NULL CHECK (typeof(request_sha256) = 'text' AND length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    sandbox_id TEXT NOT NULL UNIQUE REFERENCES sandboxes (id),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer'),
    retain_boot_id TEXT CHECK (retain_boot_id IS NULL OR (typeof(retain_boot_id) = 'text' AND length(retain_boot_id) BETWEEN 1 AND 64)),
    retain_from_boottime_ms INTEGER CHECK (retain_from_boottime_ms IS NULL OR typeof(retain_from_boottime_ms) = 'integer'),
    CHECK ((retain_boot_id IS NULL) = (retain_from_boottime_ms IS NULL)),
    PRIMARY KEY (owner_uid, request_id)
) WITHOUT ROWID;
INSERT INTO create_requests VALUES(1000,'key-deleted','1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047','sb-c4fixture000b',1800000011000,'boot-a',1011000);
INSERT INTO create_requests VALUES(1000,'key-ready','1f58b9145b24d108d7ac38887338b3ea3229833b9c1e418250343f907bfd1047','sb-c4fixture0009',1800000009000,'boot-a',1009000);
CREATE TABLE create_request_counts (
    owner_uid INTEGER PRIMARY KEY CHECK (typeof(owner_uid) = 'integer' AND owner_uid BETWEEN -1 AND 4294967295),
    records INTEGER NOT NULL CHECK (typeof(records) = 'integer' AND records >= 0)
);
INSERT INTO create_request_counts VALUES(-1,2);
INSERT INTO create_request_counts VALUES(1000,2);
CREATE TABLE reservation_membership (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    row_count INTEGER NOT NULL CHECK (typeof(row_count) = 'integer' AND row_count >= 0),
    row_sum BLOB NOT NULL CHECK (typeof(row_sum) = 'blob' AND length(row_sum) = 32),
    settled_count INTEGER NOT NULL CHECK (typeof(settled_count) = 'integer' AND settled_count >= 0),
    settled_sum BLOB NOT NULL CHECK (typeof(settled_sum) = 'blob' AND length(settled_sum) = 32)
);
INSERT INTO reservation_membership VALUES(1,15,x'cd5cc7cdb11118af7d6244f5fa5bb81a8f20106ae66d1785b19dca5274496b6b',6,x'77614a95379a09ac351e24d45cb565dd382d6ca1702846327c0b51e616dcf8e6');
CREATE TABLE reservation_unsettled (id TEXT PRIMARY KEY) WITHOUT ROWID;
INSERT INTO reservation_unsettled VALUES('sb-c4fixture0002');
CREATE TRIGGER daemon_identity_no_update BEFORE UPDATE ON daemon_identity
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER daemon_identity_no_delete BEFORE DELETE ON daemon_identity
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER release_evidence_no_update BEFORE UPDATE ON release_evidence
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_no_delete BEFORE DELETE ON release_evidence
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_not_stale BEFORE INSERT ON release_evidence
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE allocation_id = NEW.allocation_id AND last_helper_generation >= NEW.helper_generation)
BEGIN SELECT RAISE(ABORT, 'absence evidence is older than this allocation''s published generation'); END;
CREATE TRIGGER sandboxes_immutable BEFORE UPDATE ON sandboxes
WHEN NEW.id IS NOT OLD.id OR NEW.backend IS NOT OLD.backend OR NEW.spec IS NOT OLD.spec
    OR NEW.created_at_ms IS NOT OLD.created_at_ms OR NEW.list_seq IS NOT OLD.list_seq
    OR NEW.owner_uid IS NOT OLD.owner_uid OR NEW.accounting_kind IS NOT OLD.accounting_kind
    OR NEW.reserved_memory_bytes IS NOT OLD.reserved_memory_bytes
    OR NEW.reserved_disk_bytes IS NOT OLD.reserved_disk_bytes
    OR NEW.reserved_pids IS NOT OLD.reserved_pids
    OR NEW.reserved_host_cpu_millis IS NOT OLD.reserved_host_cpu_millis
    OR NEW.reserved_virtual_cpu_slots IS NOT OLD.reserved_virtual_cpu_slots
    OR NEW.reserved_host_pids IS NOT OLD.reserved_host_pids
    OR NEW.host_spec_sha256 IS NOT OLD.host_spec_sha256
    OR NEW.guest_exec_spec_sha256 IS NOT OLD.guest_exec_spec_sha256
    OR NEW.runtime_profile IS NOT OLD.runtime_profile
    OR NEW.runtime_artifact_digest IS NOT OLD.runtime_artifact_digest
    OR NEW.node_id IS NOT OLD.node_id OR NEW.instance_id IS NOT OLD.instance_id
    OR NEW.allocation_id IS NOT OLD.allocation_id OR NEW.plan_version IS NOT OLD.plan_version
    OR NEW.plan_digest IS NOT OLD.plan_digest OR NEW.plan IS NOT OLD.plan
    OR NEW.release_evidence_kind IS NOT OLD.release_evidence_kind
BEGIN SELECT RAISE(ABORT, 'sandbox identity, plan, spec and reservation are immutable'); END;
CREATE TRIGGER sandboxes_evidence_matches_update BEFORE UPDATE ON sandboxes
WHEN NEW.release_evidence_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id AND node_id = NEW.node_id AND instance_id = NEW.instance_id
      AND allocation_id = NEW.allocation_id AND plan_digest = NEW.plan_digest AND kind = 'absent_fenced')
BEGIN SELECT RAISE(ABORT, 'release evidence does not match this allocation'); END;
CREATE TRIGGER sandboxes_evidence_matches_insert BEFORE INSERT ON sandboxes
WHEN NEW.release_evidence_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id AND node_id = NEW.node_id AND instance_id = NEW.instance_id
      AND allocation_id = NEW.allocation_id AND plan_digest = NEW.plan_digest AND kind = 'absent_fenced'
      AND helper_generation IS NEW.last_helper_generation)
BEGIN SELECT RAISE(ABORT, 'release evidence does not match this allocation'); END;
CREATE TRIGGER sandboxes_generation_is_monotonic BEFORE UPDATE ON sandboxes
WHEN NEW.last_helper_generation IS NOT OLD.last_helper_generation AND (
        OLD.last_helper_generation IS NULL OR NEW.last_helper_generation IS NULL
        OR NEW.last_helper_generation <= OLD.last_helper_generation
        OR NOT ((OLD.runtime_receipt IS NULL AND NEW.runtime_receipt IS NOT NULL)
            OR (OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL)))
BEGIN SELECT RAISE(ABORT, 'a helper generation only advances with its ready or absence receipt'); END;
CREATE TRIGGER sandboxes_release_is_fresh BEFORE UPDATE ON sandboxes
WHEN OLD.release_evidence_id IS NULL AND NEW.release_evidence_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM release_evidence
    WHERE receipt_id = NEW.release_evidence_id
      AND (helper_generation <= OLD.last_helper_generation OR helper_generation IS NOT NEW.last_helper_generation))
BEGIN SELECT RAISE(ABORT, 'absence evidence is not newer than this allocation''s published generation'); END;
CREATE TRIGGER sandboxes_release_is_permanent BEFORE UPDATE ON sandboxes
WHEN (OLD.release_evidence_id IS NOT NULL
        AND (NEW.release_evidence_id IS NOT OLD.release_evidence_id OR NEW.state NOT IN ('failed', 'deleted')))
    OR (OLD.legacy_release IS NOT NULL AND NEW.legacy_release IS NULL)
    OR (OLD.state = 'deleted' AND NEW.state != 'deleted')
BEGIN SELECT RAISE(ABORT, 'a released reservation cannot be charged or reused again'); END;
CREATE TRIGGER sandboxes_no_legacy_laundering BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'legacy' AND OLD.state != 'creating' AND (
        (OLD.backend_id IS NULL AND NEW.backend_id IS NOT NULL)
        OR NEW.create_certainty IS NOT OLD.create_certainty
        OR (OLD.state = 'failed' AND OLD.legacy_release IS NULL AND NEW.state = 'deleted'))
BEGIN SELECT RAISE(ABORT, 'an ambiguous legacy reservation cannot acquire release provenance'); END;
CREATE TRIGGER sandboxes_fenced_publication BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'fenced' AND (
        (OLD.backend_id IS NOT NULL AND NEW.backend_id IS NOT OLD.backend_id)
        OR (OLD.boot_id IS NOT NULL AND NEW.boot_id IS NOT OLD.boot_id)
        OR (OLD.runtime_receipt IS NOT NULL AND NEW.runtime_receipt IS NOT OLD.runtime_receipt))
BEGIN SELECT RAISE(ABORT, 'a published allocation identity is immutable'); END;
CREATE TRIGGER sandboxes_no_resurrection BEFORE UPDATE ON sandboxes
WHEN NEW.state = 'ready' AND OLD.state != 'ready' AND (OLD.state = 'quarantined'
        OR (OLD.accounting_kind = 'fenced' AND OLD.state != 'creating'))
BEGIN SELECT RAISE(ABORT, 'a stopped or quarantined session cannot become ready'); END;
CREATE TRIGGER sandboxes_fenced_disposition BEFORE UPDATE ON sandboxes
WHEN OLD.accounting_kind = 'fenced' AND OLD.disposition != 'reusable' AND NEW.disposition = 'reusable'
BEGIN SELECT RAISE(ABORT, 'a retired allocation cannot become reusable'); END;
CREATE TRIGGER sandboxes_no_charged_delete BEFORE DELETE ON sandboxes
WHEN (OLD.accounting_kind = 'legacy' AND OLD.legacy_release IS NULL)
    OR (OLD.accounting_kind = 'fenced' AND OLD.release_evidence_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'a charged sandbox row cannot be deleted'); END;
CREATE TRIGGER sandboxes_no_replace BEFORE INSERT ON sandboxes
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE rowid = NEW.rowid OR id = NEW.id OR list_seq = NEW.list_seq
    OR (NEW.backend_id IS NOT NULL AND backend = NEW.backend AND backend_id = NEW.backend_id)
    OR (NEW.allocation_id IS NOT NULL AND allocation_id = NEW.allocation_id))
BEGIN SELECT RAISE(ABORT, 'a sandbox row cannot be replaced'); END;
CREATE TRIGGER sandboxes_no_replace_update BEFORE UPDATE ON sandboxes
WHEN EXISTS (SELECT 1 FROM sandboxes WHERE rowid != OLD.rowid AND (
    rowid = NEW.rowid OR id = NEW.id OR list_seq = NEW.list_seq
    OR (NEW.backend_id IS NOT NULL AND backend = NEW.backend AND backend_id = NEW.backend_id)
    OR (NEW.allocation_id IS NOT NULL AND allocation_id = NEW.allocation_id)))
BEGIN SELECT RAISE(ABORT, 'a sandbox row cannot be replaced'); END;
CREATE TRIGGER daemon_identity_no_replace BEFORE INSERT ON daemon_identity
WHEN EXISTS (SELECT 1 FROM daemon_identity WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'daemon identity is immutable'); END;
CREATE TRIGGER executions_no_replace BEFORE INSERT ON executions
WHEN EXISTS (SELECT 1 FROM executions WHERE rowid = NEW.rowid OR id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'an execution row cannot be replaced'); END;
CREATE TRIGGER executions_no_replace_update BEFORE UPDATE ON executions
WHEN EXISTS (SELECT 1 FROM executions WHERE rowid != OLD.rowid AND (rowid = NEW.rowid OR id = NEW.id))
BEGIN SELECT RAISE(ABORT, 'an execution row cannot be replaced'); END;
CREATE TRIGGER history_sequence_no_replace BEFORE INSERT ON history_sequence
WHEN EXISTS (SELECT 1 FROM history_sequence WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'history sequence cannot be replaced'); END;
CREATE TRIGGER history_sequence_identity BEFORE UPDATE OF id ON history_sequence
WHEN NEW.id IS NOT OLD.id
BEGIN SELECT RAISE(ABORT, 'history sequence identity is immutable'); END;
CREATE TRIGGER release_evidence_no_replace BEFORE INSERT ON release_evidence
WHEN EXISTS (SELECT 1 FROM release_evidence WHERE rowid = NEW.rowid
    OR receipt_id = NEW.receipt_id OR allocation_id = NEW.allocation_id)
BEGIN SELECT RAISE(ABORT, 'release evidence is immutable'); END;
CREATE TRIGGER release_evidence_validate BEFORE INSERT ON release_evidence
WHEN kilnd_fenced_absence_valid(NEW.receipt, NEW.receipt_id, NEW.node_id,
    NEW.instance_id, NEW.allocation_id, NEW.plan_digest, NEW.helper_generation, NEW.kind) IS NOT 1
BEGIN SELECT RAISE(ABORT, 'invalid encoded AbsentFenced evidence'); END;
CREATE TRIGGER sandboxes_expiry_policy_immutable BEFORE UPDATE ON sandboxes
WHEN NEW.expiry_lifetime_ms IS NOT OLD.expiry_lifetime_ms OR NEW.expiry_idle_ms IS NOT OLD.expiry_idle_ms
BEGIN SELECT RAISE(ABORT, 'a sandbox expiry policy is immutable'); END;
CREATE TRIGGER sandboxes_deletion_reason_once BEFORE UPDATE ON sandboxes
WHEN (OLD.deletion_reason IS NOT NULL AND NEW.deletion_reason IS NOT OLD.deletion_reason)
    OR (OLD.deletion_reason IS NULL AND NEW.deletion_reason IS NOT NULL AND NEW.state NOT IN ('deleting', 'deleted'))
BEGIN SELECT RAISE(ABORT, 'a deletion reason is written once, with DELETING or DELETED'); END;
CREATE TRIGGER sandboxes_deletion_reason_insert BEFORE INSERT ON sandboxes
WHEN NEW.deletion_reason IS NOT NULL AND NEW.state NOT IN ('deleting', 'deleted')
BEGIN SELECT RAISE(ABORT, 'a deletion reason is written once, with DELETING or DELETED'); END;
CREATE TRIGGER sandboxes_activity_seq_monotonic BEFORE UPDATE ON sandboxes
WHEN NEW.activity_seq < OLD.activity_seq
BEGIN SELECT RAISE(ABORT, 'activity_seq only increases'); END;
CREATE TRIGGER sandboxes_ready_anchor_fixed BEFORE UPDATE ON sandboxes
WHEN (OLD.ready_at_ms IS NOT NULL AND NEW.ready_at_ms IS NOT OLD.ready_at_ms)
    OR (OLD.ready_boottime_ms IS NOT NULL AND NEW.ready_boottime_ms IS NOT OLD.ready_boottime_ms
        AND NEW.clock_boot_id IS OLD.clock_boot_id)
BEGIN SELECT RAISE(ABORT, 'a READY anchor changes only in the cross-boot rebase'); END;
CREATE TRIGGER sandboxes_expiry_intent_anchor BEFORE UPDATE ON sandboxes
WHEN (OLD.expiry_intent_at_ms IS NOT NULL AND NEW.expiry_intent_at_ms IS NOT OLD.expiry_intent_at_ms)
    OR (OLD.expiry_intent_boottime_ms IS NOT NULL AND NEW.expiry_intent_boottime_ms IS NOT OLD.expiry_intent_boottime_ms
        AND NEW.clock_boot_id IS OLD.clock_boot_id)
    OR ((NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL)
        AND (NEW.deletion_reason IS NULL OR NEW.deletion_reason NOT IN ('expired_idle', 'expired_lifetime')))
BEGIN SELECT RAISE(ABORT, 'an expiry intent anchor is written once, with its reason, and moves only in the cross-boot rebase'); END;
CREATE TRIGGER sandboxes_expiry_intent_insert BEFORE INSERT ON sandboxes
WHEN NEW.expiry_intent_at_ms IS NOT NULL OR NEW.expiry_intent_boottime_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'an expiry intent anchor is written only by the expiry intent'); END;
CREATE TRIGGER executions_cancel_reason_once BEFORE UPDATE ON executions
WHEN OLD.cancel_reason IS NOT NULL AND NEW.cancel_reason IS NOT OLD.cancel_reason
BEGIN SELECT RAISE(ABORT, 'a cancel reason is written once'); END;
CREATE TRIGGER create_requests_no_replace BEFORE INSERT ON create_requests
WHEN EXISTS (SELECT 1 FROM create_requests
    WHERE (owner_uid = NEW.owner_uid AND request_id = NEW.request_id) OR sandbox_id = NEW.sandbox_id)
BEGIN SELECT RAISE(ABORT, 'a create request record cannot be replaced'); END;
CREATE TRIGGER create_requests_own_sandbox BEFORE INSERT ON create_requests
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = NEW.sandbox_id AND owner_uid = NEW.owner_uid
    AND request_id = NEW.request_id AND state = 'creating')
BEGIN SELECT RAISE(ABORT, 'a create request record is inserted with its own CREATING sandbox'); END;
CREATE TRIGGER create_requests_unanchored_insert BEFORE INSERT ON create_requests
WHEN NEW.retain_boot_id IS NOT NULL OR NEW.retain_from_boottime_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a create request record is inserted unanchored and anchored only after it commits'); END;
CREATE TRIGGER create_requests_fixed BEFORE UPDATE ON create_requests
WHEN NEW.owner_uid IS NOT OLD.owner_uid OR NEW.request_id IS NOT OLD.request_id
    OR NEW.request_sha256 IS NOT OLD.request_sha256 OR NEW.sandbox_id IS NOT OLD.sandbox_id
    OR NEW.created_at_ms IS NOT OLD.created_at_ms
    OR (OLD.retain_boot_id IS NOT NULL AND NEW.retain_boot_id IS NULL)
    OR (NEW.retain_from_boottime_ms IS NOT OLD.retain_from_boottime_ms AND NEW.retain_boot_id IS OLD.retain_boot_id)
BEGIN SELECT RAISE(ABORT, 'a create request record changes only when anchored or in the cross-boot retention rebase'); END;
CREATE TRIGGER create_requests_settled_delete BEFORE DELETE ON create_requests
WHEN NOT EXISTS (SELECT 1 FROM sandboxes WHERE id = OLD.sandbox_id AND (state = 'deleted'
    OR (state = 'failed' AND NOT ((accounting_kind = 'legacy' AND legacy_release IS NULL)
        OR (accounting_kind = 'fenced' AND release_evidence_id IS NULL)))))
BEGIN SELECT RAISE(ABORT, 'a create request record is kept until its sandbox is DELETED or released FAILED'); END;
CREATE TRIGGER sandboxes_pinned_by_request BEFORE DELETE ON sandboxes
WHEN EXISTS (SELECT 1 FROM create_requests WHERE sandbox_id = OLD.id)
BEGIN SELECT RAISE(ABORT, 'a sandbox with a create request record cannot be deleted'); END;
CREATE TRIGGER sandboxes_request_id_fixed BEFORE UPDATE ON sandboxes
WHEN NEW.request_id IS NOT OLD.request_id
    OR (OLD.request_id_released_at_ms IS NOT NULL AND NEW.request_id_released_at_ms IS NOT OLD.request_id_released_at_ms)
    OR (OLD.request_id_released_at_ms IS NULL AND NEW.request_id_released_at_ms IS NOT NULL
        AND (NEW.state != 'deleted' OR NEW.request_id IS NULL
            OR EXISTS (SELECT 1 FROM create_requests WHERE sandbox_id = NEW.id)))
BEGIN SELECT RAISE(ABORT, 'a request ID is fixed at create and released once, after its record, from DELETED'); END;
CREATE TRIGGER sandboxes_request_insert BEFORE INSERT ON sandboxes
WHEN NEW.request_id_released_at_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'a request ID is released only after its sandbox is DELETED'); END;
CREATE TRIGGER create_requests_count_insert AFTER INSERT ON create_requests
BEGIN
    INSERT INTO create_request_counts VALUES (NEW.owner_uid, 1)
        ON CONFLICT(owner_uid) DO UPDATE SET records = records + 1;
    UPDATE create_request_counts SET records = records + 1 WHERE owner_uid = -1;
END;
CREATE TRIGGER create_requests_count_delete AFTER DELETE ON create_requests
BEGIN
    UPDATE create_request_counts SET records = records - 1 WHERE owner_uid IN (OLD.owner_uid, -1);
    DELETE FROM create_request_counts WHERE owner_uid = OLD.owner_uid AND records = 0;
END;
CREATE TRIGGER sandboxes_released_unsettled AFTER UPDATE ON sandboxes
WHEN ((OLD.accounting_kind = 'legacy' AND OLD.legacy_release IS NULL) OR (OLD.accounting_kind = 'fenced' AND OLD.release_evidence_id IS NULL))
    AND NOT ((NEW.accounting_kind = 'legacy' AND NEW.legacy_release IS NULL) OR (NEW.accounting_kind = 'fenced' AND NEW.release_evidence_id IS NULL))
BEGIN INSERT OR IGNORE INTO reservation_unsettled VALUES (NEW.id); END;
CREATE TRIGGER sandboxes_default_env_insert BEFORE INSERT ON sandboxes
WHEN (NEW.default_env IS NOT NULL OR NEW.default_env_names IS NOT NULL) AND NEW.state != 'creating'
BEGIN SELECT RAISE(ABORT, 'a default env is inserted with its CREATING sandbox'); END;
CREATE TRIGGER sandboxes_default_env_fixed BEFORE UPDATE ON sandboxes
WHEN NEW.default_env_names IS NOT OLD.default_env_names OR NEW.default_env_sha256 IS NOT OLD.default_env_sha256
    OR (NEW.default_env IS NOT OLD.default_env AND NEW.default_env IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'a default env is fixed at insert; its values are only cleared'); END;
CREATE TRIGGER sandboxes_exec_features_once BEFORE UPDATE ON sandboxes
WHEN OLD.exec_features IS NOT NULL AND NEW.exec_features IS NOT OLD.exec_features
BEGIN SELECT RAISE(ABORT, 'exec features are recorded once'); END;
CREATE TRIGGER executions_env_fixed BEFORE UPDATE ON executions
WHEN NEW.cwd IS NOT OLD.cwd OR NEW.env_names IS NOT OLD.env_names OR NEW.env_sha256 IS NOT OLD.env_sha256
BEGIN SELECT RAISE(ABORT, 'an execution cwd and env names and digest are fixed at insert'); END;
CREATE TRIGGER executions_mode_fixed BEFORE UPDATE ON executions
WHEN NEW.mode IS NOT OLD.mode
BEGIN SELECT RAISE(ABORT, 'an execution mode is fixed at insert'); END;
CREATE UNIQUE INDEX sandboxes_backend_id ON sandboxes (backend, backend_id) WHERE backend_id IS NOT NULL;
CREATE INDEX sandboxes_state ON sandboxes (state);
CREATE UNIQUE INDEX sandboxes_list_seq ON sandboxes (list_seq DESC);
CREATE INDEX sandboxes_live_list_seq ON sandboxes (list_seq DESC) WHERE state != 'deleted';
CREATE INDEX sandboxes_owner_list_seq ON sandboxes (owner_uid, list_seq DESC);
CREATE UNIQUE INDEX sandboxes_allocation ON sandboxes (allocation_id) WHERE allocation_id IS NOT NULL;
CREATE INDEX executions_sandbox ON executions (sandbox_id, started_at_ms);
CREATE INDEX executions_state ON executions (state);
CREATE INDEX sandboxes_expiry ON sandboxes (id)
    WHERE state IN ('ready', 'lost', 'quarantined', 'deleting')
      AND (expiry_lifetime_ms IS NOT NULL OR expiry_idle_ms IS NOT NULL);
CREATE INDEX create_requests_unanchored ON create_requests (sandbox_id) WHERE retain_boot_id IS NULL;
CREATE INDEX sandboxes_charged ON sandboxes (id)
WHERE ((accounting_kind = 'legacy' AND legacy_release IS NULL) OR (accounting_kind = 'fenced' AND release_evidence_id IS NULL));
COMMIT;
PRAGMA user_version = 14;
