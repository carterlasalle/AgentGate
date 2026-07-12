//! Metadata-first hash-chained audit evidence and offline verification.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use agentgate_core::{CanonicalJson, Digest, SessionId};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

/// Current append-only event schema.
pub const AUDIT_SCHEMA_VERSION: u16 = 1;

/// One canonical hash-linked metadata event.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Monotonic file-local sequence starting at one.
    pub sequence: u64,
    /// UTC evidence timestamp.
    pub timestamp: DateTime<Utc>,
    /// Optional session identity for administrative/global events.
    pub session_id: Option<SessionId>,
    /// Stable event type.
    pub event_type: String,
    /// Metadata-only allowlisted data supplied by the gateway event API.
    pub data: Value,
    /// Previous event hash or all-zero genesis digest.
    pub previous_hash: Digest,
    /// Hash of the canonical preceding fields.
    pub event_hash: Digest,
}

#[derive(Serialize)]
struct EventBody<'a> {
    schema_version: u16,
    sequence: u64,
    timestamp: DateTime<Utc>,
    session_id: Option<SessionId>,
    event_type: &'a str,
    data: &'a Value,
    previous_hash: Digest,
}

/// Result of offline chain and checkpoint verification.
#[derive(Clone, Debug, Serialize)]
pub struct VerificationReport {
    /// Number of valid events read.
    pub events: u64,
    /// Number of valid signature checkpoints.
    pub checkpoints: u64,
    /// Final chain hash.
    pub final_hash: Digest,
    /// Key IDs observed in checkpoints.
    pub key_ids: Vec<String>,
}

/// Metadata-only replay summary. Replay performs no process or network I/O.
#[derive(Clone, Debug, Serialize)]
pub struct ReplayReport {
    /// Verified events processed.
    pub events: u64,
    /// Recorded policy decisions.
    pub decisions: u64,
    /// Recorded downstream forwards.
    pub forwarded: u64,
    /// Recorded denials.
    pub denied: u64,
    /// Distinct policy digests observed.
    pub policy_digests: Vec<String>,
}

/// Summary of an explicit age/size retention pass.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RetentionReport {
    /// Audit files removed.
    pub removed_files: u64,
    /// Bytes removed according to pre-delete metadata.
    pub removed_bytes: u64,
    /// Bytes retained after the pass.
    pub retained_bytes: u64,
}

/// Signed transition produced when rotating the installation audit key.
#[derive(Clone, Debug, Serialize)]
pub struct KeyRotationReport {
    /// Retired key identifier.
    pub previous_key_id: String,
    /// New key identifier.
    pub new_key_id: String,
    /// New public key in base64.
    pub new_public_key: String,
    /// Old key's Ed25519 signature over the new public key transition.
    pub transition_signature: String,
    /// Owner-only archived old signing-key path for prior-log verification.
    pub archived_key: String,
}

/// Append-only audit writer with periodic Ed25519 checkpoints.
pub struct AuditWriter {
    writer: BufWriter<File>,
    signing_key: SigningKey,
    key_id: Digest,
    sequence: u64,
    previous_hash: Digest,
    checkpoint_interval: u64,
    events_since_checkpoint: u64,
}

impl AuditWriter {
    /// Creates a new audit file and loads or creates an owner-only signing key.
    pub fn create(
        path: &Path,
        key_path: &Path,
        checkpoint_interval: u64,
    ) -> Result<Self, AuditError> {
        if checkpoint_interval == 0 {
            return Err(AuditError::InvalidCheckpointInterval);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(AuditError::Io)?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(AuditError::Io)?;
        set_owner_only(&file)?;
        let signing_key = load_or_create_key(key_path)?;
        let key_id = Digest::domain(b"audit-key/v1", signing_key.verifying_key().as_bytes());
        Ok(Self {
            writer: BufWriter::new(file),
            signing_key,
            key_id,
            sequence: 0,
            previous_hash: Digest::domain(b"audit-genesis/v1", b""),
            checkpoint_interval,
            events_since_checkpoint: 0,
        })
    }

    /// Returns the public verifying key used by this log.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Appends and flushes one metadata event.
    pub fn append(
        &mut self,
        session_id: Option<SessionId>,
        event_type: &str,
        data: Value,
    ) -> Result<AuditEvent, AuditError> {
        validate_event_type(event_type)?;
        if event_type == "checkpoint_signed" {
            return Err(AuditError::ReservedEventType);
        }
        let event = self.append_internal(session_id, event_type, data)?;
        self.events_since_checkpoint += 1;
        if self.events_since_checkpoint >= self.checkpoint_interval {
            self.checkpoint(session_id)?;
        }
        Ok(event)
    }

    /// Flushes an explicit final signature checkpoint.
    pub fn finish(mut self, session_id: Option<SessionId>) -> Result<AuditEvent, AuditError> {
        let event = self.checkpoint(session_id)?;
        self.writer.flush().map_err(AuditError::Io)?;
        self.writer.get_ref().sync_all().map_err(AuditError::Io)?;
        Ok(event)
    }

    fn checkpoint(&mut self, session_id: Option<SessionId>) -> Result<AuditEvent, AuditError> {
        let covered_sequence = self.sequence;
        let covered_hash = self.previous_hash;
        let message = checkpoint_message(covered_sequence, covered_hash);
        let signature = self.signing_key.sign(&message);
        let event = self.append_internal(
            session_id,
            "checkpoint_signed",
            json!({
                "key_id": self.key_id.to_hex(),
                "public_key": BASE64.encode(self.signing_key.verifying_key().as_bytes()),
                "covered_sequence": covered_sequence,
                "covered_hash": covered_hash.to_hex(),
                "signature": BASE64.encode(signature.to_bytes()),
            }),
        )?;
        self.events_since_checkpoint = 0;
        Ok(event)
    }

    fn append_internal(
        &mut self,
        session_id: Option<SessionId>,
        event_type: &str,
        data: Value,
    ) -> Result<AuditEvent, AuditError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        let timestamp = Utc::now();
        let body = EventBody {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence: self.sequence,
            timestamp,
            session_id,
            event_type,
            data: &data,
            previous_hash: self.previous_hash,
        };
        let value = serde_json::to_value(&body).map_err(AuditError::Json)?;
        let canonical = CanonicalJson::from_value(&value).map_err(AuditError::Core)?;
        let event_hash = Digest::domain(b"audit-event/v1", canonical.as_bytes());
        let event = AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence: self.sequence,
            timestamp,
            session_id,
            event_type: event_type.to_owned(),
            data,
            previous_hash: self.previous_hash,
            event_hash,
        };
        serde_json::to_writer(&mut self.writer, &event).map_err(AuditError::Json)?;
        self.writer.write_all(b"\n").map_err(AuditError::Io)?;
        self.writer.flush().map_err(AuditError::Io)?;
        self.previous_hash = event_hash;
        Ok(event)
    }
}

/// Verifies event sequence, hash chain, checkpoint signatures, and optional trusted public key.
pub fn verify(
    path: &Path,
    expected_key: Option<&VerifyingKey>,
) -> Result<VerificationReport, AuditError> {
    let file = File::open(path).map_err(AuditError::Io)?;
    let mut previous = Digest::domain(b"audit-genesis/v1", b"");
    let mut expected_sequence = 1_u64;
    let mut checkpoints = 0_u64;
    let mut key_ids = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(AuditError::Io)?;
        if line.trim().is_empty() {
            return Err(AuditError::InvalidEvent {
                sequence: expected_sequence,
                reason: "empty line".to_owned(),
            });
        }
        let event: AuditEvent = serde_json::from_str(&line).map_err(AuditError::Json)?;
        if event.schema_version != AUDIT_SCHEMA_VERSION {
            return Err(AuditError::InvalidEvent {
                sequence: event.sequence,
                reason: "unsupported schema version".to_owned(),
            });
        }
        if event.sequence != expected_sequence || event.previous_hash != previous {
            return Err(AuditError::InvalidEvent {
                sequence: event.sequence,
                reason: "sequence or previous hash mismatch".to_owned(),
            });
        }
        let body = EventBody {
            schema_version: event.schema_version,
            sequence: event.sequence,
            timestamp: event.timestamp,
            session_id: event.session_id,
            event_type: &event.event_type,
            data: &event.data,
            previous_hash: event.previous_hash,
        };
        let value = serde_json::to_value(&body).map_err(AuditError::Json)?;
        let canonical = CanonicalJson::from_value(&value).map_err(AuditError::Core)?;
        let computed = Digest::domain(b"audit-event/v1", canonical.as_bytes());
        if computed != event.event_hash {
            return Err(AuditError::InvalidEvent {
                sequence: event.sequence,
                reason: "event hash mismatch".to_owned(),
            });
        }
        if event.event_type == "checkpoint_signed" {
            let public_key = decode_public_key(&event.data)?;
            if let Some(expected) = expected_key
                && expected.as_bytes() != public_key.as_bytes()
            {
                return Err(AuditError::UntrustedCheckpointKey);
            }
            verify_checkpoint(&event.data, &public_key)?;
            let key_id = event
                .data
                .get("key_id")
                .and_then(Value::as_str)
                .ok_or_else(|| AuditError::InvalidCheckpoint("missing key_id".to_owned()))?;
            key_ids.push(key_id.to_owned());
            checkpoints += 1;
        }
        previous = event.event_hash;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
    }
    if expected_sequence == 1 {
        return Err(AuditError::EmptyLog);
    }
    Ok(VerificationReport {
        events: expected_sequence - 1,
        checkpoints,
        final_hash: previous,
        key_ids,
    })
}

/// Verifies the log and summarizes policy decision events without external I/O.
pub fn replay(
    path: &Path,
    expected_key: Option<&VerifyingKey>,
) -> Result<ReplayReport, AuditError> {
    let verification = verify(path, expected_key)?;
    let file = File::open(path).map_err(AuditError::Io)?;
    let mut decisions = 0;
    let mut forwarded = 0;
    let mut denied = 0;
    let mut policy_digests = std::collections::BTreeSet::new();
    for line in BufReader::new(file).lines() {
        let event: AuditEvent =
            serde_json::from_str(&line.map_err(AuditError::Io)?).map_err(AuditError::Json)?;
        match event.event_type.as_str() {
            "decision_made" => {
                decisions += 1;
                if event.data.get("decision").and_then(Value::as_str) == Some("deny") {
                    denied += 1;
                }
            }
            "call_forwarded" => forwarded += 1,
            _ => {}
        }
        if let Some(digest) = event.data.get("policy_digest").and_then(Value::as_str) {
            policy_digests.insert(digest.to_owned());
        }
    }
    Ok(ReplayReport {
        events: verification.events,
        decisions,
        forwarded,
        denied,
        policy_digests: policy_digests.into_iter().collect(),
    })
}

/// Reads a raw 32-byte AgentGate signing key and returns only its public verifier.
pub fn verifying_key_from_file(path: &Path) -> Result<VerifyingKey, AuditError> {
    let bytes = fs::read(path).map_err(AuditError::Io)?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| AuditError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&key).verifying_key())
}

/// Applies bounded age and aggregate-size retention to audit JSONL files.
pub fn apply_retention(
    directory: &Path,
    maximum_age: Duration,
    maximum_bytes: u64,
) -> Result<RetentionReport, AuditError> {
    fs::create_dir_all(directory).map_err(AuditError::Io)?;
    let now = SystemTime::now();
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).map_err(AuditError::Io)? {
        let entry = entry.map_err(AuditError::Io)?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let metadata = entry.metadata().map_err(AuditError::Io)?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        files.push((path, modified, metadata.len()));
    }
    files.sort_by_key(|(_, modified, _)| *modified);
    let mut report = RetentionReport::default();
    let mut retained: u64 = files.iter().map(|(_, _, bytes)| bytes).sum();
    for (path, modified, bytes) in files {
        let expired = now
            .duration_since(modified)
            .is_ok_and(|age| age > maximum_age);
        if expired || retained > maximum_bytes {
            fs::remove_file(path).map_err(AuditError::Io)?;
            retained = retained.saturating_sub(bytes);
            report.removed_files += 1;
            report.removed_bytes += bytes;
        }
    }
    report.retained_bytes = retained;
    Ok(report)
}

/// Rotates a raw installation signing key and archives the old key owner-only.
pub fn rotate_signing_key(path: &Path) -> Result<KeyRotationReport, AuditError> {
    let old_bytes = fs::read(path).map_err(AuditError::Io)?;
    let old_array: [u8; 32] = old_bytes.try_into().map_err(|_| AuditError::InvalidKey)?;
    let old = SigningKey::from_bytes(&old_array);
    let old_id = Digest::domain(b"audit-key/v1", old.verifying_key().as_bytes());
    let new = SigningKey::generate(&mut OsRng);
    let new_id = Digest::domain(b"audit-key/v1", new.verifying_key().as_bytes());
    let mut message = b"agentgate-key-rotation/v1\0".to_vec();
    message.extend(new.verifying_key().as_bytes());
    let signature = old.sign(&message);

    let archive = path.with_file_name(format!("audit-ed25519.{}.retired.key", old_id.to_hex()));
    if archive.exists() {
        return Err(AuditError::KeyArchiveExists(archive.display().to_string()));
    }
    let temporary = path.with_extension("new");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(AuditError::Io)?;
    set_owner_only(&file)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&new.to_bytes()).map_err(AuditError::Io)?;
    writer.flush().map_err(AuditError::Io)?;
    writer.get_ref().sync_all().map_err(AuditError::Io)?;
    fs::rename(path, &archive).map_err(AuditError::Io)?;
    let archive_file = OpenOptions::new()
        .read(true)
        .open(&archive)
        .map_err(AuditError::Io)?;
    set_owner_only(&archive_file)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::rename(&archive, path);
        return Err(AuditError::Io(error));
    }

    let report = KeyRotationReport {
        previous_key_id: old_id.to_hex(),
        new_key_id: new_id.to_hex(),
        new_public_key: BASE64.encode(new.verifying_key().as_bytes()),
        transition_signature: BASE64.encode(signature.to_bytes()),
        archived_key: archive.display().to_string(),
    };
    let report_path = path.with_file_name(format!(
        "rotation-{}-to-{}.json",
        report.previous_key_id, report.new_key_id
    ));
    fs::write(
        report_path,
        serde_json::to_vec_pretty(&report).map_err(AuditError::Json)?,
    )
    .map_err(AuditError::Io)?;
    Ok(report)
}

/// Audit storage, canonicalization, signature, or verification error.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Audit file/key I/O failed.
    #[error("audit I/O failed: {0}")]
    Io(std::io::Error),
    /// Event JSON serialization failed.
    #[error("audit JSON failed: {0}")]
    Json(serde_json::Error),
    /// Event canonicalization failed.
    #[error("audit canonicalization failed: {0}")]
    Core(agentgate_core::CoreError),
    /// Checkpoint interval was zero.
    #[error("checkpoint interval must be positive")]
    InvalidCheckpointInterval,
    /// Sequence exceeded u64.
    #[error("audit sequence overflow")]
    SequenceOverflow,
    /// Caller attempted to forge a reserved checkpoint event.
    #[error("checkpoint_signed is a reserved event type")]
    ReservedEventType,
    /// Event type was malformed.
    #[error("invalid audit event type")]
    InvalidEventType,
    /// Log was empty.
    #[error("audit log is empty")]
    EmptyLog,
    /// Hash-chain event was invalid.
    #[error("invalid audit event at sequence {sequence}: {reason}")]
    InvalidEvent {
        /// Sequence where verification failed.
        sequence: u64,
        /// Verification reason.
        reason: String,
    },
    /// Checkpoint metadata or signature was invalid.
    #[error("invalid audit checkpoint: {0}")]
    InvalidCheckpoint(String),
    /// Checkpoint key did not equal the trusted verifier key.
    #[error("checkpoint was signed by an unexpected key")]
    UntrustedCheckpointKey,
    /// Key file was malformed.
    #[error("invalid Ed25519 signing key file")]
    InvalidKey,
    /// An archive path already exists, so rotation refused to overwrite it.
    #[error("retired key archive already exists: {0}")]
    KeyArchiveExists(String),
}

fn load_or_create_key(path: &Path) -> Result<SigningKey, AuditError> {
    match fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes.try_into().map_err(|_| AuditError::InvalidKey)?;
            Ok(SigningKey::from_bytes(&key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(AuditError::Io)?;
            }
            let key = SigningKey::generate(&mut OsRng);
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .map_err(AuditError::Io)?;
            set_owner_only(&file)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&key.to_bytes()).map_err(AuditError::Io)?;
            writer.flush().map_err(AuditError::Io)?;
            writer.get_ref().sync_all().map_err(AuditError::Io)?;
            Ok(key)
        }
        Err(error) => Err(AuditError::Io(error)),
    }
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<(), AuditError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(AuditError::Io)
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<(), AuditError> {
    Ok(())
}

fn validate_event_type(value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(AuditError::InvalidEventType);
    }
    Ok(())
}

fn checkpoint_message(sequence: u64, hash: Digest) -> Vec<u8> {
    let mut message = b"agentgate-checkpoint/v1\0".to_vec();
    message.extend(sequence.to_be_bytes());
    message.extend(hash.as_bytes());
    message
}

fn decode_public_key(data: &Value) -> Result<VerifyingKey, AuditError> {
    let encoded = data
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidCheckpoint("missing public key".to_owned()))?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| AuditError::InvalidCheckpoint("invalid public key encoding".to_owned()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AuditError::InvalidCheckpoint("invalid public key size".to_owned()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| AuditError::InvalidCheckpoint("invalid public key".to_owned()))
}

fn verify_checkpoint(data: &Value, key: &VerifyingKey) -> Result<(), AuditError> {
    let sequence = data
        .get("covered_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuditError::InvalidCheckpoint("missing covered sequence".to_owned()))?;
    let hash = data
        .get("covered_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidCheckpoint("missing covered hash".to_owned()))?;
    let hash = Digest::from_hex(hash).map_err(AuditError::Core)?;
    let signature = data
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidCheckpoint("missing signature".to_owned()))?;
    let signature = BASE64
        .decode(signature)
        .map_err(|_| AuditError::InvalidCheckpoint("invalid signature encoding".to_owned()))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| AuditError::InvalidCheckpoint("invalid signature size".to_owned()))?;
    key.verify(&checkpoint_message(sequence, hash), &signature)
        .map_err(|_| AuditError::InvalidCheckpoint("signature verification failed".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use agentgate_core::SessionId;
    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        AuditWriter, apply_retention, replay, rotate_signing_key, verify, verifying_key_from_file,
    };

    #[test]
    fn writes_verifies_and_replays_metadata_events() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let log = directory.path().join("audit.jsonl");
        let key = directory.path().join("audit.key");
        let session = SessionId::new();
        let mut writer =
            AuditWriter::create(&log, &key, 2).unwrap_or_else(|error| unreachable!("{error}"));
        let public = writer.verifying_key();
        writer
            .append(
                Some(session),
                "decision_made",
                json!({"decision": "deny", "policy_digest": "abc"}),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        writer
            .append(Some(session), "call_received", json!({"tool": "send"}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        writer
            .append(
                Some(session),
                "call_forwarded",
                json!({"action_digest": "def"}),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        writer
            .finish(Some(session))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let report = verify(&log, Some(&public)).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.events, 5);
        assert_eq!(report.checkpoints, 2);
        let replay = replay(&log, Some(&public)).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(replay.decisions, 1);
        assert_eq!(replay.denied, 1);
        assert_eq!(replay.forwarded, 1);
    }

    #[test]
    fn detects_mutation_deletion_and_reordering() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let original = directory.path().join("original.jsonl");
        let key = directory.path().join("audit.key");
        let mut writer = AuditWriter::create(&original, &key, 100)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let public = writer.verifying_key();
        writer
            .append(None, "session_started", json!({"safe": true}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        writer
            .append(None, "session_ended", json!({"reason": "complete"}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        writer
            .finish(None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let source = fs::read_to_string(&original).unwrap_or_else(|error| unreachable!("{error}"));
        let lines: Vec<&str> = source.lines().collect();

        let mutated = directory.path().join("mutated.jsonl");
        fs::write(&mutated, source.replace("complete", "tampered"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&mutated, Some(&public)).is_err());

        let deleted = directory.path().join("deleted.jsonl");
        fs::write(&deleted, format!("{}\n{}\n", lines[0], lines[2]))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&deleted, Some(&public)).is_err());

        let reordered = directory.path().join("reordered.jsonl");
        fs::write(
            &reordered,
            format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&reordered, Some(&public)).is_err());
    }

    #[test]
    fn trusted_public_key_rejects_resigned_log() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let first_log = directory.path().join("first.jsonl");
        let first_key = directory.path().join("first.key");
        let first = AuditWriter::create(&first_log, &first_key, 1)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let trusted = first.verifying_key();
        first
            .finish(None)
            .unwrap_or_else(|error| unreachable!("{error}"));

        let other_log = directory.path().join("other.jsonl");
        let other_key = directory.path().join("other.key");
        AuditWriter::create(&other_log, &other_key, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .finish(None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&other_log, Some(&trusted)).is_err());
    }

    #[test]
    fn rotation_archives_old_key_and_preserves_both_verification_paths() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let key = directory.path().join("audit-ed25519.key");
        let old_log = directory.path().join("old.jsonl");
        AuditWriter::create(&old_log, &key, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .finish(None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let report = rotate_signing_key(&key).unwrap_or_else(|error| unreachable!("{error}"));
        let archived = std::path::PathBuf::from(&report.archived_key);
        let old_public =
            verifying_key_from_file(&archived).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&old_log, Some(&old_public)).is_ok());

        let new_log = directory.path().join("new.jsonl");
        AuditWriter::create(&new_log, &key, 1)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .finish(None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let new_public =
            verifying_key_from_file(&key).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify(&new_log, Some(&new_public)).is_ok());
        assert_ne!(report.previous_key_id, report.new_key_id);
    }

    #[test]
    fn retention_removes_only_audit_jsonl_files_to_size_bound() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(directory.path().join("one.jsonl"), b"12345")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(directory.path().join("two.jsonl"), b"67890")
            .unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(directory.path().join("keep.txt"), b"not an audit")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let report = apply_retention(directory.path(), std::time::Duration::MAX, 0)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.removed_files, 2);
        assert_eq!(report.retained_bytes, 0);
        assert!(directory.path().join("keep.txt").exists());
    }
}
