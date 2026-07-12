//! Per-session sensitive-value provenance and bounded flow evidence.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, VecDeque};

use agentgate_core::Digest;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

type HmacSha256 = Hmac<Sha256>;

/// Maximum scalar values extracted from one result or sink argument.
const MAX_SCALARS_PER_VALUE: usize = 10_000;
/// Maximum stored fingerprints generated from one scalar.
const MAX_CHUNKS_PER_SCALAR: usize = 128;

/// Explicit type-specific normalization profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Normalization {
    /// Unicode NFKC, lowercase, and collapsed whitespace.
    Text,
    /// Retain a leading plus and ASCII digits only.
    Contact,
    /// Normalize separators and dot path segments without filesystem access.
    Path,
    /// Exact bytes only.
    Binary,
}

impl Normalization {
    /// Parses a policy normalization name.
    #[must_use]
    pub fn from_policy(value: &str) -> Self {
        match value {
            "contact" => Self::Contact,
            "path" => Self::Path,
            "binary" => Self::Binary,
            _ => Self::Text,
        }
    }
}

/// Evidence method used to connect a source with a sink.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMethod {
    /// Exact keyed scalar fingerprint.
    Exact,
    /// Keyed fingerprint after an explicit normalization profile.
    Normalized,
    /// Keyed bounded substring fingerprint.
    Chunk,
    /// Conservative session state without a value match.
    SessionTaint,
    /// Authenticated host-provided lineage.
    AuthenticatedLineage,
}

/// One deterministic source-to-sink match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowEvidence {
    /// Sensitive source label.
    pub label: String,
    /// How the match was established.
    pub method: EvidenceMethod,
    /// Keyed fingerprint; never plaintext.
    pub fingerprint: Digest,
}

#[derive(Clone, Debug)]
struct FingerprintRecord {
    label: String,
    method: EvidenceMethod,
}

/// Bounded session-local provenance store.
pub struct ProvenanceStore {
    key: [u8; 32],
    maximum: usize,
    records: HashMap<Digest, FingerprintRecord>,
    order: VecDeque<Digest>,
    active_labels: BTreeSet<String>,
}

impl ProvenanceStore {
    /// Creates a session store with a per-installation/session key and entry cap.
    pub fn new(key: [u8; 32], maximum: usize) -> Result<Self, ProvenanceError> {
        if maximum == 0 {
            return Err(ProvenanceError::InvalidLimit);
        }
        Ok(Self {
            key,
            maximum,
            records: HashMap::new(),
            order: VecDeque::new(),
            active_labels: BTreeSet::new(),
        })
    }

    /// Returns all source labels that have entered this session.
    #[must_use]
    pub const fn active_labels(&self) -> &BTreeSet<String> {
        &self.active_labels
    }

    /// Registers bounded scalar fingerprints from a labeled result.
    pub fn register(
        &mut self,
        label: &str,
        normalization: Normalization,
        value: &Value,
        exact: bool,
        normalized: bool,
        chunks: Option<(usize, usize)>,
    ) -> Result<usize, ProvenanceError> {
        validate_label(label)?;
        self.active_labels.insert(label.to_owned());
        let mut scalars = Vec::new();
        collect_scalars(value, &mut scalars)?;
        let mut count = 0;
        for scalar in scalars {
            if exact {
                self.insert(
                    fingerprint(&self.key, b"exact", scalar.as_bytes())?,
                    label,
                    EvidenceMethod::Exact,
                );
                count += 1;
            }
            let normalized_value = normalize(normalization, &scalar);
            if normalized && normalized_value != scalar {
                self.insert(
                    fingerprint(&self.key, b"normalized", normalized_value.as_bytes())?,
                    label,
                    EvidenceMethod::Normalized,
                );
                count += 1;
            }
            if let Some((minimum, window)) = chunks
                && scalar.len() >= minimum
                && window >= 8
            {
                for chunk in bounded_utf8_chunks(&scalar, window)
                    .into_iter()
                    .take(MAX_CHUNKS_PER_SCALAR)
                {
                    self.insert(
                        fingerprint(&self.key, b"chunk", chunk.as_bytes())?,
                        label,
                        EvidenceMethod::Chunk,
                    );
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Inspects sink arguments for exact, normalized, and chunk fingerprints.
    pub fn inspect(
        &self,
        normalization: Normalization,
        value: &Value,
        chunk_windows: &[usize],
    ) -> Result<Vec<FlowEvidence>, ProvenanceError> {
        let mut scalars = Vec::new();
        collect_scalars(value, &mut scalars)?;
        let mut evidence = Vec::new();
        let mut seen = BTreeSet::new();
        for scalar in scalars {
            let candidates = [
                (
                    EvidenceMethod::Exact,
                    fingerprint(&self.key, b"exact", scalar.as_bytes())?,
                ),
                (
                    EvidenceMethod::Normalized,
                    fingerprint(
                        &self.key,
                        b"normalized",
                        normalize(normalization, &scalar).as_bytes(),
                    )?,
                ),
            ];
            for (method, digest) in candidates {
                self.add_evidence(digest, method, &mut seen, &mut evidence);
            }
            for &window in chunk_windows {
                if window < 8 {
                    continue;
                }
                for chunk in bounded_utf8_chunks(&scalar, window)
                    .into_iter()
                    .take(MAX_CHUNKS_PER_SCALAR)
                {
                    let digest = fingerprint(&self.key, b"chunk", chunk.as_bytes())?;
                    self.add_evidence(digest, EvidenceMethod::Chunk, &mut seen, &mut evidence);
                }
            }
        }
        evidence.sort_by(|left, right| {
            left.label
                .cmp(&right.label)
                .then_with(|| format!("{:?}", left.method).cmp(&format!("{:?}", right.method)))
        });
        Ok(evidence)
    }

    /// Adds conservative evidence for all active labels when no exact match is required.
    #[must_use]
    pub fn session_taint_evidence(&self) -> Vec<FlowEvidence> {
        self.active_labels
            .iter()
            .map(|label| FlowEvidence {
                label: label.clone(),
                method: EvidenceMethod::SessionTaint,
                fingerprint: Digest::domain(b"session-taint", label.as_bytes()),
            })
            .collect()
    }

    /// Returns current retained fingerprint count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no fingerprints are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn insert(&mut self, digest: Digest, label: &str, method: EvidenceMethod) {
        if self.records.contains_key(&digest) {
            return;
        }
        while self.records.len() >= self.maximum {
            if let Some(oldest) = self.order.pop_front() {
                self.records.remove(&oldest);
            } else {
                break;
            }
        }
        self.records.insert(
            digest,
            FingerprintRecord {
                label: label.to_owned(),
                method,
            },
        );
        self.order.push_back(digest);
    }

    fn add_evidence(
        &self,
        digest: Digest,
        candidate_method: EvidenceMethod,
        seen: &mut BTreeSet<(String, String)>,
        output: &mut Vec<FlowEvidence>,
    ) {
        if let Some(record) = self.records.get(&digest) {
            let method = if record.method == candidate_method {
                candidate_method
            } else {
                record.method
            };
            let key = (record.label.clone(), format!("{method:?}"));
            if seen.insert(key) {
                output.push(FlowEvidence {
                    label: record.label.clone(),
                    method,
                    fingerprint: digest,
                });
            }
        }
    }
}

/// Provenance configuration, extraction, or cryptographic errors.
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// Store capacity was zero.
    #[error("provenance capacity must be positive")]
    InvalidLimit,
    /// Label was malformed or excessive.
    #[error("invalid provenance label")]
    InvalidLabel,
    /// More scalar values were encountered than the bounded extractor permits.
    #[error("value contains too many scalar fields")]
    TooManyScalars,
    /// Per-installation HMAC key initialization failed.
    #[error("invalid provenance key")]
    InvalidKey,
}

fn fingerprint(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> Result<Digest, ProvenanceError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| ProvenanceError::InvalidKey)?;
    mac.update(b"agentgate-provenance\0");
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(payload);
    Digest::from_hex(&hex::encode(mac.finalize().into_bytes()))
        .map_err(|_| ProvenanceError::InvalidKey)
}

fn normalize(profile: Normalization, value: &str) -> String {
    match profile {
        Normalization::Text => value
            .nfkc()
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        Normalization::Contact => {
            let plus = value.trim_start().starts_with('+');
            let digits: String = value.chars().filter(char::is_ascii_digit).collect();
            if plus && !digits.is_empty() {
                format!("+{digits}")
            } else {
                digits
            }
        }
        Normalization::Path => {
            let replaced = value.replace('\\', "/");
            let absolute = replaced.starts_with('/');
            let mut parts = Vec::new();
            for part in replaced.split('/') {
                match part {
                    "" | "." => {}
                    ".." => {
                        parts.pop();
                    }
                    value => parts.push(value),
                }
            }
            format!("{}{}", if absolute { "/" } else { "" }, parts.join("/"))
        }
        Normalization::Binary => value.to_owned(),
    }
}

fn collect_scalars(value: &Value, output: &mut Vec<String>) -> Result<(), ProvenanceError> {
    if output.len() > MAX_SCALARS_PER_VALUE {
        return Err(ProvenanceError::TooManyScalars);
    }
    match value {
        Value::String(value) => output.push(value.clone()),
        Value::Number(value) => output.push(value.to_string()),
        Value::Bool(value) => output.push(value.to_string()),
        Value::Array(values) => {
            for value in values {
                collect_scalars(value, output)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_scalars(value, output)?;
            }
        }
        Value::Null => {}
    }
    Ok(())
}

fn bounded_utf8_chunks(value: &str, window_bytes: usize) -> Vec<String> {
    if value.len() < window_bytes {
        return Vec::new();
    }
    let mut starts: Vec<usize> = value.char_indices().map(|(index, _)| index).collect();
    starts.push(value.len());
    let mut output = Vec::new();
    for &start in &starts {
        let target = start.saturating_add(window_bytes);
        let Some(&end) = starts.iter().find(|&&index| index >= target) else {
            break;
        };
        if end > start {
            output.push(value[start..end].to_owned());
        }
        if output.len() >= MAX_CHUNKS_PER_SCALAR {
            break;
        }
    }
    output
}

fn validate_label(label: &str) -> Result<(), ProvenanceError> {
    if label.is_empty()
        || label.len() > 256
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProvenanceError::InvalidLabel);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{EvidenceMethod, Normalization, ProvenanceStore};

    #[test]
    fn exact_and_normalized_reuse_are_detected() {
        let mut store =
            ProvenanceStore::new([7; 32], 1_000).unwrap_or_else(|error| unreachable!("{error}"));
        store
            .register(
                "personal.messages.content",
                Normalization::Text,
                &json!("Meet at 10 AM"),
                true,
                true,
                Some((8, 8)),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = store
            .inspect(
                Normalization::Text,
                &json!({"body": "  MEET at 10 am  "}),
                &[8],
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(evidence.iter().any(|item| {
            item.label == "personal.messages.content" && item.method == EvidenceMethod::Normalized
        }));
    }

    #[test]
    fn keys_separate_installations() {
        let mut first =
            ProvenanceStore::new([1; 32], 100).unwrap_or_else(|error| unreachable!("{error}"));
        let mut second =
            ProvenanceStore::new([2; 32], 100).unwrap_or_else(|error| unreachable!("{error}"));
        for store in [&mut first, &mut second] {
            store
                .register(
                    "secret.value",
                    Normalization::Text,
                    &json!("password"),
                    true,
                    false,
                    None,
                )
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        let first_evidence = first
            .inspect(Normalization::Text, &json!("password"), &[])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second_evidence = second
            .inspect(Normalization::Text, &json!("password"), &[])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(
            first_evidence[0].fingerprint,
            second_evidence[0].fingerprint
        );
    }

    #[test]
    fn store_is_bounded_and_tracks_session_taint() {
        let mut store =
            ProvenanceStore::new([3; 32], 2).unwrap_or_else(|error| unreachable!("{error}"));
        store
            .register(
                "personal.messages.content",
                Normalization::Text,
                &json!(["one", "two", "three"]),
                true,
                false,
                None,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.len(), 2);
        assert_eq!(store.session_taint_evidence().len(), 1);
    }

    #[test]
    fn contact_normalization_matches_formatted_number() {
        let mut store =
            ProvenanceStore::new([4; 32], 100).unwrap_or_else(|error| unreachable!("{error}"));
        store
            .register(
                "personal.contacts",
                Normalization::Contact,
                &json!("+1 (555) 555-0100"),
                true,
                true,
                None,
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let evidence = store
            .inspect(Normalization::Contact, &json!("+15555550100"), &[])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!evidence.is_empty());
    }
}
