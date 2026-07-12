//! Bounded JSON-RPC 2.0 and MCP message handling.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt::Formatter;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// MCP protocol version implemented by the first AgentGate release.
pub const SUPPORTED_MCP_VERSION: &str = "2025-11-25";

/// Default maximum size of one newline-delimited JSON-RPC frame.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Resource limits applied before a frame is authorized or forwarded.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum bytes including the trailing newline.
    pub max_frame_bytes: usize,
    /// Maximum nested array/object depth.
    pub max_depth: usize,
    /// Maximum UTF-8 bytes in one JSON string.
    pub max_string_bytes: usize,
    /// Maximum elements in one array or object.
    pub max_collection_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_depth: 64,
            max_string_bytes: 1024 * 1024,
            max_collection_items: 100_000,
        }
    }
}

/// A JSON-RPC ID that can safely key pending-request state.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// String request identifier.
    String(String),
    /// Integer request identifier.
    Integer(i64),
    /// Discouraged but protocol-valid null identifier.
    Null,
}

/// Validated JSON-RPC message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Request with an ID.
    Request,
    /// Notification without an ID.
    Notification,
    /// Success response.
    Success,
    /// Error response.
    Error,
    /// Non-empty JSON-RPC batch.
    Batch,
}

/// A structurally validated JSON-RPC message.
#[derive(Clone, Debug)]
pub struct Message {
    value: Value,
    kind: MessageKind,
}

impl Message {
    /// Parses strict JSON, rejects duplicate keys, enforces limits, and validates JSON-RPC shape.
    pub fn parse(bytes: &[u8], limits: Limits) -> Result<Self, ProtocolError> {
        if bytes.len() > limits.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                actual: bytes.len(),
                maximum: limits.max_frame_bytes,
            });
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let UniqueValue(value) = UniqueValue::deserialize(&mut deserializer)
            .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
        deserializer
            .end()
            .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
        check_limits(&value, limits, 0)?;
        let kind = validate_message(&value)?;
        Ok(Self { value, kind })
    }

    /// Creates a message from an internally generated, valid JSON-RPC value.
    pub fn from_internal(value: Value) -> Result<Self, ProtocolError> {
        let kind = validate_message(&value)?;
        Ok(Self { value, kind })
    }

    /// Returns the validated message kind.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Returns the exact method for requests and notifications.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        self.value.get("method").and_then(Value::as_str)
    }

    /// Returns the request/response ID.
    #[must_use]
    pub fn id(&self) -> Option<JsonRpcId> {
        self.value.get("id").and_then(parse_id)
    }

    /// Returns the params member or JSON null when omitted.
    #[must_use]
    pub fn params(&self) -> &Value {
        self.value.get("params").unwrap_or(&Value::Null)
    }

    /// Returns the result member of a success response.
    #[must_use]
    pub fn result(&self) -> Option<&Value> {
        self.value.get("result")
    }

    /// Returns the original validated JSON value.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.value
    }

    /// Consumes this message and returns its JSON value.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.value
    }

    /// Serializes the message as one newline-delimited frame.
    pub fn to_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = serde_json::to_vec(&self.value).map_err(ProtocolError::Serialize)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Creates a valid JSON-RPC error response containing an AgentGate code.
#[must_use]
pub fn error_response(
    id: Option<JsonRpcId>,
    code: i64,
    agentgate_code: &str,
    message: &str,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(JsonRpcId::Null),
        "error": {
            "code": code,
            "message": message,
            "data": { "agentgate_code": agentgate_code }
        }
    })
}

/// Reads one newline-delimited frame with a strict byte cap.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limits: Limits,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut bytes = Vec::new();
    let read = reader
        .take((limits.max_frame_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(ProtocolError::Io)?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > limits.max_frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            actual: bytes.len(),
            maximum: limits.max_frame_bytes,
        });
    }
    if bytes.last() != Some(&b'\n') {
        return Err(ProtocolError::MissingNewline);
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    Ok(Some(bytes))
}

/// Writes one JSON-RPC value as a newline-delimited frame and flushes it.
pub async fn write_value<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
) -> Result<(), ProtocolError> {
    let mut bytes = serde_json::to_vec(value).map_err(ProtocolError::Serialize)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)
}

/// Protocol/framing failures that always prevent forwarding.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Frame exceeds configured bytes.
    #[error("frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge {
        /// Observed bytes.
        actual: usize,
        /// Configured cap.
        maximum: usize,
    },
    /// Frame ended without the required newline delimiter.
    #[error("stdio JSON-RPC frame is not newline terminated")]
    MissingNewline,
    /// Strict JSON parsing failed.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// JSON-RPC shape violates the 2.0 contract.
    #[error("invalid JSON-RPC request: {0}")]
    InvalidRequest(String),
    /// A configured structural resource bound was exceeded.
    #[error("JSON resource limit exceeded: {0}")]
    LimitExceeded(String),
    /// Transport read/write failed.
    #[error("transport I/O failed: {0}")]
    Io(std::io::Error),
    /// Internally generated JSON could not be serialized.
    #[error("JSON serialization failed: {0}")]
    Serialize(serde_json::Error),
}

fn validate_message(value: &Value) -> Result<MessageKind, ProtocolError> {
    if let Value::Array(messages) = value {
        if messages.is_empty() {
            return Err(ProtocolError::InvalidRequest("empty batch".to_owned()));
        }
        for message in messages {
            validate_single(message)?;
        }
        return Ok(MessageKind::Batch);
    }
    validate_single(value)
}

fn validate_single(value: &Value) -> Result<MessageKind, ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::InvalidRequest("message must be an object".to_owned()))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ProtocolError::InvalidRequest(
            "jsonrpc must equal 2.0".to_owned(),
        ));
    }
    if let Some(method) = object.get("method") {
        if method.as_str().is_none_or(str::is_empty) {
            return Err(ProtocolError::InvalidRequest(
                "method must be a non-empty string".to_owned(),
            ));
        }
        if let Some(params) = object.get("params")
            && !matches!(params, Value::Object(_) | Value::Array(_))
        {
            return Err(ProtocolError::InvalidRequest(
                "params must be an object or array".to_owned(),
            ));
        }
        return if object.contains_key("id") {
            validate_id(object.get("id"))?;
            Ok(MessageKind::Request)
        } else {
            Ok(MessageKind::Notification)
        };
    }

    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(ProtocolError::InvalidRequest(
            "response must contain exactly one of result or error".to_owned(),
        ));
    }
    if !object.contains_key("id") {
        return Err(ProtocolError::InvalidRequest(
            "response must contain id".to_owned(),
        ));
    }
    validate_id(object.get("id"))?;
    if has_error {
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolError::InvalidRequest("error must be an object".to_owned()))?;
        if error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none()
        {
            return Err(ProtocolError::InvalidRequest(
                "error requires integer code and string message".to_owned(),
            ));
        }
        Ok(MessageKind::Error)
    } else {
        Ok(MessageKind::Success)
    }
}

fn validate_id(value: Option<&Value>) -> Result<(), ProtocolError> {
    match value {
        Some(Value::String(_) | Value::Null) => Ok(()),
        Some(Value::Number(number)) if number.as_i64().is_some() => Ok(()),
        _ => Err(ProtocolError::InvalidRequest(
            "id must be a string, integer, or null".to_owned(),
        )),
    }
}

fn parse_id(value: &Value) -> Option<JsonRpcId> {
    match value {
        Value::String(value) => Some(JsonRpcId::String(value.clone())),
        Value::Number(value) => value.as_i64().map(JsonRpcId::Integer),
        Value::Null => Some(JsonRpcId::Null),
        _ => None,
    }
}

fn check_limits(value: &Value, limits: Limits, depth: usize) -> Result<(), ProtocolError> {
    if depth > limits.max_depth {
        return Err(ProtocolError::LimitExceeded(format!(
            "depth exceeds {}",
            limits.max_depth
        )));
    }
    match value {
        Value::String(value) if value.len() > limits.max_string_bytes => {
            Err(ProtocolError::LimitExceeded(format!(
                "string exceeds {} bytes",
                limits.max_string_bytes
            )))
        }
        Value::Array(values) => {
            if values.len() > limits.max_collection_items {
                return Err(ProtocolError::LimitExceeded(format!(
                    "array exceeds {} items",
                    limits.max_collection_items
                )));
            }
            for value in values {
                check_limits(value, limits, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > limits.max_collection_items {
                return Err(ProtocolError::LimitExceeded(format!(
                    "object exceeds {} items",
                    limits.max_collection_items
                )));
            }
            for (key, value) in values {
                if key.len() > limits.max_string_bytes {
                    return Err(ProtocolError::LimitExceeded(
                        "object key exceeds string limit".to_owned(),
                    ));
                }
                check_limits(value, limits, depth + 1)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor).map(Self)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueValue(value)) = sequence.next_element::<UniqueValue>()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate object key: {key}")));
            }
            let UniqueValue(value) = object.next_value_seed(UniqueValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct UniqueValueSeed;

impl<'de> DeserializeSeed<'de> for UniqueValueSeed {
    type Value = UniqueValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Limits, Message, MessageKind, ProtocolError, error_response};

    #[test]
    fn parses_request_and_notification() {
        let request = Message::parse(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            Limits::default(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(request.kind(), MessageKind::Request);
        assert_eq!(request.method(), Some("tools/list"));

        let notification = Message::parse(
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            Limits::default(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(notification.kind(), MessageKind::Notification);
    }

    #[test]
    fn rejects_duplicate_keys() {
        let result = Message::parse(
            br#"{"jsonrpc":"2.0","method":"ping","method":"tools/call","id":1}"#,
            Limits::default(),
        );
        let Err(error) = result else {
            unreachable!("duplicate key must be rejected")
        };
        assert!(matches!(error, ProtocolError::InvalidJson(_)));
    }

    #[test]
    fn rejects_scalar_params_and_fractional_id() {
        assert!(
            Message::parse(
                br#"{"jsonrpc":"2.0","method":"x","params":"bad","id":1}"#,
                Limits::default()
            )
            .is_err()
        );
        assert!(
            Message::parse(
                br#"{"jsonrpc":"2.0","method":"x","id":1.5}"#,
                Limits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn enforces_depth_and_string_limits() {
        let limits = Limits {
            max_depth: 2,
            max_string_bytes: 3,
            ..Limits::default()
        };
        assert!(Message::parse(br#"{"jsonrpc":"2.0","method":"long"}"#, limits).is_err());
        assert!(
            Message::parse(
                br#"{"jsonrpc":"2.0","method":"x","params":{"a":{"b":1}}}"#,
                limits
            )
            .is_err()
        );
    }

    #[test]
    fn generated_error_is_valid_json_rpc() {
        let value = error_response(None, -32_000, "AG-POLICY-NO-MATCH", "denied");
        let message = Message::from_internal(value).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(message.kind(), MessageKind::Error);
        assert_eq!(
            message.as_value()["error"]["data"],
            json!({"agentgate_code": "AG-POLICY-NO-MATCH"})
        );
    }
}
