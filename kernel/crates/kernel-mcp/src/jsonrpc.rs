//! JSON-RPC 2.0 envelope used on the MCP wire.
//!
//! This module is deliberately vendor-free: it knows the envelope shape, the
//! request-id allocator and the small set of methods this client speaks, and
//! nothing about any provider.
//!
//! Every server- or peer-supplied string (a JSON-RPC error `message`, an
//! unknown method name, a version mismatch, a string response `id`) is copied
//! through [`Sanitized`] before it can reach a `Display`/`Debug`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::error::{
    sanitize_untrusted, McpError, Sanitized, INVALID_REQUEST, MAX_UNTRUSTED_BYTES, METHOD_NOT_FOUND,
};

/// The exact JSON-RPC version string.
pub const JSONRPC_VERSION: &str = "2.0";

/// The methods this client understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Initialize,
    Initialized,
    ToolsList,
    ToolsCall,
    ToolsListChanged,
}

impl Method {
    /// The wire spelling of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Initialize => "initialize",
            Method::Initialized => "notifications/initialized",
            Method::ToolsList => "tools/list",
            Method::ToolsCall => "tools/call",
            Method::ToolsListChanged => "notifications/tools/list_changed",
        }
    }

    /// Parse a wire method name; an unknown name becomes a typed error whose
    /// (untrusted) echo is bounded and stripped of control characters.
    pub fn parse(name: &str) -> Result<Self, McpError> {
        match name {
            "initialize" => Ok(Method::Initialize),
            "notifications/initialized" => Ok(Method::Initialized),
            "tools/list" => Ok(Method::ToolsList),
            "tools/call" => Ok(Method::ToolsCall),
            "notifications/tools/list_changed" => Ok(Method::ToolsListChanged),
            other => Err(McpError::protocol(
                METHOD_NOT_FOUND,
                &format!("unknown method: {other}"),
            )),
        }
    }
}

/// A request envelope. `jsonrpc` is always [`JSONRPC_VERSION`].
#[derive(Clone, PartialEq, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

impl fmt::Debug for JsonRpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRpcRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field(
                "params_bytes",
                &serde_json::to_vec(&self.params).map_or(0, |v| v.len()),
            )
            .finish()
    }
}

impl JsonRpcRequest {
    /// Build a request with the pinned version.
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            method: method.into(),
            params,
        }
    }
}

impl<'de> Deserialize<'de> for JsonRpcRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            jsonrpc: String,
            id: u64,
            method: String,
            #[serde(default)]
            params: Value,
        }
        let Raw {
            jsonrpc,
            id,
            method,
            params,
        } = Raw::deserialize(deserializer)?;
        if jsonrpc != JSONRPC_VERSION {
            return Err(D::Error::custom(sanitize_untrusted(
                &format!("unsupported jsonrpc version: {jsonrpc}"),
                MAX_UNTRUSTED_BYTES,
            )));
        }
        Ok(Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            method,
            params,
        })
    }
}

/// A JSON-RPC error object. `message` is sanitised on decode.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: Sanitized,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl fmt::Debug for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonRpcError")
            .field("code", &self.code)
            .field("message_bytes", &self.message.len())
            .field("data_present", &self.data.is_some())
            .finish()
    }
}

/// A response id: JSON-RPC allows a number **or** a string, and a notification
/// carries none. `Null` covers both `id: null` and an absent `id`.
///
/// Numbers must be non-negative integers that fit `u64` exactly (`u64::MAX`
/// included); negatives, fractions and out-of-range values are rejected with a
/// decode error rather than coerced or panicked on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ResponseId {
    Number(u64),
    String(Sanitized),
    #[default]
    Null,
}

impl ResponseId {
    /// The id when it is numeric.
    pub fn as_number(&self) -> Option<u64> {
        match self {
            ResponseId::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// The id when it is a string (already sanitised).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ResponseId::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Whether the id was absent or explicitly `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, ResponseId::Null)
    }
}

impl Serialize for ResponseId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ResponseId::Number(value) => serializer.serialize_u64(*value),
            ResponseId::String(value) => serializer.serialize_str(value.as_str()),
            ResponseId::Null => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for ResponseId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ResponseIdVisitor;

        impl<'de> serde::de::Visitor<'de> for ResponseIdVisitor {
            type Value = ResponseId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON-RPC id: a non-negative integer, a string, or null")
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<ResponseId, E> {
                Ok(ResponseId::Null)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<ResponseId, E> {
                Ok(ResponseId::Null)
            }

            fn visit_some<D2: Deserializer<'de>>(self, inner: D2) -> Result<ResponseId, D2::Error> {
                ResponseId::deserialize(inner)
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<ResponseId, E> {
                Ok(ResponseId::Number(value))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<ResponseId, E> {
                if value < 0 {
                    return Err(E::custom("response id must not be negative"));
                }
                Ok(ResponseId::Number(value as u64))
            }

            fn visit_u128<E: serde::de::Error>(self, value: u128) -> Result<ResponseId, E> {
                u64::try_from(value)
                    .map(ResponseId::Number)
                    .map_err(|_| E::custom("response id is out of u64 range"))
            }

            fn visit_i128<E: serde::de::Error>(self, value: i128) -> Result<ResponseId, E> {
                u64::try_from(value)
                    .map(ResponseId::Number)
                    .map_err(|_| E::custom("response id is out of u64 range"))
            }

            fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<ResponseId, E> {
                Err(E::custom("response id must be an integer, not a float"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<ResponseId, E> {
                Ok(ResponseId::String(Sanitized::new(value)))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<ResponseId, E> {
                Ok(ResponseId::String(Sanitized::new(&value)))
            }
        }

        deserializer.deserialize_any(ResponseIdVisitor)
    }
}

/// A response envelope. `jsonrpc` is pinned to [`JSONRPC_VERSION`] on decode.
#[derive(Clone, PartialEq, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "ResponseId::is_null")]
    pub id: ResponseId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl fmt::Debug for JsonRpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result_bytes = self
            .result
            .as_ref()
            .map(|v| serde_json::to_vec(v).map_or(0, |v| v.len()));
        f.debug_struct("JsonRpcResponse")
            .field("id", &self.id)
            .field("result_bytes", &result_bytes)
            .field("error_present", &self.error.is_some())
            .finish()
    }
}

impl JsonRpcResponse {
    /// Construct a successful response.
    pub fn success(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id: ResponseId::Number(id),
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    pub fn failure(id: u64, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id: ResponseId::Number(id),
            result: None,
            error: Some(error),
        }
    }

    /// Decode the envelope into the result value or a typed error.
    pub fn into_result(self) -> Result<Value, McpError> {
        if let Some(err) = self.error {
            return Err(McpError::Protocol {
                code: err.code,
                message: err.message,
            });
        }
        self.result.ok_or_else(|| {
            McpError::protocol(INVALID_REQUEST, "response carried neither result nor error")
        })
    }
}

impl<'de> Deserialize<'de> for JsonRpcResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            jsonrpc: String,
            #[serde(default)]
            id: ResponseId,
            #[serde(default)]
            result: Option<Value>,
            #[serde(default)]
            error: Option<JsonRpcError>,
        }
        let Raw {
            jsonrpc,
            id,
            result,
            error,
        } = Raw::deserialize(deserializer)?;
        if jsonrpc != JSONRPC_VERSION {
            return Err(D::Error::custom(sanitize_untrusted(
                &format!("unsupported jsonrpc version: {jsonrpc}"),
                MAX_UNTRUSTED_BYTES,
            )));
        }
        Ok(Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result,
            error,
        })
    }
}

/// Monotonic `u64` request-id allocator: ids start at 1, never repeat and
/// never return 0 (0 is reserved as the "no id" sentinel on the wire).
///
/// The counter advances with a checked add, so it never wraps back to a value
/// that was already issued. When the `[1, u64::MAX - 1]` space is exhausted,
/// [`IdGenerator::next_id`] reports `None` instead of repeating an id.
#[derive(Debug)]
pub struct IdGenerator {
    next: AtomicU64,
}

impl IdGenerator {
    /// A fresh allocator whose first id is 1.
    pub fn new() -> Self {
        Self::starting_at(1)
    }

    /// Seed the allocator so the first id returned is `first` (clamped to at
    /// least 1; 0 is never handed out).
    pub fn starting_at(first: u64) -> Self {
        Self {
            next: AtomicU64::new(first.max(1)),
        }
    }

    /// Allocate the next id, or `None` once the `u64` space is exhausted.
    pub fn next_id(&self) -> Option<u64> {
        self.next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()
    }
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod security_debug_tests {
    use super::*;

    #[test]
    fn debug_hides_request_arguments_and_response_data() {
        let canary = "CANARY_IGNORE_PRIOR_INSTRUCTIONS";
        let request = JsonRpcRequest::new(
            17,
            "tools/call",
            serde_json::json!({"arguments":{"secret":canary}}),
        );
        let response = JsonRpcResponse::success(
            17,
            serde_json::json!({"content":[{"type":"text","text":canary}]}),
        );
        assert!(!format!("{request:?}").contains(canary));
        assert!(!format!("{response:?}").contains(canary));
        let error = JsonRpcError {
            code: -1,
            message: Sanitized::new("safe"),
            data: Some(serde_json::json!({"secret":canary})),
        };
        assert!(!format!("{error:?}").contains(canary));
    }
}
