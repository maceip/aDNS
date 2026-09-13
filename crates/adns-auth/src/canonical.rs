use crate::{AuthError, MAX_REQUEST_BYTES, MAX_SAFE_INTEGER};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON with nonnegative safe integers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer exceeds 2^53-1"));
                }
                Ok(StrictValue(Value::Number(Number::from(v))))
            }
            fn visit_i64<E: de::Error>(self, _v: i64) -> Result<Self::Value, E> {
                Err(E::custom("negative integers forbidden"))
            }
            fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Self::Value, E> {
                Err(E::custom("floating point syntax forbidden"))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = a.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON property"));
                    }
                    values.insert(key, a.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

/// The supported JCS schema deliberately excludes all floating point and
/// negative numeric syntax, including 1.0, 1e0 and -0. JSON escapes are decoded
/// before duplicate detection, so {"a":1,"\u0061":2} is rejected as well.
pub fn parse_strict_json(bytes: &[u8]) -> Result<Value, AuthError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(AuthError::InvalidJson("request exceeds byte limit".into()));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|e| AuthError::InvalidJson(e.to_string()))?;
    deserializer
        .end()
        .map_err(|e| AuthError::InvalidJson(e.to_string()))?;
    Ok(value.0)
}

/// RFC 8785 on the nonnegative safe-integer schema. Property ordering uses UTF-16
/// code units (not UTF-8 or Unicode scalar order); strings use JSON escaping.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, AuthError> {
    fn append(value: &Value, out: &mut Vec<u8>) -> Result<(), AuthError> {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Number(number) => {
                let n = number
                    .as_u64()
                    .filter(|v| *v <= MAX_SAFE_INTEGER)
                    .ok_or_else(|| AuthError::InvalidJson("unsupported number".into()))?;
                out.extend_from_slice(n.to_string().as_bytes());
            }
            Value::String(text) => serde_json::to_writer(out, text)
                .map_err(|e| AuthError::InvalidJson(e.to_string()))?,
            Value::Array(values) => {
                out.push(b'[');
                for (i, value) in values.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    append(value, out)?;
                }
                out.push(b']');
            }
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                out.push(b'{');
                for (i, key) in keys.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key)
                        .map_err(|e| AuthError::InvalidJson(e.to_string()))?;
                    out.push(b':');
                    append(&values[*key], out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    append(value, &mut out)?;
    Ok(out)
}

pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthError> {
    canonical_json(&serde_json::to_value(value).map_err(|e| AuthError::InvalidJson(e.to_string()))?)
}
