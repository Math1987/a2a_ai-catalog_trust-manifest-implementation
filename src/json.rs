//! Duplicate-rejecting JSON boundary and RFC 8785 canonicalization.
use crate::{Error, Result, ensure};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("I-JSON without duplicate members")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                if v.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer exceeds local safe-integer policy"));
                }
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                if v > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer exceeds local safe-integer policy"));
                }
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON member: {key}")));
                    }
                    let Strict(v) = map.next_value()?;
                    values.insert(key, v);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(V)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value> {
    ensure(bytes.len() <= MAX_JSON_BYTES, "JSON exceeds 1 MiB")?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut deserializer).map_err(|e| Error(e.to_string()))?;
    deserializer.end().map_err(|e| Error(e.to_string()))?;
    Ok(value)
}

pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    // Revalidate even caller-created Values. Duplicate names can only be checked
    // before construction: untrusted wire input MUST enter through parse().
    let wire = serde_json::to_vec(value).map_err(|e| Error(e.to_string()))?;
    parse(&wire)?;
    serde_jcs::to_vec(value).map_err(|e| Error(e.to_string()))
}

pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}
