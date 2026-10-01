//! Pure signature mechanics for two explicitly pinned AI Catalog dialects.
//!
//! No DNS certification, registry authorization, or claim truth is implied by
//! signing. Callers supply evidence and independent trust configuration.
pub mod baseline;
pub mod crypto;
pub mod did;
#[cfg(feature = "http")]
pub mod fetch;
pub mod json;
pub mod pr117;
pub mod verification;

pub const BASELINE_REVISION: &str = "04a99cd1ac9a20dd6586c6196e87f5e4570303b1";
pub const PR117_REVISION: &str = "51df07b58e831f71ab6047672d6482ef93f5015f";
pub const DID_WEB_PROFILE: &str = "did-web-v1";

/// Explicit signing authority and endorsement dates; never inferred from entry metadata.
pub struct SigningContext<'a> {
    pub signer: &'a str,
    pub kid: &'a str,
    pub key: &'a dyn crypto::Es256Signer,
    pub issued_at: &'a str,
    pub expires_at: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}

pub(crate) fn string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error(format!("missing/non-string {key}")))
}
