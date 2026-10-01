use crate::{Error, Result, ensure, json, string};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
pub struct Policy {
    pub trusted_signers: BTreeSet<String>,
    pub allowed_profiles: BTreeSet<String>,
    pub now: OffsetDateTime,
    pub clock_skew: Duration,
    pub require_expiry: bool,
}
impl Policy {
    pub fn new(trusted_signers: impl IntoIterator<Item = String>, now: OffsetDateTime) -> Self {
        Self {
            trusted_signers: trusted_signers.into_iter().collect(),
            allowed_profiles: BTreeSet::from([crate::DID_WEB_PROFILE.into()]),
            now,
            clock_skew: Duration::ZERO,
            require_expiry: true,
        }
    }
    pub fn fresh(&self, issued: &str, expires: Option<&str>) -> Result<bool> {
        ensure(
            self.clock_skew >= Duration::ZERO && self.clock_skew <= Duration::minutes(5),
            "clock skew must be between zero and five minutes",
        )?;
        let issued = timestamp(issued)?;
        let expires = expires.map(timestamp).transpose()?;
        if let Some(expires) = expires {
            ensure(expires > issued, "expiry must follow issuance")?;
        }
        Ok(issued <= self.now + self.clock_skew
            && expires
                .map(|e| self.now - self.clock_skew < e)
                .unwrap_or(!self.require_expiry))
    }
}
pub fn timestamp(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).map_err(|_| Error("invalid RFC3339 timestamp".into()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryReport {
    pub signer: String,
    pub signature_valid: bool,
    /// Authentication is relative to the supplied DID document's trusted origin.
    pub signer_authenticated: bool,
    pub trusted_signer: bool,
    pub fresh: bool,
    pub artifact_integrity: bool,
    pub subject_binding: Option<bool>,
    pub release_coverage: Option<bool>,
    pub claim_coverage: bool,
    pub contributor_attributed: Option<bool>,
    pub publisher_authorized: bool,
    pub accepted: bool,
    pub limitations: Vec<String>,
}

/// A claim is required at this exact path (or a signed ancestor). One signature
/// must meet every requirement; never aggregate coverage across reports.
#[derive(Default)]
pub struct Requirements {
    pub publisher: bool,
    pub contributor: Option<String>,
    pub claims: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogReport {
    pub signer: String,
    pub signature_valid: bool,
    pub trusted_operator: bool,
    pub fresh: Option<bool>,
    pub snapshot_coverage: bool,
    pub accepted: bool,
}

pub fn validate_entry(entry: &Value) -> Result<()> {
    ensure(entry.is_object(), "entry must be an object")?;
    string(entry, "identifier")?;
    string(entry, "type")?;
    ensure(
        entry.get("url").is_some() ^ entry.get("data").is_some(),
        "entry needs exactly one of url/data",
    )?;
    if entry.get("url").is_some() {
        string(entry, "url")?;
    }
    if entry.get("version").is_some() {
        string(entry, "version")?;
    }
    Ok(())
}

/// URL entries hash the supplied exact bytes. Inline entries hash JCS(data).
pub fn artifact_digest(entry: &Value, bytes: &[u8]) -> Result<String> {
    validate_entry(entry)?;
    Ok(match entry.get("data") {
        Some(data) => json::digest(&json::canonical(data)?),
        None => json::digest(bytes),
    })
}

pub fn validate_catalog(catalog: &Value) -> Result<()> {
    ensure(
        catalog.is_object()
            && catalog.get("specVersion").and_then(Value::as_str) == Some("1.0")
            && catalog.get("entries").is_some_and(Value::is_array),
        "expected AI Catalog 1.0 object with entries array",
    )
}
