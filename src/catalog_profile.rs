//! Current did:web Catalog Profile, pinned to PR123 at 2973e3a.
//!
//! Authentication concerns the declared host.identifier, never the retrieval
//! hostname. Supplied DID documents require trusted acquisition by the caller.
//! This module does not authenticate entry publishers, referenced artifacts or
//! Trust Manifest claims, and does not implement their schema validation.
//! Untrusted wire bytes must enter through json::parse: a prebuilt Value cannot
//! reveal duplicate members already discarded by a different JSON parser.
use crate::{
    DID_WEB_PROFILE, Error, Result, SigningContext, baseline, crypto, did, ensure, json, string,
    verification::Policy,
};
use serde::Serialize;
use serde_json::{Value, json as value};

pub const CATALOG_JWS_TYP: &str = "ai-catalog+jws";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogProfileReport {
    pub signer: String,
    pub signature_valid: bool,
    /// Conditional on the supplied DID document's trusted acquisition.
    pub signer_authenticated: bool,
    pub operator_attributed: bool,
    pub trusted_operator: bool,
    pub fresh: bool,
    pub snapshot_coverage: bool,
    pub accepted: bool,
    pub limitations: Vec<String>,
}

/// Validate only the root structure needed by this profile. Unknown members
/// remain present; individual entries and their claims are separate concerns.
pub fn validate_catalog(catalog: &Value) -> Result<()> {
    ensure(catalog.is_object(), "catalog must be an object")?;
    let version = string(catalog, "specVersion")?;
    let (major, minor) = version
        .split_once('.')
        .ok_or_else(|| Error("specVersion must be a Major.Minor string".into()))?;
    ensure(
        major == "1" && !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()),
        "unsupported or invalid catalog specVersion (supported major: 1)",
    )?;
    ensure(
        catalog.get("entries").is_some_and(Value::is_array),
        "catalog entries must be an array",
    )?;
    let host = catalog
        .get("host")
        .filter(|host| host.is_object())
        .ok_or_else(|| Error("catalog host must be an object".into()))?;
    ensure(
        host.get("displayName").is_some_and(Value::is_string),
        "catalog host.displayName must be a string",
    )?;
    string(host, "identifier")?;
    Ok(())
}

/// Reconstruct exactly the PR123 root payload. The two exclusions are local:
/// nested JWS/signatures, nested additionalSignatures, and unknown values stay.
/// A producer may supply an empty jws placeholder while constructing a signature.
pub fn payload(catalog: &Value) -> Result<Vec<u8>> {
    validate_catalog(catalog)?;
    let mut payload = catalog.clone();
    let root = payload.as_object_mut().expect("validated catalog object");
    root.remove("additionalSignatures");
    root.get_mut("signature")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error("catalog signature must be an object".into()))?
        .remove("jws");
    json::canonical(&payload)
}

/// Sign the complete snapshot using explicit authority and dates. Unknown
/// existing signature metadata is retained and signed when renewing a catalog.
pub fn sign_catalog(catalog: &Value, context: &SigningContext<'_>) -> Result<Value> {
    validate_catalog(catalog)?;
    did::domain(context.signer)?;
    did::validate_kid(context.signer, context.kid)?;
    ensure(
        catalog["host"]["identifier"].as_str() == Some(context.signer),
        "catalog host.identifier must exactly match the signing operator",
    )?;
    baseline::validate_times(context.issued_at, context.expires_at)?;
    let mut result = catalog.clone();
    if result.get("signature").is_none() {
        result["signature"] = value!({});
    }
    let signature = result["signature"]
        .as_object_mut()
        .ok_or_else(|| Error("catalog signature must be an object".into()))?;
    signature.insert("signer".into(), context.signer.into());
    signature.insert("profile".into(), DID_WEB_PROFILE.into());
    signature.insert("issuedAt".into(), context.issued_at.into());
    signature.insert("jws".into(), "".into());
    if let Some(expires) = context.expires_at {
        signature.insert("expiresAt".into(), expires.into());
    } else {
        signature.remove("expiresAt");
    }
    let jws = crypto::sign_typed(
        &payload(&result)?,
        context.signer,
        context.kid,
        context.key,
        CATALOG_JWS_TYP,
    )?;
    result["signature"]["jws"] = jws.into();
    Ok(result)
}

/// Verify the current DID authorization, whole snapshot and operator attribution.
/// The trust allowlist is caller configuration, never inferred from the catalog.
/// Invalid structure/cryptography returns an error; stale or unattributed valid
/// signatures produce an explicit report with accepted=false.
pub fn verify_catalog(
    catalog: &Value,
    document: &Value,
    policy: &Policy,
) -> Result<CatalogProfileReport> {
    validate_catalog(catalog)?;
    let signature = catalog
        .get("signature")
        .filter(|signature| signature.is_object())
        .ok_or_else(|| Error("catalog signature must be an object".into()))?;
    let signer = string(signature, "signer")?;
    let profile = string(signature, "profile")?;
    ensure(profile == DID_WEB_PROFILE, "unsupported signature profile")?;
    ensure(
        policy.allowed_profiles.contains(profile),
        "signature profile disallowed by policy",
    )?;
    did::domain(signer)?;
    let issued = string(signature, "issuedAt")?;
    let expires = signature
        .get("expiresAt")
        .map(|_| string(signature, "expiresAt"))
        .transpose()?;
    let fresh = policy.fresh(issued, expires)?;
    crypto::verify_typed(
        &payload(catalog)?,
        string(signature, "jws")?,
        signer,
        document,
        CATALOG_JWS_TYP,
    )?;
    let attributed = catalog["host"]["identifier"].as_str() == Some(signer);
    let trusted = policy.trusted_signers.contains(signer);
    Ok(CatalogProfileReport {
        signer: signer.into(), signature_valid: true, signer_authenticated: true,
        operator_attributed: attributed, trusted_operator: trusted, fresh,
        snapshot_coverage: true, accepted: attributed && trusted && fresh,
        limitations: vec![
            "DID authentication depends on trusted acquisition of the supplied current DID document.".into(),
            "Catalog attribution does not verify entry publishers, artifact integrity, claim truth or legal identity.".into(),
        ],
    })
}
