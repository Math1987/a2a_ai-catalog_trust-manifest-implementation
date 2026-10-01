//! Main at 04a99cd: whole-manifest JCS and detached JWS. Exact root did:web,
//! ES256 and assertion authorization are explicit local restrictions here.
use crate::{
    Error, Result, SigningContext, crypto, did, ensure, json as strict, string,
    verification::{self, CatalogReport, EntryReport, Policy},
};
use serde_json::{Value, json};

pub fn manifest_payload(manifest: &Value) -> Result<Vec<u8>> {
    let mut payload = manifest
        .as_object()
        .ok_or_else(|| Error("manifest must be an object".into()))?
        .clone();
    payload.remove("signature");
    strict::canonical(&Value::Object(payload))
}

/// Return a new entry. Never replace an existing manifest or change publisher
/// identity silently. Callers own evidence validation before invoking this.
pub fn sign_entry(
    entry: &Value,
    claims: &Value,
    artifact: &[u8],
    context: &SigningContext<'_>,
) -> Result<Value> {
    verification::validate_entry(entry)?;
    ensure(
        entry.get("trustManifests").is_none() && entry.get("signatures").is_none(),
        "mixed catalog dialects",
    )?;
    ensure(
        entry.get("trustManifest").is_none(),
        "entry already contains a manifest",
    )?;
    ensure(
        did::publisher_did(entry)? == context.signer,
        "baseline identity must align with publisher namespace",
    )?;
    let allowed = [
        "trustSchema",
        "extensions",
        "attestations",
        "provenance",
        "privacyPolicyUrl",
        "termsOfServiceUrl",
    ];
    let mut manifest = claims
        .as_object()
        .ok_or_else(|| Error("claims must be an object".into()))?
        .clone();
    ensure(
        manifest.keys().all(|k| allowed.contains(&k.as_str())),
        "unsupported baseline claim field",
    )?;
    validate_claim_fields(claims)?;
    validate_times(context.issued_at, context.expires_at)?;
    manifest.insert("identity".into(), context.signer.into());
    let mut subject =
        json!({"type":entry["type"], "digest":verification::artifact_digest(entry,artifact)?});
    if let Some(url) = entry.get("url") {
        subject["url"] = url.clone();
    }
    manifest.insert("subject".into(), subject);
    manifest.insert("issuedAt".into(), context.issued_at.into());
    if let Some(expires) = context.expires_at {
        manifest.insert("expiresAt".into(), expires.into());
    }
    let mut manifest = Value::Object(manifest);
    manifest["signature"] = crypto::sign(
        &manifest_payload(&manifest)?,
        context.signer,
        context.kid,
        context.key,
    )?
    .into();
    let mut result = entry.clone();
    result["trustManifest"] = manifest;
    Ok(result)
}

pub fn verify_entry(
    entry: &Value,
    artifact: &[u8],
    document: &Value,
    policy: &Policy,
) -> Result<EntryReport> {
    verification::validate_entry(entry)?;
    ensure(
        entry.get("trustManifests").is_none() && entry.get("signatures").is_none(),
        "mixed catalog dialects",
    )?;
    let manifest = entry
        .get("trustManifest")
        .ok_or_else(|| Error("trustManifest missing".into()))?;
    let signer = string(manifest, "identity")?;
    let subject = manifest
        .get("subject")
        .ok_or_else(|| Error("subject missing".into()))?;
    string(subject, "type")?;
    string(subject, "digest")?;
    validate_claim_fields(manifest)?;
    let expires = manifest
        .get("expiresAt")
        .map(|_| string(manifest, "expiresAt"))
        .transpose()?;
    let fresh = policy.fresh(string(manifest, "issuedAt")?, expires)?;
    crypto::verify(
        &manifest_payload(manifest)?,
        string(manifest, "signature")?,
        signer,
        document,
    )?;
    let subject_binding = subject.get("type") == entry.get("type")
        && subject
            .get("url")
            .map(|url| Some(url) == entry.get("url"))
            .unwrap_or(true);
    let integrity =
        subject["digest"].as_str() == Some(&verification::artifact_digest(entry, artifact)?);
    let publisher = did::publisher_did(entry)? == signer;
    let trusted = policy.trusted_signers.contains(signer);
    Ok(EntryReport {
        signer: signer.into(),
        signature_valid: true,
        signer_authenticated: true,
        trusted_signer: trusted,
        fresh,
        artifact_integrity: integrity,
        subject_binding: Some(subject_binding),
        release_coverage: None,
        claim_coverage: true,
        contributor_attributed: None,
        publisher_authorized: publisher,
        accepted: trusted && fresh && integrity && subject_binding && publisher,
        limitations: vec![
            "Baseline signature does not bind entry identifier/version or catalog membership."
                .into(),
            "Claim truth, DNS/consent, current registry status and transparency are not checked."
                .into(),
        ],
    })
}

pub fn sign_catalog(catalog: &Value, context: &SigningContext<'_>) -> Result<Value> {
    verification::validate_catalog(catalog)?;
    ensure(
        catalog.get("signatures").is_none(),
        "mixed catalog dialects",
    )?;
    let mut result = catalog.clone();
    result["signature"] = crypto::sign(
        &manifest_payload(catalog)?,
        context.signer,
        context.kid,
        context.key,
    )?
    .into();
    Ok(result)
}

/// `signer` and the authorized-operator policy come from independent configuration.
/// Baseline root signatures define no endorsement timestamps of their own.
pub fn verify_catalog(
    catalog: &Value,
    signer: &str,
    document: &Value,
    policy: &Policy,
) -> Result<CatalogReport> {
    verification::validate_catalog(catalog)?;
    ensure(
        catalog.get("signatures").is_none(),
        "mixed catalog dialects",
    )?;
    crypto::verify(
        &manifest_payload(catalog)?,
        string(catalog, "signature")?,
        signer,
        document,
    )?;
    let trusted = policy.trusted_signers.contains(signer);
    Ok(CatalogReport {
        signer: signer.into(),
        signature_valid: true,
        trusted_operator: trusted,
        fresh: None,
        snapshot_coverage: true,
        accepted: trusted,
    })
}

pub(crate) fn validate_times(issued: &str, expires: Option<&str>) -> Result<()> {
    let issued = verification::timestamp(issued)?;
    if let Some(expires) = expires {
        ensure(
            verification::timestamp(expires)? > issued,
            "expiry must follow issuance",
        )?;
    }
    Ok(())
}

pub(crate) fn validate_claim_fields(claims: &Value) -> Result<()> {
    ensure(claims.is_object(), "claims must be an object")?;
    if let Some(schema) = claims.get("trustSchema") {
        string(schema, "identifier")?;
        string(schema, "version")?;
    }
    if let Some(extensions) = claims.get("extensions") {
        ensure(extensions.is_object(), "extensions must be an object")?;
    }
    for name in ["attestations", "provenance"] {
        if let Some(value) = claims.get(name) {
            ensure(value.is_array(), "attestations/provenance must be arrays")?;
        }
    }
    Ok(())
}
