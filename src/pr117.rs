//! PR #117 at 51df07b: selected-field payloads, explicit did-web-v1 profile.
use crate::{
    DID_WEB_PROFILE, Error, Result, SigningContext, baseline, crypto, did, ensure, json as strict,
    verification::{self, CatalogReport, EntryReport, Policy, Requirements},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub type Path = Vec<String>;
#[derive(Clone, Copy)]
pub enum Scope {
    Entry,
    Catalog,
}
impl Scope {
    fn context(self) -> &'static str {
        match self {
            Self::Entry => "ai-catalog-entry-signature",
            Self::Catalog => "ai-catalog-catalog-signature",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signature {
    pub signer: String,
    pub profile: String,
    pub paths: Vec<Path>,
    pub issued_at: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "present_expiry"
    )]
    pub expires_at: Option<String>,
    pub jws: String,
}

// Absent expiry is allowed, explicit null is not.
fn present_expiry<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

pub fn resolve<'a>(object: &'a Value, path: &[String]) -> Result<&'a Value> {
    ensure(
        !path.is_empty() && path[0] != "signatures",
        "empty path or selection of containing signatures",
    )?;
    let mut value = object;
    for segment in path {
        value = value
            .as_object()
            .and_then(|o| o.get(segment))
            .ok_or_else(|| {
                Error(format!(
                    "missing object member or array traversal in {path:?}"
                ))
            })?;
    }
    Ok(value)
}

pub fn payload(object: &Value, signature: &Signature, scope: Scope) -> Result<Vec<u8>> {
    ensure(
        signature.profile == DID_WEB_PROFILE,
        "unsupported signature profile",
    )?;
    did::domain(&signature.signer)?;
    baseline::validate_times(&signature.issued_at, signature.expires_at.as_deref())?;
    ensure(
        !signature.paths.is_empty() && signature.paths.len() <= 128,
        "expected 1–128 paths (local bound)",
    )?;
    let mut fields = Vec::new();
    for path in &signature.paths {
        fields.push((path, resolve(object, path)?));
    }
    // Vec ordering supplies path-prefix semantics. Each segment uses UTF-16,
    // not Rust's UTF-8 byte ordering. Duplicates and overlaps are preserved.
    fields.sort_by_cached_key(|(path, _)| {
        path.iter()
            .map(|s| s.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>()
    });
    let mut value = json!({"context":scope.context(), "signer":signature.signer, "profile":signature.profile,
        "fields":fields, "issuedAt":signature.issued_at});
    if let Some(expires) = &signature.expires_at {
        value["expiresAt"] = expires.clone().into();
    }
    strict::canonical(&value)
}

/// Low-level selected-field signing. It can intentionally sign a partial
/// endorsement; consumers MUST use verify_entry/verify_catalog for acceptance.
pub fn sign_selected(
    object: &Value,
    paths: Vec<Path>,
    scope: Scope,
    context: &SigningContext<'_>,
) -> Result<Signature> {
    let mut result = Signature {
        signer: context.signer.into(),
        profile: DID_WEB_PROFILE.into(),
        paths,
        issued_at: context.issued_at.into(),
        expires_at: context.expires_at.map(String::from),
        jws: String::new(),
    };
    result.jws = crypto::sign(
        &payload(object, &result, scope)?,
        context.signer,
        context.kid,
        context.key,
    )?;
    Ok(result)
}

pub fn release_paths(entry: &Value) -> Vec<Path> {
    let mut paths: Vec<_> = ["identifier", "type", "digest"]
        .iter()
        .map(|s| vec![s.to_string()])
        .collect();
    for name in ["version", "url"] {
        if entry.get(name).is_some() {
            paths.push(vec![name.into()]);
        }
    }
    paths
}

pub fn snapshot_paths(catalog: &Value) -> Result<Vec<Path>> {
    Ok(catalog
        .as_object()
        .ok_or_else(|| Error("catalog must be an object".into()))?
        .keys()
        .filter(|k| *k != "signatures")
        .map(|k| vec![k.clone()])
        .collect())
}

/// Create or replace this signer's complete contribution. Existing signatures
/// by this signer are removed; other signatures are preserved and must be
/// rechecked (they may have intentionally covered this contribution).
pub fn endorse_entry(
    entry: &Value,
    claims: &Value,
    artifact: &[u8],
    context: &SigningContext<'_>,
) -> Result<Value> {
    verification::validate_entry(entry)?;
    ensure(
        entry.get("trustManifest").is_none(),
        "mixed catalog dialects",
    )?;
    validate_manifest(claims)?;
    let mut result = entry.clone();
    let digest = verification::artifact_digest(entry, artifact)?;
    if let Some(existing) = entry.get("digest") {
        ensure(
            existing.as_str() == Some(&digest),
            "existing digest does not match artifact",
        )?;
    }
    result["digest"] = digest.into();
    if result.get("trustManifests").is_none() {
        result["trustManifests"] = json!({});
    }
    result["trustManifests"]
        .as_object_mut()
        .ok_or_else(|| Error("trustManifests must be an object".into()))?
        .insert(context.signer.into(), claims.clone());
    let mut paths = release_paths(&result);
    paths.push(vec!["trustManifests".into(), context.signer.into()]);
    let signature = sign_selected(&result, paths, Scope::Entry, context)?;
    let mut signatures = match result.get("signatures") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| Error("signatures must be an array".into()))?
            .clone(),
        None => Vec::new(),
    };
    signatures.retain(|s| s.get("signer").and_then(Value::as_str) != Some(context.signer));
    signatures.push(serde_json::to_value(signature).map_err(|e| Error(e.to_string()))?);
    result["signatures"] = signatures.into();
    Ok(result)
}

pub fn verify_signature(
    object: &Value,
    signature: &Signature,
    scope: Scope,
    document: &Value,
    policy: &Policy,
) -> Result<bool> {
    ensure(
        policy.allowed_profiles.contains(&signature.profile),
        "signature profile disallowed by policy",
    )?;
    let bytes = payload(object, signature, scope)?;
    crypto::verify(&bytes, &signature.jws, &signature.signer, document)?;
    policy.fresh(&signature.issued_at, signature.expires_at.as_deref())
}

pub fn verify_entry(
    entry: &Value,
    signature: &Signature,
    artifact: &[u8],
    document: &Value,
    policy: &Policy,
    required: &Requirements,
) -> Result<EntryReport> {
    verification::validate_entry(entry)?;
    ensure(
        entry.get("trustManifest").is_none(),
        "mixed catalog dialects",
    )?;
    let fresh = verify_signature(entry, signature, Scope::Entry, document, policy)?;
    let mut release_fields = vec!["identifier", "type", "digest"];
    if entry.get("version").is_some() {
        release_fields.push("version");
    }
    let release = release_fields.iter().all(|name| {
        signature
            .paths
            .iter()
            .any(|p| p.len() == 1 && p[0] == *name)
    });
    let integrity = entry.get("digest").and_then(Value::as_str)
        == Some(&verification::artifact_digest(entry, artifact)?);
    let publisher = did::publisher_did(entry)
        .map(|d| d == signature.signer)
        .unwrap_or(false);
    let mut claim_coverage = required
        .claims
        .iter()
        .all(|p| resolve(entry, p).is_ok() && covers(&signature.paths, p));
    let attribution = if let Some(contributor) = &required.contributor {
        let path = vec!["trustManifests".into(), contributor.clone()];
        let manifest_valid = resolve(entry, &path).and_then(validate_manifest).is_ok();
        claim_coverage &= manifest_valid && covers(&signature.paths, &path);
        Some(signature.signer == *contributor && manifest_valid && covers(&signature.paths, &path))
    } else {
        None
    };
    let trusted = policy.trusted_signers.contains(&signature.signer);
    Ok(EntryReport {
        signer: signature.signer.clone(),
        signature_valid: true,
        signer_authenticated: true,
        trusted_signer: trusted,
        fresh,
        artifact_integrity: integrity,
        subject_binding: None,
        release_coverage: Some(release),
        claim_coverage,
        contributor_attributed: attribution,
        publisher_authorized: publisher,
        accepted: trusted
            && fresh
            && integrity
            && release
            && claim_coverage
            && attribution.unwrap_or(true)
            && (!required.publisher || publisher),
        limitations: vec![
            "Only selected fields are endorsed; catalog membership is not verified.".into(),
            "Claim truth, DNS/consent, current registry status and transparency are not checked."
                .into(),
        ],
    })
}

pub fn verify_catalog(
    catalog: &Value,
    signature: &Signature,
    document: &Value,
    policy: &Policy,
) -> Result<CatalogReport> {
    verification::validate_catalog(catalog)?;
    ensure(catalog.get("signature").is_none(), "mixed catalog dialects")?;
    let fresh = verify_signature(catalog, signature, Scope::Catalog, document, policy)?;
    let coverage = snapshot_paths(catalog)?
        .iter()
        .all(|p| signature.paths.contains(p));
    let trusted = policy.trusted_signers.contains(&signature.signer);
    Ok(CatalogReport {
        signer: signature.signer.clone(),
        signature_valid: true,
        trusted_operator: trusted,
        fresh: Some(fresh),
        snapshot_coverage: coverage,
        accepted: trusted && fresh && coverage,
    })
}

pub fn covers(paths: &[Path], claim: &[String]) -> bool {
    !claim.is_empty() && paths.iter().any(|p| !p.is_empty() && claim.starts_with(p))
}

pub fn validate_manifest(value: &Value) -> Result<()> {
    baseline::validate_claim_fields(value)?;
    let map = value.as_object().expect("validated object");
    ensure(
        map.keys().all(|k| {
            ["trustSchema", "extensions", "attestations", "provenance"].contains(&k.as_str())
        }),
        "unsupported PR manifest field",
    )?;
    ensure(
        value.get("trustSchema").is_some()
            || ["attestations", "provenance"].iter().any(|k| {
                value
                    .get(*k)
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
            })
            || value
                .get("extensions")
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty()),
        "empty PR trust manifest",
    )
}
