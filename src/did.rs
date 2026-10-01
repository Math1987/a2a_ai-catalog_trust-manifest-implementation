//! Current-state root did:web assertion-key selection from supplied documents.
//! The caller must obtain the document through a trusted resolver. Supplying an
//! arbitrary document does not authenticate a domain; the demo uses local pins.
use crate::{Error, Result, crypto, ensure, string};
use p256::ecdsa::VerifyingKey;
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

pub fn domain(signer: &str) -> Result<&str> {
    let name = signer
        .strip_prefix("did:web:")
        .ok_or_else(|| Error("expected root did:web".into()))?;
    ensure(
        !name.is_empty()
            && name.len() <= 253
            && name.is_ascii()
            && name == name.to_ascii_lowercase()
            && name.parse::<IpAddr>().is_err()
            && name.split('.').all(|s| {
                !s.is_empty()
                    && s.len() <= 63
                    && !s.starts_with('-')
                    && !s.ends_with('-')
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "invalid root did:web domain",
    )?;
    // WHATWG catches alternative IP spellings such as 2130706433.
    let url = url::Url::parse(&format!("https://{name}/"))
        .map_err(|_| Error("invalid DID hostname".into()))?;
    ensure(
        matches!(url.host(), Some(url::Host::Domain(_))) && url.host_str() == Some(name),
        "noncanonical DID hostname",
    )?;
    Ok(name)
}

pub fn validate_kid(signer: &str, kid: &str) -> Result<()> {
    domain(signer)?;
    let fragment = kid
        .strip_prefix(&format!("{signer}#"))
        .ok_or_else(|| Error("kid must be the exact signer DID plus a fragment".into()))?;
    ensure(!fragment.is_empty(), "empty kid fragment")?;
    let bytes = fragment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let b = bytes[index];
        if b == b'%' {
            ensure(
                index + 2 < bytes.len()
                    && bytes[index + 1].is_ascii_hexdigit()
                    && bytes[index + 2].is_ascii_hexdigit(),
                "invalid kid percent escape",
            )?;
            index += 3;
        } else {
            // RFC 3986 fragment = *( pchar / "/" / "?" ). No normalization:
            // the profile compares the resulting DID URL exactly.
            ensure(
                b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&b),
                "invalid kid fragment",
            )?;
            index += 1;
        }
    }
    Ok(())
}

pub fn document_url(signer: &str) -> Result<String> {
    Ok(format!("https://{}/.well-known/did.json", domain(signer)?))
}

fn absolute(reference: &str, signer: &str) -> String {
    if reference.starts_with('#') {
        format!("{signer}{reference}")
    } else {
        reference.into()
    }
}

pub fn assertion_key(document: &Value, signer: &str, kid: &str) -> Result<VerifyingKey> {
    validate_kid(signer, kid)?;
    ensure(
        string(document, "id")? == signer,
        "DID document id mismatch",
    )?;
    let mut methods = BTreeMap::new();
    if let Some(value) = document.get("verificationMethod") {
        for method in value
            .as_array()
            .ok_or_else(|| Error("verificationMethod must be an array".into()))?
        {
            let id = absolute(string(method, "id")?, signer);
            ensure(
                methods.insert(id, method).is_none(),
                "ambiguous duplicate verification method",
            )?;
        }
    }
    let assertions = document
        .get("assertionMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| Error("assertionMethod authorization required".into()))?;
    let mut matches = Vec::new();
    for assertion in assertions {
        if let Some(reference) = assertion.as_str() {
            if absolute(reference, signer) == kid {
                matches.push(
                    *methods
                        .get(kid)
                        .ok_or_else(|| Error("unresolved assertionMethod reference".into()))?,
                );
            }
        } else {
            let id = absolute(string(assertion, "id")?, signer);
            ensure(
                !methods.contains_key(&id),
                "ambiguous embedded verification method",
            )?;
            if id == kid {
                matches.push(assertion);
            }
        }
    }
    ensure(
        matches.len() == 1,
        "kid must select exactly one authorized assertion method",
    )?;
    let method = matches[0];
    string(method, "type")?;
    ensure(
        string(method, "controller")? == signer,
        "assertion controller mismatch",
    )?;
    let jwk = method
        .get("publicKeyJwk")
        .ok_or_else(|| Error("publicKeyJwk required".into()))?;
    ensure(
        string(jwk, "kty")? == "EC" && string(jwk, "crv")? == "P-256",
        "expected EC P-256 key",
    )?;
    ensure(
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .all(|name| jwk.get(*name).is_none()),
        "private key material is forbidden",
    )?;
    if let Some(alg) = jwk.get("alg") {
        ensure(alg.as_str() == Some("ES256"), "JWK alg mismatch")?;
    }
    if let Some(usage) = jwk.get("use") {
        ensure(usage.as_str() == Some("sig"), "JWK use mismatch")?;
    }
    if let Some(ops) = jwk.get("key_ops") {
        let ops = ops
            .as_array()
            .ok_or_else(|| Error("invalid JWK key_ops".into()))?;
        ensure(
            ops.iter().all(Value::is_string) && ops.iter().any(|v| v.as_str() == Some("verify")),
            "JWK key_ops does not permit verify",
        )?;
    }
    let x = crypto::decode(string(jwk, "x")?)?;
    let y = crypto::decode(string(jwk, "y")?)?;
    ensure(
        x.len() == 32 && y.len() == 32,
        "P-256 coordinates must be 32 bytes",
    )?;
    let point = [vec![4], x, y].concat();
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error("invalid P-256 curve point".into()))
}

pub fn publisher_did(entry: &Value) -> Result<String> {
    let id = string(entry, "identifier")?;
    let parts: Vec<_> = id.split(':').collect();
    ensure(
        parts.len() == 5
            && parts[0] == "urn"
            && parts[1] == "air"
            && parts
                .iter()
                .all(|s| !s.is_empty() && !s.chars().any(char::is_whitespace)),
        "expected standard urn:air publisher identifier",
    )?;
    let signer = format!("did:web:{}", parts[2]);
    domain(&signer)?;
    Ok(signer)
}
