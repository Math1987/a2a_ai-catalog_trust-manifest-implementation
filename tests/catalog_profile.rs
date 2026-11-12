//! Independent contract tests for PR #123, head 2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad.
//! Test signers are ephemeral. No production keys or online trust roots are used.
use aithos_catalog_signatures::{
    SigningContext, catalog_profile,
    crypto::{self, Es256Signer, LocalKey},
    json,
    verification::{Policy, timestamp},
};
use serde_json::{Value, json as v};
use std::path::PathBuf;
use time::Duration;

const SIGNER: &str = "did:web:catalog-test.example";
const KID: &str = "did:web:catalog-test.example#assertion-key";
const ISSUED: &str = "2026-11-12T12:00:00Z";
const EXPIRES: &str = "2026-11-12T13:00:00Z";
const NOW: &str = "2026-11-12T12:30:00Z";

fn catalog() -> Value {
    v!({"specVersion":"1.0","host":{"displayName":"Public test operator","identifier":SIGNER},
        "entries":[{"identifier":"urn:air:publisher.example:a2a:discovery",
            "type":"application/a2a-agent-card+json","url":"https://publisher.example/card.json"}]})
}

fn policy() -> Policy {
    Policy::new([SIGNER.into()], timestamp(NOW).unwrap())
}

fn context(key: &LocalKey) -> SigningContext<'_> {
    SigningContext {
        signer: SIGNER,
        kid: KID,
        key,
        issued_at: ISSUED,
        expires_at: Some(EXPIRES),
    }
}

fn header() -> Value {
    v!({"alg":"ES256","typ":"ai-catalog+jws","kid":KID})
}

// Deliberately does not call catalog_profile::payload or sign_catalog.
fn independent_payload(catalog: &Value) -> Vec<u8> {
    let mut value = catalog.clone();
    value
        .as_object_mut()
        .unwrap()
        .remove("additionalSignatures");
    value["signature"].as_object_mut().unwrap().remove("jws");
    serde_jcs::to_vec(&value).unwrap()
}

fn seal_header_bytes(mut catalog: Value, key: &LocalKey, protected: &[u8]) -> Value {
    let encoded = crypto::encode(protected);
    let input = format!(
        "{}.{}",
        encoded,
        crypto::encode(&independent_payload(&catalog))
    );
    let signature = key.sign_es256(input.as_bytes()).unwrap();
    catalog["signature"]["jws"] = format!("{encoded}..{}", crypto::encode(&signature)).into();
    catalog
}

fn seal(catalog: Value, key: &LocalKey, protected: Value) -> Value {
    seal_header_bytes(catalog, key, &serde_json::to_vec(&protected).unwrap())
}

fn signed(key: &LocalKey) -> Value {
    let mut value = catalog();
    value["signature"] =
        v!({"signer":SIGNER,"profile":"did-web-v1","issuedAt":ISSUED,"expiresAt":EXPIRES});
    seal(value, key, header())
}

fn document(key: &LocalKey) -> Value {
    key.did_document(SIGNER, KID).unwrap()
}

fn reject(catalog: &Value, doc: &Value, p: &Policy, label: &str) {
    match catalog_profile::verify_catalog(catalog, doc, p) {
        Err(_) => (),
        Ok(report) => assert!(!report.accepted, "incorrectly accepted {label}"),
    }
}

fn crypto_valid(catalog: &Value, doc: &Value) {
    crypto::verify(
        &independent_payload(catalog),
        catalog["signature"]["jws"].as_str().unwrap(),
        SIGNER,
        doc,
    )
    .unwrap();
}

#[test]
fn plain_catalog_needs_neither_publisher_endorsement_nor_trust_manifest() {
    let key = LocalKey::generate();
    let value = signed(&key);
    assert!(value["entries"][0].get("publisher").is_none());
    assert!(value["entries"][0].get("trustManifests").is_none());
    let report = catalog_profile::verify_catalog(&value, &document(&key), &policy()).unwrap();
    assert!(report.signature_valid && report.signer_authenticated && report.operator_attributed);
    assert!(report.snapshot_coverage && report.trusted_operator && report.fresh && report.accepted);
    assert_eq!(report.signer, SIGNER);
    // Signing through the production entry point must interoperate with the independent payload.
    let generated = catalog_profile::sign_catalog(&catalog(), &context(&key)).unwrap();
    crypto_valid(&generated, &document(&key));
    assert_eq!(
        catalog_profile::payload(&generated).unwrap(),
        independent_payload(&generated)
    );
}

#[test]
fn payload_exclusions_are_exact_and_not_recursive() {
    let input = v!({"specVersion":"1.0","host":{"displayName":"Test","identifier":SIGNER},"entries":[],
        "signature":{"signer":SIGNER,"profile":"did-web-v1","issuedAt":ISSUED,"jws":"omit-root-only","value":"keep-unknown"},
        "additionalSignatures":{"any":"omitted"},
        "trustManifests":[{"signature":{"jws":"keep-root-unknown-trust"}}],
        "unknown":{"jws":"keep","additionalSignatures":["keep-too"]}});
    let expected = v!({"specVersion":"1.0","host":{"displayName":"Test","identifier":SIGNER},"entries":[],
        "signature":{"signer":SIGNER,"profile":"did-web-v1","issuedAt":ISSUED,"value":"keep-unknown"},
        "trustManifests":[{"signature":{"jws":"keep-root-unknown-trust"}}],
        "unknown":{"jws":"keep","additionalSignatures":["keep-too"]}});
    assert_eq!(
        catalog_profile::payload(&input).unwrap(),
        serde_jcs::to_vec(&expected).unwrap()
    );
}

fn nested_catalog(key: &LocalKey) -> Value {
    let mut c = signed(key);
    c["entries"][0]["trustManifests"] = v!([{"contributor":"did:web:assessor.example",
        "subject":{"identifier":"urn:air:publisher.example:a2a:discovery","type":"application/a2a-agent-card+json","digest":"sha256:abc"},
        "signature":{"signer":"did:web:assessor.example","profile":"future-profile","issuedAt":ISSUED,"jws":"opaque-unverified-evidence"},
        "additionalSignatures":{"reserved":"nested-covered"}}]);
    c["unknown"] = v!({"jws":"covered","additionalSignatures":["covered"],"future":"value"});
    c["signature"]["value"] = "unknown-signature-member-covered".into();
    seal(c, key, header())
}

#[test]
fn root_signature_covers_unknowns_entries_and_nested_manifest_signatures() {
    let key = LocalKey::generate();
    let c = nested_catalog(&key);
    let doc = document(&key);
    assert!(
        catalog_profile::verify_catalog(&c, &doc, &policy())
            .unwrap()
            .accepted
    );
    for pointer in [
        "/host/displayName",
        "/entries/0/url",
        "/unknown/future",
        "/unknown/jws",
        "/unknown/additionalSignatures/0",
        "/signature/value",
        "/entries/0/trustManifests/0/signature/jws",
        "/entries/0/trustManifests/0/additionalSignatures/reserved",
        "/entries/0/trustManifests/0/contributor",
    ] {
        let mut changed = c.clone();
        *changed.pointer_mut(pointer).unwrap() = v!("tampered");
        assert!(
            catalog_profile::verify_catalog(&changed, &doc, &policy()).is_err(),
            "{pointer}"
        );
    }
    let mut changed = c.clone();
    changed["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("trustManifests");
    assert!(catalog_profile::verify_catalog(&changed, &doc, &policy()).is_err());
    let mut changed = c.clone();
    changed["unknownNewField"] = true.into();
    assert!(catalog_profile::verify_catalog(&changed, &doc, &policy()).is_err());
}

#[test]
fn reserved_root_additional_signatures_can_be_added_changed_or_removed() {
    let key = LocalKey::generate();
    let c = signed(&key);
    for arbitrary in [
        Value::Null,
        v!(false),
        v!([{"jws":"no-authority"}]),
        v!({"arbitrary":"ignored"}),
    ] {
        let mut changed = c.clone();
        changed["additionalSignatures"] = arbitrary;
        assert!(
            catalog_profile::verify_catalog(&changed, &document(&key), &policy())
                .unwrap()
                .accepted
        );
        changed
            .as_object_mut()
            .unwrap()
            .remove("additionalSignatures");
        assert!(
            catalog_profile::verify_catalog(&changed, &document(&key), &policy())
                .unwrap()
                .accepted
        );
    }
}

fn reverse_keys_wire(value: &Value) -> String {
    match value {
        Value::Object(o) => format!(
            "{{ {} }}",
            o.iter()
                .rev()
                .map(|(k, v)| format!(
                    "{} : {}",
                    serde_json::to_string(k).unwrap(),
                    reverse_keys_wire(v)
                ))
                .collect::<Vec<_>>()
                .join(",\n")
        ),
        Value::Array(a) => format!(
            "[ {} ]",
            a.iter()
                .map(reverse_keys_wire)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

#[test]
fn whitespace_and_object_key_order_do_not_change_jcs_but_array_order_does() {
    let key = LocalKey::generate();
    let mut c = signed(&key);
    c["entries"]
        .as_array_mut()
        .unwrap()
        .push(v!({"identifier":"second","type":"application/json","data":{"hello":"world"}}));
    c = seal(c, &key, header());
    let roundtrip = json::parse(reverse_keys_wire(&c).as_bytes()).unwrap();
    assert!(
        catalog_profile::verify_catalog(&roundtrip, &document(&key), &policy())
            .unwrap()
            .accepted
    );
    assert_eq!(
        independent_payload(&c),
        catalog_profile::payload(&roundtrip).unwrap()
    );
    c["entries"].as_array_mut().unwrap().reverse();
    assert!(catalog_profile::verify_catalog(&c, &document(&key), &policy()).is_err());
}

#[test]
fn resigned_host_mismatches_have_valid_crypto_but_fail_operator_attribution() {
    let key = LocalKey::generate();
    let doc = document(&key);
    for host in [
        "did:web:other.example",
        "did:web:CATALOG-test.example",
        "DID:web:catalog-test.example",
        "did:web:catalog-test.example.",
        "did:web:catalog-test.example:catalog",
        "https://catalog-test.example/",
        "did:web:catalog-test%2eexample",
    ] {
        let mut c = signed(&key);
        c["host"]["identifier"] = host.into();
        let c = seal(c, &key, header());
        crypto_valid(&c, &doc);
        let report = catalog_profile::verify_catalog(&c, &doc, &policy()).unwrap();
        assert!(
            report.signature_valid && report.signer_authenticated,
            "{host}"
        );
        assert!(!report.operator_attributed && !report.accepted, "{host}");
    }
}

#[test]
fn absent_host_and_absent_or_nonstring_identifier_cannot_be_accepted() {
    let key = LocalKey::generate();
    for missing in ["host", "identifier", "nonstring"] {
        let mut c = signed(&key);
        match missing {
            "host" => {
                c.as_object_mut().unwrap().remove("host");
            }
            "identifier" => {
                c["host"].as_object_mut().unwrap().remove("identifier");
            }
            _ => c["host"]["identifier"] = v!([SIGNER]),
        }
        let c = seal(c, &key, header());
        crypto_valid(&c, &document(&key));
        reject(&c, &document(&key), &policy(), missing);
    }
}

#[test]
fn authenticated_operator_still_requires_independent_trust_policy() {
    let key = LocalKey::generate();
    let p = Policy::new(Vec::<String>::new(), timestamp(NOW).unwrap());
    let report = catalog_profile::verify_catalog(&signed(&key), &document(&key), &p).unwrap();
    assert!(report.operator_attributed && report.signer_authenticated && report.signature_valid);
    assert!(!report.trusted_operator && !report.accepted);
}

#[test]
fn assertion_authorization_is_required_and_can_be_embedded() {
    let key = LocalKey::generate();
    let c = signed(&key);
    let mut doc = document(&key);
    doc.as_object_mut().unwrap().remove("assertionMethod");
    assert!(catalog_profile::verify_catalog(&c, &doc, &policy()).is_err());
    doc["authentication"] = v!([KID]);
    assert!(catalog_profile::verify_catalog(&c, &doc, &policy()).is_err());
    doc["keyAgreement"] = v!([KID]);
    assert!(catalog_profile::verify_catalog(&c, &doc, &policy()).is_err());
    let mut embedded = document(&key);
    embedded["assertionMethod"] = v!([embedded["verificationMethod"][0].clone()]);
    embedded
        .as_object_mut()
        .unwrap()
        .remove("verificationMethod");
    assert!(
        catalog_profile::verify_catalog(&c, &embedded, &policy())
            .unwrap()
            .accepted
    );
}

#[test]
fn invalid_did_identity_controller_ambiguous_keys_or_private_material_fail() {
    let key = LocalKey::generate();
    let c = signed(&key);
    let good = document(&key);
    let mutations = [
        ("/id", v!("did:web:other.example")),
        (
            "/verificationMethod/0/controller",
            v!("did:web:other.example"),
        ),
        (
            "/verificationMethod/0/id",
            v!("did:web:catalog-test.example#wrong"),
        ),
        ("/verificationMethod/0/publicKeyJwk/kty", v!("OKP")),
        ("/verificationMethod/0/publicKeyJwk/crv", v!("P-384")),
        ("/verificationMethod/0/publicKeyJwk/alg", v!("ES384")),
        ("/verificationMethod/0/publicKeyJwk/use", v!("enc")),
        ("/verificationMethod/0/publicKeyJwk/key_ops", v!(["sign"])),
        (
            "/verificationMethod/0/publicKeyJwk/x",
            v!(crypto::encode(&[0; 32])),
        ),
    ];
    for (path, value) in mutations {
        let mut doc = good.clone();
        *doc.pointer_mut(path).unwrap() = value;
        assert!(
            catalog_profile::verify_catalog(&c, &doc, &policy()).is_err(),
            "{path}"
        );
    }
    for private in ["d", "k", "p", "q"] {
        let mut doc = good.clone();
        doc["verificationMethod"][0]["publicKeyJwk"][private] = "not-a-production-secret".into();
        assert!(
            catalog_profile::verify_catalog(&c, &doc, &policy()).is_err(),
            "{private}"
        );
    }
    let mut duplicate = good.clone();
    duplicate["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(good["verificationMethod"][0].clone());
    assert!(catalog_profile::verify_catalog(&c, &duplicate, &policy()).is_err());
    let mut duplicate = good.clone();
    duplicate["assertionMethod"] = v!([KID, KID]);
    assert!(catalog_profile::verify_catalog(&c, &duplicate, &policy()).is_err());
    let other_key = LocalKey::generate();
    assert!(catalog_profile::verify_catalog(&c, &document(&other_key), &policy()).is_err());
}

#[test]
fn embedded_jwk_kid_is_not_the_key_selection_authority() {
    let key = LocalKey::generate();
    let mut doc = document(&key);
    doc["verificationMethod"][0]["publicKeyJwk"]["kid"] = "an-irrelevant-inner-kid".into();
    assert!(
        catalog_profile::verify_catalog(&signed(&key), &doc, &policy())
            .unwrap()
            .accepted
    );
}

#[test]
fn protected_headers_are_checked_even_with_a_valid_signature() {
    let key = LocalKey::generate();
    let c = signed(&key);
    let mut headers = Vec::new();
    for (name, value) in [
        ("typ", v!("ai-catalog-trust-manifest+jws")),
        ("typ", v!("AI-CATALOG+JWS")),
        ("alg", v!("none")),
        ("alg", v!("ES384")),
        ("b64", v!(false)),
        ("b64", v!(true)),
        ("jku", v!("https://attacker.example/keys")),
        ("jwk", key.public_jwk()),
        ("x5u", v!("https://attacker.example/cert")),
        ("x5c", v!(["attacker"])),
        ("kid", v!("did:web:other.example#assertion-key")),
        ("kid", v!("did:web:catalog-test.example#")),
        ("kid", v!("did:web:catalog-test.example/path#assertion-key")),
        (
            "kid",
            v!("did:web:catalog-test.example?query#assertion-key"),
        ),
        ("crit", v!(["unknown-critical"])),
    ] {
        let mut h = header();
        h[name] = value;
        headers.push((name.to_string(), h));
    }
    for missing in ["typ", "alg", "kid"] {
        let mut h = header();
        h.as_object_mut().unwrap().remove(missing);
        headers.push((format!("missing-{missing}"), h));
    }
    for (label, h) in headers {
        assert!(
            catalog_profile::verify_catalog(&seal(c.clone(), &key, h), &document(&key), &policy())
                .is_err(),
            "{label}"
        );
    }
    let mut h = header();
    h["cty"] = "application/ai-catalog+json".into();
    assert!(
        catalog_profile::verify_catalog(&seal(c, &key, h), &document(&key), &policy())
            .unwrap()
            .accepted
    );
}

#[test]
fn profile_is_explicit_and_cannot_fall_back() {
    let key = LocalKey::generate();
    for name in [
        "",
        "DID-WEB-V1",
        "did-web-v2",
        "https://catalog-test.example/profiles/custom",
    ] {
        let mut c = signed(&key);
        c["signature"]["profile"] = name.into();
        assert!(
            catalog_profile::verify_catalog(&seal(c, &key, header()), &document(&key), &policy())
                .is_err(),
            "{name}"
        );
    }
    let mut p = policy();
    p.allowed_profiles.clear();
    reject(
        &signed(&key),
        &document(&key),
        &p,
        "locally disallowed profile",
    );
}

#[test]
fn unknown_noncritical_headers_are_authenticated_and_ignored_but_critical_ones_fail() {
    let key = LocalKey::generate();
    let c = signed(&key);
    for value in [v!("metadata"), v!(42), v!({"future":"extension"})] {
        let mut h = header();
        h["extra"] = value;
        let signed = seal(c.clone(), &key, h.clone());
        assert!(
            catalog_profile::verify_catalog(&signed, &document(&key), &policy())
                .unwrap()
                .accepted
        );
        h["crit"] = v!(["extra"]);
        assert!(
            catalog_profile::verify_catalog(&seal(c.clone(), &key, h), &document(&key), &policy())
                .is_err()
        );
    }
}

#[test]
fn timestamps_compare_instants_and_enforce_issuance_expiry_boundaries() {
    let key = LocalKey::generate();
    let c = signed(&key);
    let doc = document(&key);
    for (now, accepted) in [
        ("2026-11-12T11:59:59Z", false),
        (ISSUED, true),
        ("2026-11-12T12:59:59Z", true),
        (EXPIRES, false),
    ] {
        let mut p = policy();
        p.now = timestamp(now).unwrap();
        assert_eq!(
            catalog_profile::verify_catalog(&c, &doc, &p)
                .unwrap()
                .accepted,
            accepted,
            "{now}"
        );
    }
    let mut offset = c.clone();
    offset["signature"]["issuedAt"] = "2026-11-12T14:00:00+02:00".into();
    offset["signature"]["expiresAt"] = "2026-11-12T08:00:00-05:00".into();
    assert!(
        catalog_profile::verify_catalog(&seal(offset, &key, header()), &doc, &policy())
            .unwrap()
            .accepted
    );
    for invalid in ["not-a-time", "2026-11-12", "2026-11-12T12:00:00Z"] {
        let mut invalid_expiry = c.clone();
        invalid_expiry["signature"]["expiresAt"] = invalid.into();
        assert!(
            catalog_profile::verify_catalog(&seal(invalid_expiry, &key, header()), &doc, &policy())
                .is_err(),
            "{invalid}"
        );
    }
    let mut skew = policy();
    skew.now = timestamp("2026-11-12T11:59:30Z").unwrap();
    skew.clock_skew = Duration::seconds(30);
    assert!(
        catalog_profile::verify_catalog(&c, &doc, &skew)
            .unwrap()
            .accepted
    );
}

#[test]
fn expiry_is_optional_in_spec_and_can_be_required_by_local_policy() {
    let key = LocalKey::generate();
    let mut c = signed(&key);
    c["signature"].as_object_mut().unwrap().remove("expiresAt");
    let c = seal(c, &key, header());
    let mut p = policy();
    p.require_expiry = false;
    assert!(
        catalog_profile::verify_catalog(&c, &document(&key), &p)
            .unwrap()
            .accepted
    );
    p.require_expiry = true;
    reject(&c, &document(&key), &p, "locally required expiry");
}

#[test]
fn duplicate_and_malformed_wire_json_is_rejected_before_value_construction() {
    for bytes in [
        br#"{"specVersion":"1.0","specVersion":"1.0","entries":[]}"#.as_slice(),
        br#"{"host":{"identifier":"a","identifier":"b"}}"#.as_slice(),
        br#"{"signature":{"jws":"a","jws":"b"}}"#.as_slice(),
        br#"{"entries":[{"data":{"same":1,"same":2}}]}"#.as_slice(),
        br#"{"entries":[]} trailing"#.as_slice(),
        br#"{"broken":NaN}"#.as_slice(),
    ] {
        assert!(json::parse(bytes).is_err());
    }
    let key = LocalKey::generate();
    let raw =
        format!(r#"{{"alg":"ES256","typ":"ai-catalog+jws","typ":"ai-catalog+jws","kid":"{KID}"}}"#);
    let c = seal_header_bytes(signed(&key), &key, raw.as_bytes());
    assert!(catalog_profile::verify_catalog(&c, &document(&key), &policy()).is_err());
}

#[cfg(feature = "http")]
#[test]
fn safe_fetch_rejects_alternative_private_ip_spellings_and_private_dns() {
    use aithos_catalog_signatures::fetch::Fetcher;
    for origin in [
        "https://127.1",
        "https://2130706433",
        "https://0x7f000001",
        "https://[::ffff:127.0.0.1]",
    ] {
        match Fetcher::new([origin.into()]) {
            Err(_) => (),
            Ok(f) => assert!(f.checked_url(origin).is_err(), "{origin}"),
        }
    }
    // Local hostname resolution only: rejection occurs before any HTTPS connection.
    let f = Fetcher::new(["https://localhost".into()]).unwrap();
    assert!(f.get("https://localhost/.well-known/did.json").is_err());
}

struct Vector {
    id: &'static str,
    catalog: Value,
    doc: Value,
    accepted: bool,
    trusted: bool,
    require_expiry: bool,
    now: &'static str,
}

fn public_vectors(key: &LocalKey) -> Vec<Vector> {
    let c = signed(key);
    let doc = document(key);
    let mut out = Vec::new();
    let mut add = |id, catalog, doc, accepted| {
        out.push(Vector {
            id,
            catalog,
            doc,
            accepted,
            trusted: true,
            require_expiry: true,
            now: NOW,
        })
    };
    add("valid", c.clone(), doc.clone(), true);
    let mut x = c.clone();
    x["additionalSignatures"] = v!({"arbitrary":"ignored"});
    add("root-additional-signatures", x, doc.clone(), true);
    let nested = nested_catalog(key);
    add("nested-opaque-evidence", nested.clone(), doc.clone(), true);
    for (id, path) in [
        ("tampered-url", "/entries/0/url"),
        (
            "tampered-nested-jws",
            "/entries/0/trustManifests/0/signature/jws",
        ),
        (
            "tampered-nested-additional-signatures",
            "/entries/0/trustManifests/0/additionalSignatures/reserved",
        ),
        ("tampered-unknown-field", "/unknown/future"),
    ] {
        let mut x = nested.clone();
        *x.pointer_mut(path).unwrap() = v!("tampered");
        add(id, x, doc.clone(), false);
    }
    for (id, host) in [
        ("resigned-host-mismatch", "did:web:other.example"),
        (
            "resigned-host-case-mismatch",
            "did:web:CATALOG-test.example",
        ),
        (
            "resigned-host-uri-normalization",
            "did:web:catalog-test%2eexample",
        ),
    ] {
        let mut x = c.clone();
        x["host"]["identifier"] = host.into();
        add(id, seal(x, key, header()), doc.clone(), false);
    }
    let mut x = c.clone();
    x.as_object_mut().unwrap().remove("host");
    add(
        "resigned-no-host",
        seal(x, key, header()),
        doc.clone(),
        false,
    );
    for (id, name, value) in [
        ("wrong-typ", "typ", v!("ai-catalog-trust-manifest+jws")),
        ("b64-false", "b64", v!(false)),
        ("b64-true", "b64", v!(true)),
        ("alg-none", "alg", v!("none")),
        ("header-jwk-injection", "jwk", key.public_jwk()),
        ("unknown-critical", "crit", v!(["unknown-critical"])),
    ] {
        let mut h = header();
        h[name] = value;
        add(id, seal(c.clone(), key, h), doc.clone(), false);
    }
    let mut h = header();
    h["cty"] = "application/ai-catalog+json".into();
    add("optional-cty", seal(c.clone(), key, h), doc.clone(), true);
    let mut h = header();
    h["extra"] = v!({"metadata":"future-extension"});
    add(
        "unknown-noncritical-header",
        seal(c.clone(), key, h),
        doc.clone(),
        true,
    );
    let mut d = doc.clone();
    d.as_object_mut().unwrap().remove("assertionMethod");
    add("verification-method-only", c.clone(), d.clone(), false);
    d["authentication"] = v!([KID]);
    add("authentication-only", c.clone(), d, false);
    for (id, path, value) in [
        ("wrong-did-id", "/id", v!("did:web:other.example")),
        (
            "wrong-controller",
            "/verificationMethod/0/controller",
            v!("did:web:other.example"),
        ),
        (
            "invalid-p256-point",
            "/verificationMethod/0/publicKeyJwk/x",
            v!(crypto::encode(&[0; 32])),
        ),
    ] {
        let mut d = doc.clone();
        *d.pointer_mut(path).unwrap() = value;
        add(id, c.clone(), d, false);
    }
    let mut d = doc.clone();
    d["verificationMethod"][0]["publicKeyJwk"]["d"] = "deliberately-invalid-test-marker".into();
    add("private-jwk-forbidden", c.clone(), d, false);
    let mut d = doc.clone();
    d["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(doc["verificationMethod"][0].clone());
    add("duplicate-verification-method", c.clone(), d, false);
    let mut x = c.clone();
    x["signature"]["issuedAt"] = "2026-11-12T12:31:00Z".into();
    add("future-issued", seal(x, key, header()), doc.clone(), false);
    let mut x = c.clone();
    x["signature"]["expiresAt"] = NOW.into();
    add(
        "expiry-boundary",
        seal(x, key, header()),
        doc.clone(),
        false,
    );
    let mut x = c.clone();
    x["signature"]["issuedAt"] = "2026-11-12T14:00:00+02:00".into();
    x["signature"]["expiresAt"] = "2026-11-12T08:00:00-05:00".into();
    add(
        "equivalent-timestamp-instants",
        seal(x, key, header()),
        doc.clone(),
        true,
    );
    let mut x = c.clone();
    x["signature"].as_object_mut().unwrap().remove("expiresAt");
    out.push(Vector {
        id: "no-expiry-permitted",
        catalog: seal(x, key, header()),
        doc: doc.clone(),
        accepted: true,
        trusted: true,
        require_expiry: false,
        now: NOW,
    });
    out.push(Vector {
        id: "untrusted-operator",
        catalog: c,
        doc,
        accepted: false,
        trusted: false,
        require_expiry: true,
        now: NOW,
    });
    out
}

fn vectors_dir() -> PathBuf {
    match std::env::var_os("PR123_VECTOR_DIR") {
        Some(path) => {
            assert!(!path.is_empty(), "PR123_VECTOR_DIR must not be empty");
            PathBuf::from(path)
        }
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/pr123"),
    }
}

#[test]
#[ignore = "Explicitly generates public proof vectors using an ephemeral in-memory test key"]
fn generate_public_proof_vectors() {
    let root = vectors_dir();
    assert!(
        !root.exists() || std::fs::read_dir(&root).unwrap().next().is_none(),
        "Refusing to replace existing proof vectors; set PR123_VECTOR_DIR to a new empty directory"
    );
    std::fs::create_dir_all(&root).unwrap();
    let key = LocalKey::generate();
    let vectors = public_vectors(&key);
    let mut index = Vec::new();
    for case in vectors {
        let dir = root.join("cases").join(case.id);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = serde_json::to_vec_pretty(&case.catalog).unwrap();
        let did_bytes = serde_json::to_vec_pretty(&case.doc).unwrap();
        std::fs::write(dir.join("catalog.json"), &bytes).unwrap();
        std::fs::write(dir.join("did.json"), &did_bytes).unwrap();
        let mut p = Policy::new(
            if case.trusted {
                vec![SIGNER.into()]
            } else {
                vec![]
            },
            timestamp(case.now).unwrap(),
        );
        p.require_expiry = case.require_expiry;
        let result = catalog_profile::verify_catalog(&case.catalog, &case.doc, &p);
        let actual = result.as_ref().is_ok_and(|report| report.accepted);
        assert_eq!(actual, case.accepted, "{}", case.id);
        let observed = match result {
            Ok(report) => serde_json::to_value(report).unwrap(),
            Err(error) => v!({"error":error.to_string()}),
        };
        index.push(v!({"id":case.id,"catalog":format!("cases/{}/catalog.json",case.id),"didDocument":format!("cases/{}/did.json",case.id),"expectedAccepted":case.accepted,"trustedOperators":p.trusted_signers,"requireExpiry":case.require_expiry,"now":case.now,"observedRust":observed,"catalogSha256":json::digest(&bytes),"didSha256":json::digest(&did_bytes)}));
        if case.id == "valid" {
            std::fs::write(root.join("valid-catalog.json"), &bytes).unwrap();
            std::fs::write(root.join("did.json"), &did_bytes).unwrap();
        }
    }
    let mut malformed = serde_json::to_string(&signed(&key)).unwrap();
    malformed.insert_str(1, "\"specVersion\":\"1.0\",");
    let dir = root.join("cases/duplicate-json-member");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("catalog.json"), malformed.as_bytes()).unwrap();
    std::fs::write(
        dir.join("did.json"),
        serde_json::to_vec_pretty(&document(&key)).unwrap(),
    )
    .unwrap();
    index.push(v!({"id":"duplicate-json-member","catalog":"cases/duplicate-json-member/catalog.json","didDocument":"cases/duplicate-json-member/did.json","expectedAccepted":false,"trustedOperators":[SIGNER],"requireExpiry":true,"now":NOW,"observedRust":{"error":"duplicate JSON member rejected at wire boundary"},"catalogSha256":json::digest(malformed.as_bytes())}));
    let manifest = v!({"profile":"did-web-v1","specificationHead":"2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad","purpose":"Public test vectors only; keys generated ephemerally and never exported. DID documents are offline fixture pins, not live domain authentication.","cases":index});
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn published_proof_vectors_replay_without_private_keys() {
    let root = vectors_dir();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("index.json")).expect("generate proof vectors first"),
    )
    .unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let bytes = std::fs::read(root.join(case["catalog"].as_str().unwrap())).unwrap();
        let doc =
            json::parse(&std::fs::read(root.join(case["didDocument"].as_str().unwrap())).unwrap())
                .unwrap();
        let mut p = Policy::new(
            case["trustedOperators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string()),
            timestamp(case["now"].as_str().unwrap()).unwrap(),
        );
        p.require_expiry = case["requireExpiry"].as_bool().unwrap();
        let accepted = json::parse(&bytes)
            .and_then(|c| catalog_profile::verify_catalog(&c, &doc, &p))
            .is_ok_and(|r| r.accepted);
        assert_eq!(
            accepted,
            case["expectedAccepted"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn root_did_restrictions_apply_to_signer_but_dns_subdomains_are_allowed() {
    let key = LocalKey::generate();
    for (signer, accepted) in [
        ("did:web:sub.catalog-test.example", true),
        ("did:web:CATALOG-test.example", false),
        ("did:web:catalog-test.example.", false),
        ("did:web:catalog-test.example:catalog", false),
        ("did:web:catalog-test.example%3A443", false),
        ("did:web:127.0.0.1", false),
        ("did:web:2130706433", false),
        ("did:web:café.example", false),
    ] {
        let kid = format!("{signer}#assertion-key");
        let mut c = signed(&key);
        c["host"]["identifier"] = signer.into();
        c["signature"]["signer"] = signer.into();
        let mut h = header();
        h["kid"] = kid.clone().into();
        let c = seal(c, &key, h);
        let mut doc = document(&key);
        doc["id"] = signer.into();
        doc["verificationMethod"][0]["id"] = kid.clone().into();
        doc["verificationMethod"][0]["controller"] = signer.into();
        doc["assertionMethod"] = v!([kid]);
        let p = Policy::new([signer.into()], timestamp(NOW).unwrap());
        assert_eq!(
            catalog_profile::verify_catalog(&c, &doc, &p).is_ok_and(|r| r.accepted),
            accepted,
            "{signer}"
        );
    }
}

#[test]
fn wrong_jws_serialization_and_missing_signature_members_fail() {
    let key = LocalKey::generate();
    let original = signed(&key);
    for name in ["signer", "profile", "issuedAt", "jws"] {
        let mut c = original.clone();
        c["signature"].as_object_mut().unwrap().remove(name);
        assert!(
            catalog_profile::verify_catalog(&c, &document(&key), &policy()).is_err(),
            "{name}"
        );
    }
    let jws = original["signature"]["jws"].as_str().unwrap();
    let parts: Vec<_> = jws.split('.').collect();
    for bad in [
        format!("{}.e30.{}", parts[0], parts[2]),
        format!("{}.{}", parts[0], parts[2]),
        format!("{jws}.extra"),
        format!("{}..{}", parts[0], crypto::encode(&[0; 63])),
    ] {
        let mut c = original.clone();
        c["signature"]["jws"] = bad.into();
        assert!(catalog_profile::verify_catalog(&c, &document(&key), &policy()).is_err());
    }
}

#[test]
fn required_root_and_host_structure_is_checked_without_inventing_name_constraints() {
    let key = LocalKey::generate();
    for (pointer, value) in [
        ("/specVersion", v!("1")),
        ("/specVersion", v!("1.")),
        ("/specVersion", v!("2.0")),
        ("/specVersion", v!(1)),
        ("/entries", v!({})),
        ("/host", Value::Null),
        ("/host/displayName", v!(23)),
        ("/host/displayName", Value::Null),
    ] {
        let mut c = signed(&key);
        *c.pointer_mut(pointer).unwrap() = value;
        let c = seal(c, &key, header());
        assert!(
            catalog_profile::verify_catalog(&c, &document(&key), &policy()).is_err(),
            "{pointer}"
        );
    }
    let mut c = signed(&key);
    c["host"].as_object_mut().unwrap().remove("displayName");
    assert!(
        catalog_profile::verify_catalog(&seal(c, &key, header()), &document(&key), &policy())
            .is_err()
    );
    let mut c = signed(&key);
    c["host"]["displayName"] = "".into();
    c["entries"] = v!([]);
    assert!(
        catalog_profile::verify_catalog(&seal(c, &key, header()), &document(&key), &policy())
            .unwrap()
            .accepted
    );
}

#[cfg(all(feature = "cli", unix))]
struct PrivateTestDirectory(PathBuf);

#[cfg(all(feature = "cli", unix))]
impl PrivateTestDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static SEQUENCE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = vectors_dir().join(format!(".ephemeral-cli-test-{}-{id}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}

#[cfg(all(feature = "cli", unix))]
impl Drop for PrivateTestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(all(feature = "cli", unix))]
#[test]
fn cli_signing_requires_private_regular_key_and_preserves_output_on_rejection() {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        process::Command,
    };
    let dir = PrivateTestDirectory::new();
    let key = LocalKey::generate();
    let key_path = dir.0.join("ephemeral-key.pem");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    f.write_all(key.to_pem().unwrap().as_bytes()).unwrap();
    drop(f);
    let catalog_path = dir.0.join("catalog.json");
    std::fs::write(&catalog_path, serde_json::to_vec(&catalog()).unwrap()).unwrap();
    let out = dir.0.join("signed.json");
    let run = |key_file: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_catalog-signatures"))
            .args(["sign-catalog", "--catalog"])
            .arg(&catalog_path)
            .arg("--key")
            .arg(key_file)
            .args([
                "--signer",
                SIGNER,
                "--kid",
                KID,
                "--issued-at",
                ISSUED,
                "--out",
            ])
            .arg(&out)
            .output()
            .unwrap()
    };
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!run(&key_path).status.success());
    assert!(!out.exists());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.0.join("key-symlink.pem");
    symlink(&key_path, &link).unwrap();
    assert!(!run(&link).status.success());
    assert!(!out.exists());
    let success = run(&key_path);
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let c = json::parse(&std::fs::read(&out).unwrap()).unwrap();
    assert!(
        catalog_profile::verify_catalog(&c, &document(&key), &policy())
            .unwrap()
            .accepted
    );
    // Invalid signing input must not replace an existing reviewable result.
    let before = std::fs::read(&out).unwrap();
    let mut wrong = catalog();
    wrong["host"]["identifier"] = "did:web:other.example".into();
    std::fs::write(&catalog_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(!run(&key_path).status.success());
    assert_eq!(std::fs::read(&out).unwrap(), before);
    // RAII removes the directory and its test-only private key, including on panic.
}

#[cfg(feature = "cli")]
#[test]
fn cli_offline_verification_requires_explicit_operator_and_did_pin() {
    use std::process::Command;
    let root = vectors_dir();
    let run = |operator: bool, did: bool, path: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_catalog-signatures"));
        c.args(["verify-catalog", "--catalog"])
            .arg(root.join(path))
            .args(["--now", NOW]);
        if operator {
            c.args(["--expect-operator", SIGNER]);
        }
        if did {
            c.arg("--did-document").arg(root.join("did.json"));
        }
        c.output().unwrap()
    };
    assert!(!run(false, true, "valid-catalog.json").status.success());
    assert!(!run(true, false, "valid-catalog.json").status.success());
    let success = run(true, true, "valid-catalog.json");
    assert!(success.status.success());
    let report: Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(report["accepted"], true);
    assert_eq!(report["didAcquisition"], "caller-pinned-did");
    assert!(
        !run(true, true, "cases/duplicate-json-member/catalog.json")
            .status
            .success()
    );
}
