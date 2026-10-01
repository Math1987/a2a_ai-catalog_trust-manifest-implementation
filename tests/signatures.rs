use aithos_catalog_signatures::{
    self as lib, SigningContext, baseline,
    crypto::{self, LocalKey},
    did, json,
    pr117::{self, Scope, Signature},
    verification::{Policy, Requirements, timestamp},
};
use serde_json::{Value, json as v};
use time::Duration;

const SIGNER: &str = "did:web:registry.example";
const KID: &str = "did:web:registry.example#key";
const ISSUED: &str = "2026-10-01T10:00:00Z";
const EXPIRES: &str = "2026-10-01T11:00:00Z";
const BYTES: &[u8] = b"{\"signatures\":[{\"signature\":\"opaque\"}],\"name\":\"Meeting\"}\n";
fn entry() -> Value {
    v!({"identifier":"urn:air:registry.example:agent:meeting","type":"application/a2a-agent-card+json","url":"https://cards.example/card.json"})
}
fn claims() -> Value {
    v!({"trustSchema":{"identifier":"https://registry.example/fixture","version":"1"},
    "extensions":{"https://registry.example/fixture":{"nested":{"signature":"kept","signatures":["also kept"]},"fixtureOnly":true}}})
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
fn policy() -> Policy {
    Policy::new([SIGNER.into()], timestamp("2026-10-01T10:30:00Z").unwrap())
}
fn requirements() -> Requirements {
    Requirements {
        publisher: true,
        contributor: Some(SIGNER.into()),
        claims: vec![],
    }
}
fn sig(entry: &Value) -> Signature {
    serde_json::from_value(entry["signatures"][0].clone()).unwrap()
}
fn b(key: &LocalKey) -> Value {
    pr117::endorse_entry(&entry(), &claims(), BYTES, &context(key)).unwrap()
}
fn verify(
    entry: &Value,
    signature: &Signature,
    key: &LocalKey,
) -> lib::Result<lib::verification::EntryReport> {
    pr117::verify_entry(
        entry,
        signature,
        BYTES,
        &key.did_document(SIGNER, KID).unwrap(),
        &policy(),
        &requirements(),
    )
}

#[test]
fn same_exact_artifact_in_both_formats() {
    let key = LocalKey::generate();
    let document = key.did_document(SIGNER, KID).unwrap();
    let a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    let b = b(&key);
    assert_eq!(a["trustManifest"]["subject"]["digest"], b["digest"]);
    assert!(
        baseline::verify_entry(&a, BYTES, &document, &policy())
            .unwrap()
            .accepted
    );
    assert!(verify(&b, &sig(&b), &key).unwrap().accepted);
    assert!(a.get("trustManifests").is_none());
    assert!(b.get("trustManifest").is_none());
}

#[test]
fn exact_bytes_include_card_signatures_and_whitespace() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    let b = b(&key);
    for changed in [
        BYTES[..BYTES.len() - 1].to_vec(),
        String::from_utf8(BYTES.to_vec())
            .unwrap()
            .replace("opaque", "changed")
            .into_bytes(),
    ] {
        let r = baseline::verify_entry(&a, &changed, &doc, &policy()).unwrap();
        assert!(r.signature_valid && !r.artifact_integrity && !r.accepted);
        assert!(
            !pr117::verify_entry(&b, &sig(&b), &changed, &doc, &policy(), &requirements())
                .unwrap()
                .accepted
        );
    }
}

#[test]
fn nested_signatures_are_never_stripped() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let mut a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    a["trustManifest"]["extensions"]["https://registry.example/fixture"]["nested"]["signature"] =
        "changed".into();
    assert!(baseline::verify_entry(&a, BYTES, &doc, &policy()).is_err());
    let mut b = b(&key);
    let s = sig(&b);
    b["trustManifests"][SIGNER]["extensions"]["https://registry.example/fixture"]["nested"]["signatures"] =
        v!([]);
    assert!(verify(&b, &s, &key).is_err());
}

#[test]
fn baseline_relabeling_limitation_is_reported_not_hidden() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let mut a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    a["identifier"] = "urn:air:registry.example:agent:renamed".into();
    a["version"] = "9000".into();
    let report = baseline::verify_entry(&a, BYTES, &doc, &policy()).unwrap();
    assert!(report.accepted);
    assert_eq!(report.release_coverage, None);
    assert!(!report.limitations.is_empty());
    a["identifier"] = "urn:air:someone.example:agent:renamed".into();
    assert!(
        !baseline::verify_entry(&a, BYTES, &doc, &policy())
            .unwrap()
            .accepted
    );
}

#[test]
fn baseline_subject_type_and_location_are_checked() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    for field in ["type", "url"] {
        let mut altered = a.clone();
        altered[field] = "changed".into();
        let report = baseline::verify_entry(&altered, BYTES, &doc, &policy()).unwrap();
        assert!(!report.accepted && report.signature_valid);
    }
}

#[test]
fn baseline_refuses_signing_someone_elses_namespace() {
    let key = LocalKey::generate();
    let mut e = entry();
    e["identifier"] = "urn:air:publisher.example:agent:meeting".into();
    assert!(baseline::sign_entry(&e, &claims(), BYTES, &context(&key)).is_err());
}

#[test]
fn inline_artifacts_use_jcs_in_both_formats() {
    let key = LocalKey::generate();
    let mut e = entry();
    e.as_object_mut().unwrap().remove("url");
    e["data"] = v!({"z":1,"a":2});
    let a = baseline::sign_entry(&e, &claims(), b"ignored", &context(&key)).unwrap();
    let b = pr117::endorse_entry(&e, &claims(), b"ignored", &context(&key)).unwrap();
    assert_eq!(
        a["trustManifest"]["subject"]["digest"],
        json::digest(b"{\"a\":2,\"z\":1}")
    );
    assert_eq!(a["trustManifest"]["subject"]["digest"], b["digest"]);
    assert!(a["trustManifest"]["subject"].get("url").is_none());
    assert!(verify(&b, &sig(&b), &key).unwrap().accepted);
}

#[test]
fn strict_wire_json_rejects_duplicates_at_every_depth() {
    for raw in [
        r#"{"x":1,"x":2}"#,
        r#"{"nested":{"alg":"ES256","alg":"none"}}"#,
        r#"[1,NaN]"#,
        r#"{"x":9007199254740993}"#,
        r#"{"x":"\ud800"}"#,
    ] {
        assert!(json::parse(raw.as_bytes()).is_err(), "{raw}");
    }
    assert!(json::parse(b"null true").is_err());
    assert!(json::parse(&vec![b' '; json::MAX_JSON_BYTES + 1]).is_err());
}

#[test]
fn canonical_known_answer_preserves_arrays_and_utf16_property_order() {
    let value = v!({"\u{e000}":1,"😀":2,"a":[3,2,1],"num":1e-7});
    assert_eq!(
        String::from_utf8(json::canonical(&value).unwrap()).unwrap(),
        "{\"a\":[3,2,1],\"num\":1e-7,\"😀\":2,\"\u{e000}\":1}"
    );
}

#[test]
fn selected_paths_sort_utf16_with_prefixes_and_preserve_duplicates() {
    let key = LocalKey::generate();
    let object = v!({"\u{e000}":1,"😀":2,"":{"x":null},"a":[2,1]});
    let paths = vec![
        vec!["\u{e000}".into()],
        vec!["😀".into()],
        vec!["".into(), "x".into()],
        vec!["".into()],
        vec!["".into()],
    ];
    let mut s = pr117::sign_selected(&object, paths, Scope::Entry, &context(&key)).unwrap();
    let bytes = pr117::payload(&object, &s, Scope::Entry).unwrap();
    let parsed = json::parse(&bytes).unwrap();
    assert_eq!(parsed["fields"][0][0], v!([""]));
    assert_eq!(parsed["fields"][1][0], v!([""]));
    assert_eq!(parsed["fields"][2][0], v!(["", "x"]));
    assert_eq!(parsed["fields"][3][0], v!(["😀"]));
    assert!(parsed["fields"][2][1].is_null());
    s.paths.reverse();
    assert_eq!(bytes, pr117::payload(&object, &s, Scope::Entry).unwrap());
    assert!(
        pr117::verify_signature(
            &object,
            &s,
            Scope::Entry,
            &key.did_document(SIGNER, KID).unwrap(),
            &policy()
        )
        .unwrap()
    );
}

#[test]
fn paths_distinguish_missing_null_objects_and_arrays() {
    let object = v!({"null":null,"array":[1],"object":{"0":"member"},"signatures":[]});
    for path in [
        vec![],
        vec!["missing"],
        vec!["array", "0"],
        vec!["null", "x"],
        vec!["signatures"],
    ] {
        assert!(
            pr117::resolve(
                &object,
                &path.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    assert!(pr117::resolve(&object, &["null".into()]).unwrap().is_null());
    assert_eq!(
        pr117::resolve(&object, &["object".into(), "0".into()]).unwrap(),
        "member"
    );
}

#[test]
fn profile_selection_is_explicit_signed_and_locally_permitted() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut s = sig(&b);
    s.profile = "DID-WEB-V1".into();
    assert!(verify(&b, &s, &key).is_err());
    let mut p = policy();
    p.allowed_profiles.clear();
    assert!(
        pr117::verify_entry(
            &b,
            &sig(&b),
            BYTES,
            &key.did_document(SIGNER, KID).unwrap(),
            &p,
            &requirements()
        )
        .is_err()
    );
    let mut raw = serde_json::to_value(sig(&b)).unwrap();
    raw.as_object_mut().unwrap().remove("profile");
    assert!(serde_json::from_value::<Signature>(raw).is_err());
}

#[test]
fn signature_metadata_has_no_extra_members_or_null_expiry() {
    let key = LocalKey::generate();
    let b = b(&key);
    for (field, value) in [("expiresAt", Value::Null), ("extra", v!(true))] {
        let mut raw = b["signatures"][0].clone();
        raw[field] = value;
        assert!(serde_json::from_value::<Signature>(raw).is_err());
    }
}

#[test]
fn adding_unsigned_version_fails_coverage_even_when_crypto_passes() {
    let key = LocalKey::generate();
    let mut b = b(&key);
    let s = sig(&b);
    b["version"] = "2.0".into();
    let report = verify(&b, &s, &key).unwrap();
    assert!(report.signature_valid);
    assert_eq!(report.release_coverage, Some(false));
    assert!(!report.accepted);
}

#[test]
fn removing_signed_version_fails_path_resolution() {
    let key = LocalKey::generate();
    let mut e = entry();
    e["version"] = "1".into();
    let mut b = pr117::endorse_entry(&e, &claims(), BYTES, &context(&key)).unwrap();
    let s = sig(&b);
    b.as_object_mut().unwrap().remove("version");
    assert!(verify(&b, &s, &key).is_err());
}

#[test]
fn partial_signatures_cannot_be_combined_for_release_or_claims() {
    let key = LocalKey::generate();
    let b = b(&key);
    for paths in [
        vec![vec!["identifier".into()], vec!["type".into()]],
        vec![
            vec!["digest".into()],
            vec!["trustManifests".into(), SIGNER.into()],
        ],
        pr117::release_paths(&b),
    ] {
        let s = pr117::sign_selected(&b, paths, Scope::Entry, &context(&key)).unwrap();
        let report = verify(&b, &s, &key).unwrap();
        assert!(report.signature_valid);
        assert!(!report.accepted);
    }
}

#[test]
fn unknown_signer_is_cryptographically_valid_but_untrusted() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut p = policy();
    p.trusted_signers.clear();
    let report = pr117::verify_entry(
        &b,
        &sig(&b),
        BYTES,
        &key.did_document(SIGNER, KID).unwrap(),
        &p,
        &requirements(),
    )
    .unwrap();
    assert!(report.signature_valid && !report.trusted_signer && !report.accepted);
}

#[test]
fn contributor_attribution_is_not_another_signers_endorsement() {
    let key = LocalKey::generate();
    let mut b = b(&key);
    b["trustManifests"]["did:web:assessor.example"] = claims();
    let mut paths = pr117::release_paths(&b);
    paths.push(vec![
        "trustManifests".into(),
        "did:web:assessor.example".into(),
    ]);
    let s = pr117::sign_selected(&b, paths, Scope::Entry, &context(&key)).unwrap();
    let req = Requirements {
        publisher: false,
        contributor: Some("did:web:assessor.example".into()),
        claims: vec![],
    };
    let report = pr117::verify_entry(
        &b,
        &s,
        BYTES,
        &key.did_document(SIGNER, KID).unwrap(),
        &policy(),
        &req,
    )
    .unwrap();
    assert!(report.signature_valid && report.claim_coverage);
    assert_eq!(report.contributor_attributed, Some(false));
    assert!(!report.accepted);
}

#[test]
fn registry_contribution_on_personal_namespace_is_not_publisher_authorization() {
    let key = LocalKey::generate();
    let mut e = entry();
    e["identifier"] = "urn:air:publisher.example:agent:meeting".into();
    let b = pr117::endorse_entry(&e, &claims(), BYTES, &context(&key)).unwrap();
    let report = verify(&b, &sig(&b), &key).unwrap();
    assert!(report.signature_valid);
    assert!(!report.publisher_authorized && !report.accepted);
    let req = Requirements {
        publisher: false,
        ..requirements()
    };
    assert!(
        pr117::verify_entry(
            &b,
            &sig(&b),
            BYTES,
            &key.did_document(SIGNER, KID).unwrap(),
            &policy(),
            &req
        )
        .unwrap()
        .accepted
    );
}

#[test]
fn expiry_boundary_and_future_are_separate_from_crypto() {
    let key = LocalKey::generate();
    let b = b(&key);
    let doc = key.did_document(SIGNER, KID).unwrap();
    for (now, expected) in [
        (ISSUED, true),
        (EXPIRES, false),
        ("2026-10-01T09:59:59Z", false),
    ] {
        let p = Policy::new([SIGNER.into()], timestamp(now).unwrap());
        let r = pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &p, &requirements()).unwrap();
        assert!(r.signature_valid);
        assert_eq!(r.accepted, expected);
    }
    let mut p = Policy::new([SIGNER.into()], timestamp(EXPIRES).unwrap());
    p.clock_skew = Duration::seconds(120);
    assert!(
        pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &p, &requirements())
            .unwrap()
            .accepted
    );
    p.now += Duration::seconds(120);
    assert!(
        !pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &p, &requirements())
            .unwrap()
            .accepted
    );
}

#[test]
fn absent_expiry_obeys_explicit_local_policy() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut c = context(&key);
    c.expires_at = None;
    let s = pr117::sign_selected(&b, sig(&b).paths, Scope::Entry, &c).unwrap();
    assert!(!verify(&b, &s, &key).unwrap().accepted);
    let mut p = policy();
    p.require_expiry = false;
    assert!(
        pr117::verify_entry(
            &b,
            &s,
            BYTES,
            &key.did_document(SIGNER, KID).unwrap(),
            &p,
            &requirements()
        )
        .unwrap()
        .accepted
    );
    assert!(
        json::parse(&pr117::payload(&b, &s, Scope::Entry).unwrap())
            .unwrap()
            .get("expiresAt")
            .is_none()
    );
}

#[test]
fn did_core_fragment_references_and_embedded_methods() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut doc = key.did_document(SIGNER, KID).unwrap();
    doc["verificationMethod"][0]["id"] = "#key".into();
    doc["assertionMethod"] = v!(["#key"]);
    assert!(
        pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &policy(), &requirements())
            .unwrap()
            .accepted
    );
    let method = doc["verificationMethod"][0].clone();
    doc.as_object_mut().unwrap().remove("verificationMethod");
    doc["assertionMethod"] = v!([method]);
    assert!(
        pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &policy(), &requirements())
            .unwrap()
            .accepted
    );
}

#[test]
fn did_key_authorization_and_key_metadata_are_enforced() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let mut variants = vec![];
    let mut bad = doc.clone();
    bad["assertionMethod"] = v!([]);
    variants.push(bad);
    let mut bad = doc.clone();
    bad["assertionMethod"] = v!([KID, KID]);
    variants.push(bad);
    let mut bad = doc.clone();
    bad["id"] = "did:web:other.example".into();
    variants.push(bad);
    let mut bad = doc.clone();
    bad["verificationMethod"][0]["controller"] = "did:web:other.example".into();
    variants.push(bad);
    for (field, value) in [
        ("d", v!("secret")),
        ("alg", v!("ES384")),
        ("use", v!("enc")),
        ("key_ops", v!(["sign"])),
        ("x", v!("AA")),
    ] {
        let mut bad = doc.clone();
        bad["verificationMethod"][0]["publicKeyJwk"][field] = value;
        variants.push(bad);
    }
    for bad in variants {
        assert!(did::assertion_key(&bad, SIGNER, KID).is_err());
    }
    assert!(did::assertion_key(&doc, SIGNER, "did:web:other.example#key").is_err());
    assert!(did::assertion_key(&doc, SIGNER, "did:web:registry.example:path#key").is_err());
}

#[test]
fn current_did_removal_prevents_old_signature_verification() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut doc = key.did_document(SIGNER, KID).unwrap();
    doc["assertionMethod"] = v!(["#new-key"]);
    assert!(pr117::verify_entry(&b, &sig(&b), BYTES, &doc, &policy(), &requirements()).is_err());
}

#[test]
fn root_did_profile_rejects_noncanonical_domains() {
    for signer in [
        "did:web:EXAMPLE.com",
        "did:web:example.com.",
        "did:web:example.com:agent",
        "did:web:example.com%3A443",
        "did:web:127.0.0.1",
        "did:web:2130706433",
        "did:web:éxample.com",
        "did:web:-bad.example",
    ] {
        assert!(did::domain(signer).is_err(), "{signer}");
    }
}

#[test]
fn forbidden_jws_headers_and_bad_signatures_fail() {
    let key = LocalKey::generate();
    let b = b(&key);
    for (name, value) in [
        ("alg", v!("none")),
        ("alg", v!("HS256")),
        ("jku", v!("https://evil.example")),
        ("jwk", v!({})),
        ("x5u", v!("https://evil.example")),
        ("x5c", v!([])),
        ("crit", v!(["custom"])),
        ("b64", v!(true)),
    ] {
        let mut s = sig(&b);
        let mut parts: Vec<String> = s.jws.split('.').map(String::from).collect();
        let mut header = json::parse(&crypto::decode(&parts[0]).unwrap()).unwrap();
        header[name] = value;
        parts[0] = crypto::encode(&json::canonical(&header).unwrap());
        // Sign the altered header correctly: refusal must be the profile/header
        // policy, not merely a now-invalid cryptographic signature.
        let payload = pr117::payload(&b, &s, Scope::Entry).unwrap();
        let input = format!("{}.{}", parts[0], crypto::encode(&payload));
        parts[2] =
            crypto::encode(&crypto::Es256Signer::sign_es256(&key, input.as_bytes()).unwrap());
        s.jws = parts.join(".");
        assert!(verify(&b, &s, &key).is_err());
    }
    let mut s = sig(&b);
    s.jws.push('A');
    assert!(verify(&b, &s, &key).is_err());
    let other = LocalKey::generate();
    assert!(verify(&b, &sig(&b), &other).is_err());
}

#[test]
fn protected_header_duplicate_json_is_rejected() {
    let key = LocalKey::generate();
    let b = b(&key);
    let mut s = sig(&b);
    let header =
        crypto::encode(br#"{"alg":"ES256","alg":"ES256","kid":"did:web:registry.example#key"}"#);
    s.jws = format!("{header}..{}", s.jws.split('.').nth(2).unwrap());
    assert!(
        verify(&b, &s, &key)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
}

#[test]
fn kid_is_a_valid_absolute_did_url_with_a_nonempty_fragment() {
    for suffix in ["", "bad%", "bad%GG", "bad<", "bad#again", "white space"] {
        assert!(did::validate_kid(SIGNER, &format!("{SIGNER}#{suffix}")).is_err());
    }
    assert!(did::validate_kid(SIGNER, &format!("{SIGNER}#key%20id")).is_ok());
}

#[test]
fn signature_cannot_move_between_entry_and_catalog_contexts() {
    let key = LocalKey::generate();
    let object = v!({"specVersion":"1.0","entries":[]});
    let s = pr117::sign_selected(
        &object,
        vec![vec!["specVersion".into()]],
        Scope::Entry,
        &context(&key),
    )
    .unwrap();
    assert!(
        pr117::verify_catalog(
            &object,
            &s,
            &key.did_document(SIGNER, KID).unwrap(),
            &policy()
        )
        .is_err()
    );
}

#[test]
fn catalog_snapshot_requires_every_current_root_member() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let mut catalog = v!({"specVersion":"1.0","entries":[b(&key)]});
    let s = pr117::sign_selected(
        &catalog,
        pr117::snapshot_paths(&catalog).unwrap(),
        Scope::Catalog,
        &context(&key),
    )
    .unwrap();
    assert!(
        pr117::verify_catalog(&catalog, &s, &doc, &policy())
            .unwrap()
            .accepted
    );
    catalog["extensions"] = v!({});
    let r = pr117::verify_catalog(&catalog, &s, &doc, &policy()).unwrap();
    assert!(r.signature_valid && !r.snapshot_coverage && !r.accepted);
    catalog["entries"][0]["signatures"] = v!([]);
    assert!(pr117::verify_catalog(&catalog, &s, &doc, &policy()).is_err());
}

#[test]
fn baseline_catalog_signature_covers_membership() {
    let key = LocalKey::generate();
    let doc = key.did_document(SIGNER, KID).unwrap();
    let mut catalog = baseline::sign_catalog(
        &v!({"specVersion":"1.0","entries":[entry()]}),
        &context(&key),
    )
    .unwrap();
    assert!(
        baseline::verify_catalog(&catalog, SIGNER, &doc, &policy())
            .unwrap()
            .accepted
    );
    catalog["entries"] = v!([]);
    assert!(baseline::verify_catalog(&catalog, SIGNER, &doc, &policy()).is_err());
}

#[test]
fn independent_contributor_renewal_preserves_publisher_signature() {
    let registry = LocalKey::generate();
    let owner = LocalKey::generate();
    let publisher = "did:web:publisher.example";
    let owner_context = SigningContext {
        signer: publisher,
        kid: "did:web:publisher.example#key",
        key: &owner,
        ..context(&registry)
    };
    let mut e = entry();
    e["identifier"] = "urn:air:publisher.example:agent:meeting".into();
    e["digest"] = json::digest(BYTES).into();
    let owner_sig =
        pr117::sign_selected(&e, pr117::release_paths(&e), Scope::Entry, &owner_context).unwrap();
    e["signatures"] = v!([owner_sig]);
    let before = pr117::endorse_entry(&e, &claims(), BYTES, &context(&registry)).unwrap();
    let mut new_claims = claims();
    new_claims["extensions"]["https://registry.example/fixture"]["renewed"] = true.into();
    let after = pr117::endorse_entry(
        &before,
        &new_claims,
        BYTES,
        &SigningContext {
            issued_at: "2026-10-01T10:01:00Z",
            ..context(&registry)
        },
    )
    .unwrap();
    assert_eq!(before["signatures"][0], after["signatures"][0]);
    assert_eq!(after["signatures"].as_array().unwrap().len(), 2);
    let doc = owner.did_document(publisher, owner_context.kid).unwrap();
    let p = Policy::new([publisher.into()], policy().now);
    assert!(
        pr117::verify_entry(
            &after,
            &owner_sig,
            BYTES,
            &doc,
            &p,
            &Requirements {
                publisher: true,
                ..Default::default()
            }
        )
        .unwrap()
        .accepted
    );
}

#[test]
fn kms_der_conversion_and_local_pkcs8_roundtrip() {
    let key = LocalKey::generate();
    let pem = key.to_pem().unwrap();
    let restored = LocalKey::from_pem(&pem).unwrap();
    assert_eq!(key.public_jwk(), restored.public_jwk());
    let jws = crypto::sign(b"test", SIGNER, KID, &key).unwrap();
    let raw = crypto::decode(jws.split('.').nth(2).unwrap()).unwrap();
    let signature = p256::ecdsa::Signature::from_slice(&raw).unwrap();
    assert_eq!(
        crypto::der_to_jose(signature.to_der().as_bytes())
            .unwrap()
            .as_slice(),
        raw
    );
    assert!(crypto::der_to_jose(&[0; 64]).is_err());
}

#[test]
fn dialect_mixing_is_rejected() {
    let key = LocalKey::generate();
    let b = b(&key);
    assert!(baseline::sign_entry(&b, &claims(), BYTES, &context(&key)).is_err());
    let a = baseline::sign_entry(&entry(), &claims(), BYTES, &context(&key)).unwrap();
    assert!(pr117::endorse_entry(&a, &claims(), BYTES, &context(&key)).is_err());
}

#[test]
fn signed_location_is_optional_for_pr_mirroring() {
    let key = LocalKey::generate();
    let mut b = b(&key);
    let mut paths = sig(&b).paths;
    paths.retain(|p| p != &vec!["url".to_string()]);
    let s = pr117::sign_selected(&b, paths, Scope::Entry, &context(&key)).unwrap();
    b["url"] = "https://mirror.example/card.json".into();
    assert!(verify(&b, &s, &key).unwrap().accepted);
}
