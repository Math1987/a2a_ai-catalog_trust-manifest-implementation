use aithos_catalog_signatures::{
    baseline, json, pr117,
    verification::{Policy, Requirements, timestamp},
};

#[test]
fn stored_public_vectors_verify_without_the_original_private_keys() {
    let artifact = include_bytes!("../vectors/demo/artifact.bin");
    let a = json::parse(include_bytes!("../vectors/demo/baseline-entry.json")).unwrap();
    let b = json::parse(include_bytes!("../vectors/demo/pr117-entry.json")).unwrap();
    let doc = json::parse(include_bytes!("../vectors/demo/registry-did.json")).unwrap();
    let report = json::parse(include_bytes!("../vectors/demo/report.json")).unwrap();
    let signer = "did:web:registry.example";
    let policy = Policy::new(
        [signer.into()],
        timestamp(report["verifyAt"].as_str().unwrap()).unwrap(),
    );
    assert!(
        baseline::verify_entry(&a, artifact, &doc, &policy)
            .unwrap()
            .accepted
    );
    let signature = serde_json::from_value(b["signatures"][0].clone()).unwrap();
    assert!(
        pr117::verify_entry(
            &b,
            &signature,
            artifact,
            &doc,
            &policy,
            &Requirements {
                publisher: true,
                contributor: Some(signer.into()),
                claims: vec![]
            }
        )
        .unwrap()
        .accepted
    );
    assert_eq!(a["trustManifest"]["subject"]["digest"], b["digest"]);
}
