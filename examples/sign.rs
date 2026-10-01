use aithos_catalog_signatures::{
    SigningContext, baseline,
    crypto::LocalKey,
    pr117,
    verification::{Policy, Requirements},
};
use serde_json::json;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = LocalKey::generate();
    let now = OffsetDateTime::now_utc();
    let issued = now.format(&Rfc3339)?;
    let expires = (now + Duration::hours(1)).format(&Rfc3339)?;
    let context = SigningContext {
        signer: "did:web:registry.example",
        kid: "did:web:registry.example#demo",
        key: &key,
        issued_at: &issued,
        expires_at: Some(&expires),
    };
    let entry = json!({
        "identifier":"urn:air:registry.example:agent:meeting",
        "type":"application/a2a-agent-card+json",
        "url":"https://cards.example/meeting.json"
    });
    let claims = json!({"extensions":{
        "https://registry.example/local-fixture":{"fixtureOnly":true,"observation":"not-performed"}
    }});
    let exact_bytes = b"{\"name\":\"Synthetic fixture\"}\n";
    let a = baseline::sign_entry(&entry, &claims, exact_bytes, &context)?;
    let b = pr117::endorse_entry(&entry, &claims, exact_bytes, &context)?;
    let document = key.did_document(context.signer, context.kid)?;
    let policy = Policy::new([context.signer.into()], now);
    let signature = serde_json::from_value(b["signatures"][0].clone())?;
    let report = pr117::verify_entry(
        &b,
        &signature,
        exact_bytes,
        &document,
        &policy,
        &Requirements {
            publisher: true,
            contributor: Some(context.signer.into()),
            claims: vec![],
        },
    )?;
    assert!(report.accepted);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"baseline":a,"pr117":b,"verification":report}))?
    );
    Ok(())
}
