use aithos_catalog_signatures::{
    self as lib, SigningContext, baseline,
    crypto::LocalKey,
    fetch::Fetcher,
    json,
    pr117::{self, Scope, Signature},
    verification::{Policy, Requirements},
};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json as value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Parser)]
#[command(
    about = "Local AI Catalog signing lab. Evidence supplied by callers is not independently certified."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Baseline,
    Pr117,
}
#[derive(Subcommand)]
enum Command {
    /// Ephemeral example-domain keys, A/B0/B1 and independent renewal fixtures.
    Demo {
        #[arg(long, default_value = ".local/demo")]
        out: PathBuf,
    },
    /// Save exactly one catalog entry and the exact referenced bytes. Does not sign.
    Fetch {
        #[arg(long)]
        catalog: String,
        #[arg(long)]
        identifier: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long, required = true)]
        allow_origin: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a local P-256 PKCS#8 key (0600, never overwritten) and public DID fixture.
    Keygen {
        #[arg(long)]
        signer: String,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        did_document: PathBuf,
    },
    /// Sign caller-supplied claims; no domain certification or registry issuance occurs.
    Sign {
        #[arg(long, value_enum)]
        format: Format,
        #[arg(long)]
        entry: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        claims: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        signer: String,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long, default_value_t = 3600)]
        lifetime_seconds: i64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify with a locally pinned DID document and explicit trusted signer.
    Verify {
        #[arg(long, value_enum)]
        format: Format,
        #[arg(long)]
        entry: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        did_document: PathBuf,
        #[arg(long, required = true)]
        trust: Vec<String>,
        #[arg(long, default_value_t = 0)]
        signature_index: usize,
        #[arg(long)]
        now: Option<String>,
        #[arg(long)]
        contributor: Option<String>,
        #[arg(long)]
        require_publisher: bool,
    },
}

fn read(path: &Path) -> lib::Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| lib::Error(e.to_string()))?;
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(json::MAX_JSON_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| lib::Error(e.to_string()))?;
    if bytes.len() > json::MAX_JSON_BYTES {
        return Err(lib::Error("input file exceeds 1 MiB".into()));
    }
    Ok(bytes)
}
fn read_json(path: &Path) -> lib::Result<Value> {
    json::parse(&read(path)?)
}
fn write_new(path: &Path, bytes: &[u8], secret: bool) -> lib::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| lib::Error(e.to_string()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    if secret {
        return Err(lib::Error(
            "private-key creation requires Unix permission support".into(),
        ));
    }
    let mut file = options
        .open(path)
        .map_err(|e| lib::Error(format!("cannot create {}: {e}", path.display())))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| lib::Error(e.to_string()))
}
fn write_json(path: &Path, value: &Value) -> lib::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| lib::Error(e.to_string()))?;
    bytes.push(b'\n');
    write_new(path, &bytes, false)
}
fn stamp(t: OffsetDateTime) -> lib::Result<String> {
    t.format(&Rfc3339).map_err(|e| lib::Error(e.to_string()))
}
fn output(value: &impl serde::Serialize) -> lib::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| lib::Error(e.to_string()))?
    );
    Ok(())
}

fn run() -> lib::Result<bool> {
    match Args::parse().command {
        Command::Demo { out } => demo(&out),
        Command::Fetch {
            catalog,
            identifier,
            version,
            allow_origin,
            out,
        } => {
            let fetched =
                Fetcher::new(allow_origin)?.entry(&catalog, &identifier, version.as_deref())?;
            write_json(&out.join("entry.json"), &fetched.entry)?;
            write_new(&out.join("artifact.bin"), &fetched.artifact, false)?;
            write_json(
                &out.join("fetch.json"),
                &value!({"catalog":catalog,"identifier":identifier,
                "fetchedAt":stamp(OffsetDateTime::now_utc())?,"artifactDigest":json::digest(&fetched.artifact),
                "claimVerification":"not-performed"}),
            )?;
            output(&value!({"fetched":true,"directory":out}))?;
            Ok(true)
        }
        Command::Keygen {
            signer,
            kid,
            key,
            did_document,
        } => {
            let local = LocalKey::generate();
            let document = local.did_document(&signer, &kid)?;
            if did_document.exists() {
                return Err(lib::Error("DID output already exists".into()));
            }
            write_new(&key, local.to_pem()?.as_bytes(), true)?;
            write_json(&did_document, &document)?;
            output(
                &value!({"publicDidDocument":did_document,"privateKeyFile":key,"note":"Local key only; DID document has not been published."}),
            )?;
            Ok(true)
        }
        Command::Sign {
            format,
            entry,
            artifact,
            claims,
            key,
            signer,
            kid,
            issued_at,
            lifetime_seconds,
            out,
        } => {
            if !(1..=86400).contains(&lifetime_seconds) {
                return Err(lib::Error(
                    "local CLI lifetime must be 1–86400 seconds".into(),
                ));
            }
            let bytes = zeroize::Zeroizing::new(read(&key)?);
            let key = LocalKey::from_pem(
                std::str::from_utf8(&bytes)
                    .map_err(|_| lib::Error("key is not UTF-8 PEM".into()))?,
            )?;
            let issued = issued_at
                .map(|s| lib::verification::timestamp(&s))
                .transpose()?
                .unwrap_or_else(OffsetDateTime::now_utc);
            let issued = stamp(issued)?;
            let expires = stamp(
                lib::verification::timestamp(&issued)? + Duration::seconds(lifetime_seconds),
            )?;
            let context = SigningContext {
                signer: &signer,
                kid: &kid,
                key: &key,
                issued_at: &issued,
                expires_at: Some(&expires),
            };
            let (entry, artifact, claims) =
                (read_json(&entry)?, read(&artifact)?, read_json(&claims)?);
            let signed = match format {
                Format::Baseline => baseline::sign_entry(&entry, &claims, &artifact, &context)?,
                Format::Pr117 => pr117::endorse_entry(&entry, &claims, &artifact, &context)?,
            };
            write_json(&out, &signed)?;
            output(&value!({"signedEntry":out,"evidenceValidation":"caller-responsibility"}))?;
            Ok(true)
        }
        Command::Verify {
            format,
            entry,
            artifact,
            did_document,
            trust,
            signature_index,
            now,
            contributor,
            require_publisher,
        } => {
            let (entry, artifact, document) = (
                read_json(&entry)?,
                read(&artifact)?,
                read_json(&did_document)?,
            );
            let now = now
                .map(|s| lib::verification::timestamp(&s))
                .transpose()?
                .unwrap_or_else(OffsetDateTime::now_utc);
            let policy = Policy::new(trust, now);
            let report = match format {
                Format::Baseline => {
                    if contributor.is_some() {
                        return Err(lib::Error("contributor selection requires PR117".into()));
                    }
                    baseline::verify_entry(&entry, &artifact, &document, &policy)?
                }
                Format::Pr117 => {
                    let raw = entry
                        .get("signatures")
                        .and_then(Value::as_array)
                        .and_then(|a| a.get(signature_index))
                        .ok_or_else(|| lib::Error("signature index absent".into()))?;
                    let sig: Signature = serde_json::from_value(raw.clone())
                        .map_err(|e| lib::Error(e.to_string()))?;
                    pr117::verify_entry(
                        &entry,
                        &sig,
                        &artifact,
                        &document,
                        &policy,
                        &Requirements {
                            publisher: require_publisher,
                            contributor,
                            claims: Vec::new(),
                        },
                    )?
                }
            };
            output(&report)?;
            Ok(report.accepted)
        }
    }
}

fn demo(out: &Path) -> lib::Result<bool> {
    if out.exists() {
        return Err(lib::Error(
            "demo output already exists; choose a new --out directory".into(),
        ));
    }
    let key = LocalKey::generate();
    let owner = LocalKey::generate();
    let signer = "did:web:registry.example";
    let kid = "did:web:registry.example#local";
    let publisher = "did:web:publisher.example";
    let owner_kid = "did:web:publisher.example#local";
    let now = OffsetDateTime::now_utc();
    let issued = stamp(now)?;
    let expires = stamp(now + Duration::hours(1))?;
    let context = SigningContext {
        signer,
        kid,
        key: &key,
        issued_at: &issued,
        expires_at: Some(&expires),
    };
    let owner_context = SigningContext {
        signer: publisher,
        kid: owner_kid,
        key: &owner,
        issued_at: &issued,
        expires_at: Some(&expires),
    };
    let document = key.did_document(signer, kid)?;
    let owner_document = owner.did_document(publisher, owner_kid)?;
    let artifact=b"{\"name\":\"Synthetic signing fixture\",\"signatures\":[{\"signature\":\"opaque-fixture-value\"}]}\n";
    let entry = value!({"identifier":"urn:air:registry.example:agent:meeting","version":"1.0.0",
        "type":"application/a2a-agent-card+json","url":"https://cards.example/meeting.json"});
    let claims = value!({"trustSchema":{"identifier":"https://registry.example/profiles/local-fixture","version":"1.0"},
        "extensions":{"https://registry.example/schemas/local-fixture":{"fixtureOnly":true,"observation":"not-performed","revision":1}}});
    let a = baseline::sign_entry(&entry, &claims, artifact, &context)?;
    let b = pr117::endorse_entry(&entry, &claims, artifact, &context)?;
    let mut b1 = entry.clone();
    b1["identifier"] = "urn:air:publisher.example:agent:meeting".into();
    b1["digest"] = json::digest(artifact).into();
    let owner_signature =
        pr117::sign_selected(&b1, pr117::release_paths(&b1), Scope::Entry, &owner_context)?;
    b1["signatures"] = value!([owner_signature]);
    let b1 = pr117::endorse_entry(&b1, &claims, artifact, &context)?;
    let catalog = value!({"specVersion":"1.0","entries":[b1]});
    let snapshot = pr117::sign_selected(
        &catalog,
        pr117::snapshot_paths(&catalog)?,
        Scope::Catalog,
        &context,
    )?;
    let mut signed_catalog = catalog.clone();
    signed_catalog["signatures"] = value!([snapshot]);
    let mut renewed_claims = claims.clone();
    renewed_claims["extensions"]["https://registry.example/schemas/local-fixture"]["revision"] =
        2.into();
    let renewed_at = stamp(now + Duration::minutes(1))?;
    let renewal = SigningContext {
        issued_at: &renewed_at,
        ..context
    };
    let renewed = pr117::endorse_entry(&b1, &renewed_claims, artifact, &renewal)?;
    let mut renewed_catalog = signed_catalog.clone();
    renewed_catalog["entries"] = value!([renewed]);
    let check_at = now + Duration::minutes(1);
    let policy = Policy::new([signer.into(), publisher.into()], check_at);
    let required = Requirements {
        publisher: true,
        contributor: None,
        claims: Vec::new(),
    };
    let report_a = baseline::verify_entry(&a, artifact, &document, &policy)?;
    let sig_b: Signature = serde_json::from_value(b["signatures"][0].clone())
        .map_err(|e| lib::Error(e.to_string()))?;
    let report_b = pr117::verify_entry(&b, &sig_b, artifact, &document, &policy, &required)?;
    let owner_after = pr117::verify_entry(
        &renewed,
        &owner_signature,
        artifact,
        &owner_document,
        &policy,
        &required,
    )?;
    let stale_snapshot_fails =
        pr117::verify_catalog(&renewed_catalog, &snapshot, &document, &policy).is_err();
    let refreshed_snapshot = pr117::sign_selected(
        &renewed_catalog,
        pr117::snapshot_paths(&renewed_catalog)?,
        Scope::Catalog,
        &renewal,
    )?;
    renewed_catalog["signatures"] = value!([refreshed_snapshot]);
    let root = pr117::verify_catalog(&renewed_catalog, &refreshed_snapshot, &document, &policy)?;
    let report = value!({"fixtureOnly":true,"baselineRevision":lib::BASELINE_REVISION,"pr117Revision":lib::PR117_REVISION,
        "verifyAt":stamp(check_at)?,"baseline":report_a,"pr117":report_b,
        "publisherSurvivesContributorRenewal":owner_after.accepted,"oldCatalogSnapshotRejected":stale_snapshot_fails,
        "refreshedCatalogSnapshotAccepted":root.accepted,"privateKeys":"ephemeral; not saved"});
    for (name, value) in [
        ("baseline-entry.json", a.clone()),
        ("pr117-entry.json", b.clone()),
        ("b1-entry.json", b1),
        ("b1-renewed-entry.json", renewed),
        ("b1-catalog.json", signed_catalog),
        ("b1-renewed-catalog.json", renewed_catalog),
        ("registry-did.json", document),
        ("publisher-did.json", owner_document),
        ("claims.json", claims),
        ("input-entry.json", entry),
        ("report.json", report.clone()),
        (
            "baseline-catalog.json",
            value!({"specVersion":"1.0","entries":[a]}),
        ),
        (
            "pr117-catalog.json",
            value!({"specVersion":"1.0","entries":[b]}),
        ),
    ] {
        write_json(&out.join(name), &value)?;
    }
    write_new(&out.join("artifact.bin"), artifact, false)?;
    output(&report)?;
    Ok(report_a.accepted
        && report_b.accepted
        && owner_after.accepted
        && stale_snapshot_fails
        && root.accepted)
}

fn main() {
    match run() {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("{}", value!({"accepted":false,"error":error.to_string()}));
            std::process::exit(1);
        }
    }
}
