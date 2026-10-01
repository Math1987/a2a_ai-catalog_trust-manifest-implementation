# Aithos Catalog Signatures

A Rust library and local CLI for signing and verifying AI Catalog entries in
two **explicitly pinned, separate formats**. The pure library is suitable for
import into the Rust registry. HTTP fetching and the CLI are optional features.

| Dialect | Pinned source | Construction |
| --- | --- | --- |
| `baseline` | [main 04a99cd](https://github.com/Agent-Card/ai-catalog/blob/04a99cd1ac9a20dd6586c6196e87f5e4570303b1/specification/ai-catalog.md) | Singular `trustManifest`; JCS of manifest excluding only its top-level `signature` |
| `pr117` | [draft head 51df07b](https://github.com/jonathanhefner/ai-catalog/blob/51df07b58e831f71ab6047672d6482ef93f5015f/specification/ai-catalog.md) | Contributor map, entry digest, selected-field signatures with explicit `did-web-v1` |

This package implements signature mechanics, artifact binding and configured
acceptance checks. **It does not perform domain certification or establish
ownership, endpoint control, claim truth, registry status or log inclusion.**
The registry must validate its evidence and authorize issuance before signing.
The example keys and claims are local fixtures under `.example` domains.

## Run the local comparison

Requires Rust 1.95.0; the toolchain and dependency lockfile are included.

```sh
git clone https://github.com/Math1987/a2a_ai-catalog_trust-manifest-implementation.git aithos-catalog-signatures
cd aithos-catalog-signatures
cargo test --locked --all-features
cargo run --locked --features cli -- demo --out .local/my-demo
```

Choose a new output directory on subsequent runs. The demo creates fresh
in-memory keys and writes public fixtures, never private keys:

* `baseline-entry.json` and `pr117-entry.json` bind identical artifact bytes and claims.
* `b1-entry.json` has a separate publisher signature and registry contribution.
* `b1-renewed-entry.json` renews that contribution while retaining the publisher signature.
* `b1-catalog.json` and `b1-renewed-catalog.json` demonstrate root snapshot replacement.
* `report.json` records acceptance checks, source revisions and the verification instant.
* `artifact.bin` is an opaque synthetic signing fixture. Its embedded signature
  is deliberately not an A2A signature test vector.

The demo verifies that the original publisher signature survives renewal, the
old root snapshot fails, and the new root snapshot succeeds. It exits nonzero
if those checks fail. It uses a verification instant one minute after initial
issuance to test renewal; `report.json.verifyAt` records that instant.

An independent Python implementation checks the resulting ES256/JCS signatures:

```sh
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements.txt
.venv/bin/python scripts/verify_demo.py .local/my-demo
```

Fixed public vectors are also checked in under `vectors/demo`; pass that path
to the Python checker to reproduce the result without generating keys.

This checker reconstructs the payloads itself with Python `rfc8785` and
`cryptography`; it does not call Rust to canonicalize or verify. It is a fixture
interop test, not a general production verifier. Do not run it with Python `-O`.

## Fetch your existing catalog entry

```sh
cargo run --locked --features cli -- fetch \
  --catalog https://catalog.aithos.me/.well-known/ai-catalog.json \
  --identifier urn:air:mathieucolla.com:agent:meeting \
  --allow-origin https://catalog.aithos.me \
  --allow-origin https://agents.aithos.app \
  --out .local/fetched
```

This saves `entry.json`, the exact `artifact.bin`, and retrieval metadata. It
does not invoke the agent or validate the card's own A2A signature. Select an
explicit `--version` when the identifier appears more than once; ambiguity fails.
Inline artifacts use JCS bytes.

The fetcher permits only configured HTTPS origins and port 443. It disables
proxies and redirects, rejects private/special addresses (including mixed DNS
answers), and pins the connection to the checked addresses. The total fetch
budget is 15 seconds including DNS, with a 1 MiB response bound. It requests
identity encoding and refuses encoded responses. At most eight DNS workers can
remain active; a timed-out OS DNS call may finish in the background.

## Sign the local copy

Create a local development key and public DID document:

```sh
cargo run --locked --features cli -- keygen \
  --signer did:web:registry.example \
  --kid 'did:web:registry.example#local' \
  --key .local/key.pem --did-document .local/did.json
```

On Unix the unencrypted development key is created with mode 0600 and cannot
overwrite an existing file. `.local/` and PEM files are ignored by Git. The DID
document is a local trust fixture; this command does not publish it on a domain.

Sign the fetched personal entry as a **registry contributor** in the PR format:

```sh
cargo run --locked --features cli -- sign --format pr117 \
  --entry .local/fetched/entry.json --artifact .local/fetched/artifact.bin \
  --claims .local/my-demo/claims.json --key .local/key.pem \
  --signer did:web:registry.example --kid 'did:web:registry.example#local' \
  --out .local/signed-entry.json

cargo run --locked --features cli -- verify --format pr117 \
  --entry .local/signed-entry.json --artifact .local/fetched/artifact.bin \
  --did-document .local/did.json --trust did:web:registry.example \
  --contributor did:web:registry.example
```

The example claims explicitly say that observation was not performed. A passing
result proves the local signature and its artifact/claim coverage. It correctly
reports `publisherAuthorized: false` on Mathieu's namespace. Adding
`--require-publisher` makes acceptance fail. To verify a publisher's separate
signature, select its `--signature-index`, DID document and trusted identity.

For baseline signing, prepare an entry under the signer's own namespace, such
as `urn:air:registry.example:agent:meeting`, then use `--format baseline`.
The library will not silently rewrite Mathieu's identifier to make it pass.
The `sign` command returns the complete signed entry. It defaults to a one-hour
validity period; use `--issued-at` and `--lifetime-seconds` for reproducible tests.
The CLI restricts lifetimes to 1–86400 seconds.

Verification prints JSON per-check results and exits 1 on rejection. Invalid
structures or cryptographic signatures return a JSON error. Use `--now` to
replay an old local fixture at its recorded verification instant.

## Library use

```toml
[dependencies]
aithos-catalog-signatures = { path = "../aithos-catalog-signatures" }
```

See [examples/sign.rs](examples/sign.rs), which runs without network features:

```sh
cargo run --locked --example sign
```

The primary APIs are:

| Function | Result |
| --- | --- |
| `baseline::sign_entry` | New entry with signed singular manifest; requires publisher-domain alignment |
| `pr117::endorse_entry` | New entry with digest, this signer's contributor manifest and covering signature |
| `pr117::sign_selected` | Signature object for explicit paths and entry/catalog scope |
| `baseline::verify_entry`, `pr117::verify_entry` | Per-signature acceptance report with independent trust policy |
| `baseline::sign_catalog`, `verify_catalog` | Whole baseline root snapshot signature |
| `pr117::snapshot_paths`, `verify_catalog` | Complete-root coverage construction and checking |
| `json::parse` | Duplicate-rejecting bounded input boundary |
| `fetch::Fetcher` (feature `http`) | Public HTTPS fetching and exact entry selection |

`endorse_entry` signs the complete own manifest, identifier/type/digest, version
when present, and URL when present. Renewal replaces this signer's manifest and
removes its previous entry signatures; other signers' signatures are preserved.
Those signatures still need verification: a signer that intentionally covered
the whole contributor map will be affected by the update.

`sign_selected` is deliberately lower level and can produce partial endorsements.
Always use the entry/root verification functions before treating one as a release,
claim or snapshot endorsement. Never combine partial coverage across signatures.
For claim verification, pass `Requirements::contributor` or explicit required
claim paths; the default requirements only request a release endorsement.

`Policy::trusted_signers` is independent caller configuration. For root checks,
it is the set of authorized catalog operators. With a supplied DID document,
`signerAuthenticated` is conditional on that document's trusted acquisition.
Use a locally pinned document in fixtures, or `Fetcher::did_document` with an
independent allowed-origin configuration for current-state resolution. Never
take the signer allowlist or replacement DID document from an untrusted entry.

## Key integration and future registry API

The `Es256Signer` trait accepts ordinary JWS signing-input bytes and returns
64 JOSE r||s bytes. A future KMS adapter can implement this trait and use
`crypto::der_to_jose` for KMS responses. The key must be P-256 and the operation
ES256. With `MessageType=RAW`, pass the signing input; with `DIGEST`, hash it
exactly once before KMS. There is no AWS dependency or KMS call in this package.

An eventual `/trustmanifest/{agentId}` endpoint must return enough signed data
to reconstruct verification, not just the JWS string:

* Baseline: manifest plus the entry/card binding context.
* PR: own contributor manifest, complete signature object and selected release fields.

Returning a complete entry in an API envelope is simplest. Include dialect and
source revision in that envelope. The registry must authorize the request,
construct truthful evidence, commit/log the issuance, and store its bytes before
exposing it. Retrieval should serve stored output without calling the signer.

## Exact scope and local policies

* This is a restricted ES256/root-did:web implementation, not every identity or
  algorithm the baseline allows. The baseline's assertion authorization and
  exact domain match are explicit local restrictions, not backported PR rules.
* PR DID selection supports absolute IDs and fragment-relative IDs, embedded
  assertion methods and references. It requires one suitable method with matching
  controller and valid public JWK metadata. Current document authorization is
  checked; historical key authorization is not reconstructed.
* Baseline signatures do not bind entry identifier/version. A same-domain
  relabeling test intentionally passes crypto and reports absent release coverage.
* PR path traversal is object-only. Empty member names and null values work;
  missing members and array indexing fail. Paths are sorted by unsigned UTF-16.
  Duplicate/overlapping paths are preserved exactly; the producer emits neither.
* Signature objects require an exact profile and reject unknown members, null
  expiry, unsupported profiles and failed-profile fallback. No `b64`/`crit` or
  alternative key sources are supported. Local JWS header policy permits only
  `alg`, `kid`, `typ`, and `cty`.
* Default policy requires expiry and uses zero clock skew. Library callers can
  explicitly allow absent expiry or configure up to five minutes skew. No
  anti-rollback database or current registry-status check is supplied.
* Untrusted JSON must enter through `json::parse`. A previously constructed
  `serde_json::Value` cannot reveal discarded duplicate members. Local bounds:
  1 MiB JSON, serde's normal nesting bound, 128 selected paths, integer tokens
  within ±(2^53−1). Cryptographic canonicalization uses `serde_jcs`.
* Claims are opaque signed application data with basic container checks. This
  is not a full catalog/evidence-schema validator, A2A verifier or attestation
  verifier. Signature validity alone never establishes that evidence is true.

## Development checks

```sh
cargo fmt --check
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
```

Tests exercise altered bytes, nested signatures, baseline relabeling, PR coverage
and version changes, split signatures, publisher/contributor separation, DID
authorization/removal, timestamps, Unicode path ordering, strict JSON, KMS DER
conversion, root snapshots and fetch boundaries. No live credentials or network
access are required by the Rust test suite.
