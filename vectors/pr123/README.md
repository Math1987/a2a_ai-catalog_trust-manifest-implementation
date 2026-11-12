# PR123 public proof vectors

These files exercise the did:web Catalog Profile proposed at commit
[`2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad`](https://github.com/Agent-Card/ai-catalog/blob/2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad/specification/ai-catalog.md#the-did-web-catalog-profile).

They are test fixtures, not production endorsements or certificates. The domain
`catalog-test.example` is an example identity. Its DID document is a caller-pinned
offline fixture; these checks do not prove live DNS/HTTPS domain control.

`index.json` lists 32 cases: 7 accepted and 25 rejected. Every case supplies a
catalog wire file, DID document, independently configured trusted operators,
verification time, expiry policy and expected decision. Rust observations are
included for reproducibility. The root signature is checked independently of
publisher endorsements and evidence inside referenced entries.

## Main example

- `valid-catalog.json`: signed catalog with one public Agent Card reference.
- `did.json`: public P-256 assertion key for the test operator.
- Signing time: `2026-11-12T12:00:00Z`.
- Expiry: `2026-11-12T13:00:00Z`.
- Fixed verification time: **`2026-11-12T12:30:00Z`**.

Use the fixed time to reproduce the result. The fixtures are not intended to
remain fresh at the current wall-clock time.

From the `signatures` directory:

```sh
cargo test --locked --offline --all-features --test catalog_profile
cargo run --locked --offline --features cli -- verify-catalog --catalog vectors/pr123/valid-catalog.json --did-document vectors/pr123/did.json --expect-operator did:web:catalog-test.example --now 2026-11-12T12:30:00Z
```

Tests use the in-repository `vectors/pr123` directory by default. Set
`PR123_VECTOR_DIR` explicitly to use another fixture directory. No directory
outside the crate is required for `cargo test`.

The separate independent Python verification report, distributed with the
project's proof package, records whether its decisions agree with this index.

## Scope of negative cases

The suite includes validly re-signed host mismatches, so rejection is not merely
a consequence of tampering with an existing signature. Other cases check payload
mutation, nested signature coverage, unknown fields, optional `cty`, accepted
unknown noncritical headers, forbidden
headers, unsupported critical parameters, DID assertion authorization, incorrect
controllers and curve points, expiry boundaries and equivalent timestamp offsets.

The `nested-opaque-evidence` case intentionally includes unverified contributor
evidence. Acceptance concerns only the catalog operator's signed snapshot;
it makes no claim that the nested evidence or its signing profile is valid.
The `private-jwk-forbidden` case contains an invalid text marker in `d`, not
private key material. The duplicate-member case is deliberately invalid JSON
for a duplicate-rejecting parser, even though many general-purpose parsers would
silently accept it.

## Generation and key handling

The generator is an explicitly ignored integration test in
`signatures/tests/catalog_profile.rs`. It signs through the primitive ES256
adapter and constructs the JCS payload independently of the implementation's
`sign_catalog` and `payload` functions.

```sh
PR123_VECTOR_DIR=/absolute/path/to/new-empty-directory cargo test --locked --offline --all-features --test catalog_profile generate_public_proof_vectors -- --ignored --exact
```

The generator refuses any nonempty destination, preserving the published
fixtures. Each explicit generation uses a new random in-memory test key. The private key
is never exported; regeneration changes signatures and hashes. Ordinary tests
only read the checked-in public vectors. The separate CLI permission tests create
short-lived test keys inside private temporary directories and remove those
directories on completion or panic. No production keys are involved.

The integration tests also exercise alternative private-IP spellings and local
`localhost` DNS rejection. They do not claim a live HTTPS redirect/DNS-rebinding
integration test. The existing fetcher disables redirects and proxies, filters
resolved addresses and pins the checked addresses to the connection; that last
statement is a code inspection finding, distinct from the executed tests.
