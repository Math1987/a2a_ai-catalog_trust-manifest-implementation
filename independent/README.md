# Independent Python PR #123 catalog verifier

This implementation was written from the specification at
`2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad`, independently of the Rust payload builder
and the previous Trust Manifest verifier. It reconstructs the whole catalog
payload itself and uses `rfc8785` and `cryptography` for JCS and ES256 verification.

## Scope and trust boundary

This is an **offline verifier**. It reads the catalog and DID document supplied
by the caller, requires an explicitly expected operator, and makes no DNS or
HTTP requests. Its success means that the snapshot passes the Catalog Profile
against that supplied DID document and local policy. It does **not** establish
that the DID document came from the current HTTPS resolution endpoint.

A production verification must pair this result with a separately recorded safe
HTTPS fetch of the current DID document. The acquisition record should identify
the resolved URL, observation time, HTTP result, transport/redirect checks,
response-size limits, and exact response digest. Match that digest to
`did_document_sha256` in this verifier's report. The root operator owns that
online acquisition and verification; this program supplies no insecure URL mode
or "skip validation" switch.

No private key is needed or read. The report contains only public identity/key
references, hashes, policy, and results. Catalog entry URLs and nested trust
claims are covered as signed data but are not fetched or independently endorsed.

## Reproduce

From this directory, create an isolated Python environment and install
`requirements.txt` (the bundle excludes the working environment):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

```sh
.venv/bin/python verify_catalog.py \
  --catalog ../proof-vectors/valid-catalog.json \
  --did-document ../proof-vectors/did.json \
  --expected-operator did:web:catalog-test.example \
  --now 2026-11-12T12:30:00Z \
  --require-expiry

.venv/bin/python check_vectors.py \
  --index ../proof-vectors/index.json \
  --report vector-results.json

.venv/bin/python -m unittest -v test_helpers
```

For a current production check, omit `--now`; it defaults to the current UTC
time. Supplying `--now` is intended for reproducible fixture or historical checks
and the chosen instant is included in the output. Exit status is 0 for an offline
verification success, 1 for rejection/input failure, and 2 for CLI usage errors.

```sh
.venv/bin/python verify_catalog.py \
  --catalog ../receipts/public-verification/public-ai-catalog.json \
  --did-document ../receipts/public-verification/public-did.json \
  --expected-operator did:web:ai-catalog.a2a-market.com \
  --now 2026-11-12T19:57:53Z --require-expiry
```

This replays the captured public bytes at their observation instant; it does
not prove current DID authorization. For a new current check, acquire fresh
catalog and DID bytes with recorded HTTPS provenance, then omit `--now`.

## Rules implemented

- Strict UTF-8 JSON parsing, duplicate-member rejection at every nesting level,
  document bounds, known catalog/CDDL member shapes and supported major version.
  Unknown members are preserved, including unknown signature metadata.
- Exactly `did-web-v1`, root lowercase ASCII `did:web`, IDNA 2008 A-label
  validation, no IP literal, port, trailing dot or DID path.
- Exact, case-sensitive equality of expected operator, root signer and
  `host.identifier`; no URI or domain-suffix normalization.
- RFC3339 instants and zero clock skew. Fractional seconds are retained when
  comparing instants. Expiry must follow issuance and acceptance is strictly
  before expiry. `--require-expiry` adds local policy; expiry is otherwise
  optional under the specification.
- Detached compact JWS, `ES256`, `ai-catalog+jws`, absolute matching DID `kid`,
  no `b64` and no header-supplied keys. Unknown noncritical headers are allowed;
  a valid string `cty` is not confused with `typ`.
- The DID document's exact `id`, a unique verification method authorized through
  `assertionMethod`, exact controller, P-256 public JWK and valid curve point.
  Relative fragment IDs/references are resolved against the document DID.
- Root payload reconstruction removes **only** root `signature.jws` and root
  `additionalSignatures`. Nested signatures, nested reserved members, unknown
  fields, entry order and host data remain covered.
- JCS from the independent Python RFC8785 implementation and ECDSA/SHA-256 from
  Python cryptography/OpenSSL, converting the JOSE 64-byte R/S representation
  directly for verification.

Local policies beyond the interoperable profile are explicit: 4 MiB per input,
nesting limit 64, no clock skew, leap-second notation rejected, no supported
critical JWS extensions, and `key_ops`, when present, restricted to `["verify"]`.
The RFC8785 library rejects out-of-range integer values in the signed payload;
represent such values as strings. This tool does not claim a general DID Core
resolver or exhaustive conformance for every DID representation.

## Evidence produced so far

`vector-results.json`: 32/32 cases matched expected acceptance (7 accepted,
25 rejected), using public test fixtures with ephemeral signing keys managed by
the separate reviewer. The case with no trusted operators is exercised by
passing an explicitly different expected operator, since this CLI requires one.
No Rust verifier is invoked by the Python matrix runner.

`helper-test-results.json`: the seven pure parsing/policy tests and runtime
dependency versions. `verification-artifacts.json` records this verifier's
source/evidence hashes. Separate public verification succeeded at 19:57:53 UTC
on 12 November 2026: see `../receipts/public-verification/summary.json`, the
Rust online result, the Python result and HTTPS provenance in that directory.
See `../proof-docs/DARREL_EVIDENCE.md` for their scope, portable reproduction
commands and the separate, unsent comment draft.
