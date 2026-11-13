#!/usr/bin/env python3
"""Offline, independent Python verifier for AI Catalog PR #123 at 2973e3a.

No network access, private keys, Rust payloads, or legacy signing helpers are
used. A supplied DID document is input evidence, NOT proof of live DID resolution.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import rfc8785
import idna
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


SPEC_REVISION = "2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad"
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
PROFILE = "did-web-v1"
CATALOG_TYPE = "ai-catalog+jws"
RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})\Z")


class VerificationError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationError(code)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_member")
        result[key] = value
    return result


def reject_constant(_):
    raise VerificationError("invalid_json_number")


def parse_json(raw: bytes):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "document_size_limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except VerificationError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise VerificationError("invalid_json") from None
    pending = [(value, 0)]
    while pending:
        child, depth = pending.pop()
        require(depth <= MAX_DEPTH, "document_depth_limit")
        if type(child) is dict:
            pending.extend((item, depth + 1) for item in child.values())
        elif type(child) is list:
            pending.extend((item, depth + 1) for item in child)
    return value


def read_document(path: Path) -> bytes:
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "document_size_limit")
    return raw


def timestamp(value: str) -> Decimal:
    """Compare RFC3339 instants without truncating fractional seconds.

    Local policy rejects leap-second notation rather than normalizing it to
    another instant. It accepts offset notation and either RFC3339 T/Z case.
    """
    require(type(value) is str, "invalid_timestamp")
    match = RFC3339.fullmatch(value)
    require(match is not None, "invalid_timestamp")
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    require(second < 60, "unsupported_leap_second")
    fraction, zone = match.groups()[6:]
    try:
        local = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        raise VerificationError("invalid_timestamp") from None
    offset = 0
    if zone.upper() != "Z":
        hours, minutes = map(int, zone[1:].split(":"))
        require(hours < 24 and minutes < 60, "invalid_timestamp")
        offset = (hours * 3600 + minutes * 60) * (1 if zone[0] == "+" else -1)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = local - epoch
    with localcontext() as context:
        context.prec = max(32, len(fraction or "") + 32)
        return Decimal(delta.days * 86400 + delta.seconds - offset) + Decimal(fraction or "0")


def object_shape(value, required=(), optional=(), *, arrays=(), objects=()):
    """Validate known CDDL members without deleting unrecognized members."""
    require(type(value) is dict, "invalid_object_structure")
    for name in required:
        require(name in value and type(value[name]) is str, "invalid_required_string")
    for name in optional:
        if name in value:
            require(type(value[name]) is str, "invalid_optional_string")
    for name in arrays:
        if name in value:
            require(type(value[name]) is list, "invalid_array_structure")
    for name in objects:
        if name in value:
            require(type(value[name]) is dict, "invalid_object_structure")


def string_array(value):
    require(type(value) is list and all(type(item) is str for item in value), "invalid_string_array")


def signature_shape(value):
    object_shape(value, ("signer", "profile", "issuedAt", "jws"), ("expiresAt",))
    require(bool(value["profile"]), "empty_signature_profile")
    issued = timestamp(value["issuedAt"])
    if "expiresAt" in value:
        require(timestamp(value["expiresAt"]) > issued, "invalid_validity_interval")


def manifest_shape(manifest):
    object_shape(manifest, ("contributor",), arrays=("attestations", "provenance"),
                 objects=("subject", "signature", "trustSchema", "extensions"))
    require(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$", manifest["contributor"]) is not None,
            "invalid_contributor_uri")
    require("signature" in manifest or "trustSchema" in manifest or any(
        manifest.get(name) for name in ("attestations", "provenance", "extensions")), "empty_manifest")
    if "signature" in manifest:
        require("subject" in manifest, "signed_manifest_without_subject")
        signature_shape(manifest["signature"])
    if "subject" in manifest:
        object_shape(manifest["subject"], ("identifier", "type", "digest"), ("version",))
    if "trustSchema" in manifest:
        object_shape(manifest["trustSchema"], ("identifier", "version"), ("governanceUri",),
                     arrays=("verificationMethods",))
        if "verificationMethods" in manifest["trustSchema"]:
            string_array(manifest["trustSchema"]["verificationMethods"])
    for attestation in manifest.get("attestations", []):
        object_shape(attestation, ("type", "uri"), ("digest", "description"))
        if "size" in attestation:
            require(type(attestation["size"]) is int and attestation["size"] >= 0, "invalid_attestation_size")
    for provenance in manifest.get("provenance", []):
        object_shape(provenance, ("relation", "sourceId"),
                     ("sourceDigest", "registryUri", "statementUri", "signatureRef"))


def catalog_shape(catalog):
    object_shape(catalog, ("specVersion",), objects=("host", "signature", "extensions"))
    require(re.fullmatch(r"\d+\.\d+", catalog["specVersion"]) is not None, "invalid_spec_version")
    require(int(catalog["specVersion"].split(".")[0]) == 1, "unsupported_spec_major")
    require("entries" in catalog and type(catalog["entries"]) is list, "invalid_entries")
    require("host" in catalog, "missing_host")
    object_shape(catalog["host"], ("displayName", "identifier"), ("documentationUrl", "logoUrl"))
    require("signature" in catalog, "missing_root_signature")
    signature_shape(catalog["signature"])
    seen = {}
    for entry in catalog["entries"]:
        object_shape(entry, ("identifier", "type"),
                     ("url", "displayName", "description", "version", "updatedAt", "digest"),
                     arrays=("tags", "trustManifests"), objects=("publisher", "extensions"))
        require(("url" in entry) != ("data" in entry), "entry_requires_url_xor_data")
        if "tags" in entry:
            string_array(entry["tags"])
        if "updatedAt" in entry:
            timestamp(entry["updatedAt"])
        if "publisher" in entry:
            object_shape(entry["publisher"], ("identifier", "displayName"), ("identityType",))
        policy_urls = entry.get("extensions", {}).get("https://ai-catalog.org/extensions/policy-urls")
        if "https://ai-catalog.org/extensions/policy-urls" in entry.get("extensions", {}):
            object_shape(policy_urls, optional=("privacyPolicyUrl", "termsOfServiceUrl"))
        versions = seen.setdefault(entry["identifier"], [])
        version = entry.get("version")
        require(not versions or (version is not None and None not in versions and version not in versions),
                "duplicate_or_unversioned_identifier")
        versions.append(version)
        for manifest in entry.get("trustManifests", []):
            manifest_shape(manifest)


def root_did(value: str) -> str:
    require(type(value) is str and value.startswith("did:web:"), "invalid_root_did")
    domain = value[len("did:web:"):]
    require(domain.isascii() and domain == domain.lower() and 0 < len(domain) <= 253,
            "invalid_root_did")
    require(not domain.endswith("."), "invalid_root_did")
    labels = domain.split(".")
    require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels),
            "invalid_root_did")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise VerificationError("ip_address_did_forbidden")
    # Reject ambiguous dotted-numeric host spellings in addition to IP literals.
    require(not all(char in "0123456789." for char in domain), "ip_address_did_forbidden")
    try:
        decoded = idna.decode(domain, strict=True, uts46=False)
        require(idna.encode(decoded, strict=True, uts46=False).decode("ascii") == domain,
                "invalid_idna_alabel")
    except idna.IDNAError:
        raise VerificationError("invalid_idna_alabel") from None
    return "https://" + domain + "/.well-known/did.json"


def decode64(value: str, *, length=None) -> bytes:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None, "invalid_base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise VerificationError("invalid_base64url") from None
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value, "noncanonical_base64url")
    require(length is None or len(raw) == length, "invalid_binary_length")
    return raw


def kid_url(kid, signer):
    require(type(kid) is str and kid.startswith(signer + "#"), "kid_signer_mismatch")
    fragment = kid[len(signer) + 1:]
    require(bool(fragment) and re.fullmatch(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+", fragment)
            is not None, "invalid_kid_fragment")
    # '/' and '?' in the fragment are fragment data, not a DID path/query.
    require(urlsplit(kid).query == "" and urlsplit(kid).path == signer[len("did:"):], "invalid_kid_url")


def did_reference(value, signer):
    require(type(value) is str and bool(value), "invalid_did_reference")
    if value.startswith("#"):
        return signer + value
    require(value.startswith("did:"), "unsupported_relative_did_reference")
    return value


def did_public_key(document, signer, kid):
    require(type(document) is dict and document.get("id") == signer, "did_document_id_mismatch")
    methods = document.get("verificationMethod", [])
    assertions = document.get("assertionMethod", [])
    require(type(methods) is list and type(assertions) is list, "invalid_did_relationships")
    by_id = {}
    for method in methods:
        require(type(method) is dict and type(method.get("id")) is str, "invalid_verification_method")
        ident = did_reference(method["id"], signer)
        require(ident not in by_id, "duplicate_verification_method_id")
        by_id[ident] = method
    selected = []
    for assertion in assertions:
        if type(assertion) is str:
            ident = did_reference(assertion, signer)
            require(ident in by_id, "unresolved_assertion_reference")
            if ident == kid:
                selected.append(by_id[ident])
        elif type(assertion) is dict:
            ident = did_reference(assertion.get("id"), signer)
            require(ident not in by_id, "duplicate_verification_method_id")
            if ident == kid:
                selected.append(assertion)
        else:
            raise VerificationError("invalid_assertion_method")
    require(len(selected) == 1, "key_not_uniquely_authorized")
    method = selected[0]
    require(type(method.get("type")) is str and bool(method["type"]), "missing_verification_method_type")
    require(method.get("controller") == signer, "delegated_controller_forbidden")
    require(not any(name in method for name in ("publicKeyMultibase", "publicKeyBase58", "privateKeyJwk")),
            "ambiguous_verification_material")
    jwk = method.get("publicKeyJwk")
    require(type(jwk) is dict and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256", "invalid_jwk_type")
    require(not set(jwk).intersection({"d", "p", "q", "dp", "dq", "qi", "oth", "k"}), "private_jwk_material")
    require("alg" not in jwk or jwk["alg"] == "ES256", "invalid_jwk_algorithm")
    require("use" not in jwk or jwk["use"] == "sig", "invalid_jwk_use")
    if "key_ops" in jwk:
        operations = jwk["key_ops"]
        require(type(operations) is list and operations == ["verify"], "invalid_jwk_key_ops")
    x, y = (int.from_bytes(decode64(jwk[axis], length=32), "big") if axis in jwk else None for axis in ("x", "y"))
    require(x is not None and y is not None, "missing_jwk_coordinate")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:
        raise VerificationError("invalid_curve_point") from None


def verify(catalog_raw: bytes, did_raw: bytes, expected_operator: str, *, now: str | None = None,
           require_expiry: bool = False) -> dict:
    checked_at = now or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    instant = timestamp(checked_at)
    root_did(expected_operator)
    catalog, did = parse_json(catalog_raw), parse_json(did_raw)
    catalog_shape(catalog)
    signature = catalog["signature"]
    signer = signature["signer"]
    did_url = root_did(signer)
    require(signature["profile"] == PROFILE, "unsupported_signature_profile")
    require(signer == expected_operator, "unexpected_operator")
    require(catalog["host"]["identifier"] == signer, "host_operator_mismatch")
    issued = timestamp(signature["issuedAt"])
    require(instant >= issued, "signature_not_yet_valid")
    require(not require_expiry or "expiresAt" in signature, "expiry_required_by_policy")
    if "expiresAt" in signature:
        require(instant < timestamp(signature["expiresAt"]), "signature_expired")
    parts = signature["jws"].split(".")
    require(len(parts) == 3 and parts[1] == "", "invalid_detached_jws")
    protected = parse_json(decode64(parts[0]))
    require(type(protected) is dict, "invalid_jws_header")
    require(protected.get("alg") == "ES256", "unsupported_jws_algorithm")
    require(protected.get("typ") == CATALOG_TYPE, "wrong_jws_type")
    require(not set(protected).intersection({"b64", "jku", "jwk", "x5u", "x5c"}), "forbidden_jws_header")
    require("crit" not in protected, "unsupported_critical_header")
    if "cty" in protected:
        require(type(protected["cty"]) is str, "invalid_jws_content_type")
    kid = protected.get("kid")
    kid_url(kid, signer)
    public_key = did_public_key(did, signer, kid)
    payload = copy.deepcopy(catalog)
    del payload["signature"]["jws"]
    payload.pop("additionalSignatures", None)
    try:
        canonical = rfc8785.dumps(payload)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise VerificationError("invalid_jcs_payload") from None
    signing_input = parts[0].encode("ascii") + b"." + base64.urlsafe_b64encode(canonical).rstrip(b"=")
    raw_signature = decode64(parts[2], length=64)
    r, s = (int.from_bytes(raw_signature[start:start + 32], "big") for start in (0, 32))
    try:
        public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise VerificationError("signature_verification_failed") from None
    return {
        "success": True, "spec_revision": SPEC_REVISION, "profile": PROFILE,
        "verification_mode": "offline-provided-did", "checked_at": checked_at,
        "signer": signer, "expected_operator": expected_operator, "kid": kid,
        "did_resolution_url": did_url, "did_resolution": "not_performed",
        "current_online_authorization_checked": False,
        "catalog_sha256": sha256(catalog_raw), "payload_sha256": sha256(canonical),
        "did_document_sha256": sha256(did_raw), "payload_bytes": len(canonical),
        "checks": ["strict_json", "known_catalog_structure", "exact_profile_and_expected_operator",
                   "exact_host_operator", "signature_time", "detached_es256_catalog_jws",
                   "did_assertion_authorization", "public_p256_key", "whole_catalog_jcs_signature"],
        "policy": {"max_bytes": MAX_BYTES, "max_depth": MAX_DEPTH, "clock_skew_seconds": 0,
                   "require_expiry": require_expiry, "leap_seconds": "rejected",
                   "jwk_key_ops_if_present": ["verify"]},
        "not_verified": ["live_did_resolution_and_fetch_provenance", "nested_trust_endorsements",
                         "referenced_artifact_bytes", "publisher_authority", "legal_identity", "reputation"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--did-document", type=Path, required=True)
    parser.add_argument("--expected-operator", required=True)
    parser.add_argument("--now", help="RFC3339 validation instant; omitted means current UTC time")
    parser.add_argument("--require-expiry", action="store_true", help="Local policy requiring expiresAt")
    args = parser.parse_args(argv)
    failure = {"success": False, "spec_revision": SPEC_REVISION, "verification_mode": "offline-provided-did",
               "did_resolution": "not_performed", "current_online_authorization_checked": False}
    try:
        catalog_raw, did_raw = read_document(args.catalog), read_document(args.did_document)
        failure.update(catalog_sha256=sha256(catalog_raw), did_document_sha256=sha256(did_raw))
        result = verify(catalog_raw, did_raw, args.expected_operator, now=args.now,
                        require_expiry=args.require_expiry)
    except VerificationError as error:
        result = {**failure, "error": error.code}
    except OSError:
        result = {**failure, "error": "input_file_unavailable"}
    except (TypeError, ValueError, RecursionError, OverflowError):
        result = {**failure, "error": "invalid_input"}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
