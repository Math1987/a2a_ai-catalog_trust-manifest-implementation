#!/usr/bin/env python3
"""Independent Python check of Rust-generated LOCAL demo fixtures.

Uses separate RFC8785 and cryptography implementations. This is a fixture
interop check, not a production DID resolver or evidence certification service.
"""
import base64
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def pairs(values):
    out = {}
    for key, value in values:
        if key in out:
            raise ValueError('duplicate JSON member')
        out[key] = value
    return out


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=')


def check_jws(payload, jws, signer, document):
    protected, detached, signature = jws.split('.')
    assert detached == ''
    header = json.loads(decode(protected), object_pairs_hook=pairs)
    assert header['alg'] == 'ES256' and set(header) == {'alg', 'kid'}
    assert document['id'] == signer and header['kid'].startswith(signer + '#')
    assert header['kid'] in document['assertionMethod']
    methods = [m for m in document['verificationMethod'] if m['id'] == header['kid']]
    assert len(methods) == 1 and methods[0]['controller'] == signer
    jwk = methods[0]['publicKeyJwk']
    assert jwk['kty'] == 'EC' and jwk['crv'] == 'P-256' and 'd' not in jwk
    point = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk['x']), 'big'),
                                       int.from_bytes(decode(jwk['y']), 'big'), ec.SECP256R1())
    raw = decode(signature)
    assert len(raw) == 64
    der = encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
    point.public_key().verify(der, protected.encode() + b'.' + encode(rfc8785.dumps(payload)),
                              ec.ECDSA(hashes.SHA256()))


def instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def check_time(value, now):
    assert instant(value['issuedAt']) <= now < instant(value['expiresAt'])


def resolve(value, path):
    assert path and path[0] != 'signatures'
    for name in path:
        assert isinstance(value, dict) and name in value
        value = value[name]
    return value


def check_pr(value, signature, documents, now, scope='entry'):
    assert signature['profile'] == 'did-web-v1'
    paths = sorted(signature['paths'], key=lambda p: [s.encode('utf-16-be') for s in p])
    payload = {'context': f'ai-catalog-{scope}-signature', 'signer': signature['signer'],
               'profile': signature['profile'], 'issuedAt': signature['issuedAt'],
               'fields': [[p, resolve(value, p)] for p in paths]}
    if 'expiresAt' in signature:
        payload['expiresAt'] = signature['expiresAt']
    check_jws(payload, signature['jws'], signature['signer'], documents[signature['signer']])
    check_time(signature, now)
    required = ['identifier', 'type', 'digest'] + (['version'] if 'version' in value else [])
    if scope == 'catalog':
        required = [key for key in value if key != 'signatures']
    assert all([key] in paths for key in required)


def main():
    directory = Path(sys.argv[1])
    report = load(directory / 'report.json')
    assert report['fixtureOnly'] is True
    now = instant(report['verifyAt'])  # reproduce the local demo's verification instant
    documents = {d['id']: d for d in [load(directory / 'registry-did.json'),
                                     load(directory / 'publisher-did.json')]}
    raw = (directory / 'artifact.bin').read_bytes()
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    baseline = load(directory / 'baseline-entry.json')
    manifest = baseline['trustManifest']
    check_jws({k: v for k, v in manifest.items() if k != 'signature'}, manifest['signature'],
              manifest['identity'], documents[manifest['identity']])
    check_time(manifest, now)
    assert manifest['subject']['digest'] == digest
    assert manifest['subject']['url'] == baseline['url']
    assert manifest['subject']['type'] == baseline['type']
    assert baseline['identifier'].split(':')[2] == manifest['identity'].split(':')[2]
    count = 1
    for name in ['pr117-entry.json', 'b1-entry.json', 'b1-renewed-entry.json']:
        entry = load(directory / name)
        assert entry['digest'] == digest
        for signature in entry['signatures']:
            check_pr(entry, signature, documents, now)
            count += 1
            if signature['signer'] == 'did:web:registry.example':
                assert ['trustManifests', signature['signer']] in signature['paths']
            else:
                assert signature['signer'] == 'did:web:' + entry['identifier'].split(':')[2]
    before = load(directory / 'b1-entry.json')
    after = load(directory / 'b1-renewed-entry.json')
    assert before['signatures'][0] == after['signatures'][0]
    for name in ['b1-catalog.json', 'b1-renewed-catalog.json']:
        catalog = load(directory / name)
        check_pr(catalog, catalog['signatures'][0], documents, now, 'catalog')
        count += 1
    stale = load(directory / 'b1-catalog.json')
    stale['entries'] = [copy.deepcopy(after)]
    try:
        check_pr(stale, stale['signatures'][0], documents, now, 'catalog')
    except Exception:
        pass
    else:
        raise AssertionError('old catalog snapshot unexpectedly verified')
    print(json.dumps({'independentPythonVerification': 'passed', 'signaturesVerified': count,
                      'publisherSurvivesRenewal': True, 'staleRootRejected': True}, indent=2))


if __name__ == '__main__':
    main()
