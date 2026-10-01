//! ES256 detached compact JWS. No A2A payload rules or jku resolution.
use crate::{Error, Result, did, ensure, json as strict, string};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use serde_json::{Value, json};

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error("invalid unpadded base64url".into()))
}

/// Adapter boundary for a local key or KMS/HSM. Input is the ordinary JWS
/// signing input, not a precomputed digest. Return exactly 64 JOSE r||s bytes.
pub trait Es256Signer {
    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64]>;
}

pub struct LocalKey(SigningKey);
impl LocalKey {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut rand_core::OsRng))
    }
    pub fn from_pem(pem: &str) -> Result<Self> {
        SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|_| Error("invalid P-256 PKCS#8 key".into()))
    }
    /// Secret material: persist only to a private local key file.
    pub fn to_pem(&self) -> Result<zeroize::Zeroizing<String>> {
        self.0
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| Error("key export failed".into()))
    }
    pub fn public_jwk(&self) -> Value {
        let point = self.0.verifying_key().to_encoded_point(false);
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig", "key_ops":["verify"],
            "x":encode(point.x().expect("uncompressed point")), "y":encode(point.y().expect("uncompressed point"))})
    }
    pub fn did_document(&self, signer: &str, kid: &str) -> Result<Value> {
        did::validate_kid(signer, kid)?;
        Ok(
            json!({"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id":signer, "verificationMethod":[{"id":kid, "type":"JsonWebKey2020", "controller":signer,
                "publicKeyJwk":self.public_jwk()}], "assertionMethod":[kid]}),
        )
    }
}
impl Es256Signer for LocalKey {
    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64]> {
        let signature: Signature = self.0.sign(signing_input);
        Ok(signature.to_bytes().into())
    }
}

/// Convert AWS KMS's DER ECDSA representation to JOSE. The caller remains
/// responsible for using the correct KMS key and MessageType (avoid double hashing).
pub fn der_to_jose(der: &[u8]) -> Result<[u8; 64]> {
    Signature::from_der(der)
        .map(|s| s.to_bytes().into())
        .map_err(|_| Error("invalid ES256 DER signature".into()))
}

pub fn sign(payload: &[u8], signer: &str, kid: &str, key: &dyn Es256Signer) -> Result<String> {
    did::validate_kid(signer, kid)?;
    let protected = encode(&strict::canonical(&json!({"alg":"ES256", "kid":kid}))?);
    let input = format!("{protected}.{}", encode(payload));
    let raw = key.sign_es256(input.as_bytes())?;
    // Catch malformed external adapter responses before producing a JWS.
    Signature::from_slice(&raw).map_err(|_| Error("invalid ES256 signer output".into()))?;
    Ok(format!("{protected}..{}", encode(&raw)))
}

pub fn verify(payload: &[u8], jws: &str, signer: &str, document: &Value) -> Result<()> {
    let parts: Vec<_> = jws.split('.').collect();
    ensure(
        parts.len() == 3 && parts[1].is_empty(),
        "expected detached compact JWS",
    )?;
    let header = strict::parse(&decode(parts[0])?)?;
    let obj = header
        .as_object()
        .ok_or_else(|| Error("JWS header is not an object".into()))?;
    ensure(string(&header, "alg")? == "ES256", "did:web requires ES256")?;
    // Strict local header allowlist, including refusal of crit and all key-source
    // parameters. No critical extensions are implemented by this library.
    ensure(
        obj.keys()
            .all(|k| ["alg", "kid", "typ", "cty"].contains(&k.as_str())),
        "unsupported JWS header (including b64, crit or key sources)",
    )?;
    for key in ["typ", "cty"] {
        if let Some(v) = obj.get(key) {
            ensure(v.is_string(), "JWS type header must be a string")?;
        }
    }
    let public = did::assertion_key(document, signer, string(&header, "kid")?)?;
    let signature = Signature::from_slice(&decode(parts[2])?)
        .map_err(|_| Error("expected 64-byte JOSE ES256 signature".into()))?;
    verify_raw(
        &public,
        &format!("{}.{}", parts[0], encode(payload)).into_bytes(),
        &signature,
    )
}

fn verify_raw(key: &VerifyingKey, input: &[u8], signature: &Signature) -> Result<()> {
    key.verify(input, signature)
        .map_err(|_| Error("cryptographic signature invalid".into()))
}
