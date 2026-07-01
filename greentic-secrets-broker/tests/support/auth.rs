use std::slice;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;
use serde_json::Value;

pub struct TestAuth {
    encoding: EncodingKey,
    issuer: String,
    audience: String,
    public_key: Vec<u8>,
}

impl TestAuth {
    pub fn configured() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");

        let issuer = "https://greentic.test/issuer".to_string();
        let audience = "greentic-broker".to_string();

        let public_raw = keypair.public_key().as_ref().to_vec();
        let public_b64 = URL_SAFE_NO_PAD.encode(&public_raw);
        // SAFETY: integration tests own the process environment and clean up before exit.
        unsafe {
            std::env::set_var("AUTH_JWT_ISS", &issuer);
            std::env::set_var("AUTH_JWT_AUD", &audience);
            std::env::set_var("AUTH_JWT_ED25519_PUB", public_b64);
            std::env::remove_var("AUTH_JWT_JWKS_URL");
            std::env::remove_var("AUTH_JWT_INTERNAL_SUBJECTS");
            std::env::remove_var("AUTH_JWT_INTERNAL_TOKEN");
        }

        let encoding_pem = encode_pem("PRIVATE KEY", pkcs8.as_ref());
        let encoding = EncodingKey::from_ed_pem(encoding_pem.as_bytes()).expect("encoding key");

        Self {
            encoding,
            issuer,
            audience,
            public_key: public_raw,
        }
    }

    #[allow(dead_code)]
    pub fn token(&self, roles: &[&str], tenant: &str, team: Option<&str>) -> String {
        self.token_with_ttl("svc@greentic.dev", roles, tenant, team, 3600)
    }

    #[allow(dead_code)]
    pub fn expired_token(&self, roles: &[&str], tenant: &str, team: Option<&str>) -> String {
        self.token_with_ttl("svc@greentic.dev", roles, tenant, team, -60)
    }

    pub fn token_with_ttl(
        &self,
        subject: &str,
        roles: &[&str],
        tenant: &str,
        team: Option<&str>,
        ttl_secs: i64,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs() as i64;
        let exp = now.saturating_add(ttl_secs);

        let roles_vec = roles
            .iter()
            .map(|role| role.to_string())
            .collect::<Vec<_>>();
        let claims = TestClaims {
            sub: subject,
            iss: &self.issuer,
            aud: &self.audience,
            exp,
            tenant,
            team,
            roles: &roles_vec,
            actor: subject,
        };

        let token = encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .expect("failed to encode test token");

        let mut segments = token.split('.');
        let header_segment = segments.next().expect("header");
        let payload_segment = segments.next().expect("payload");
        let signature_segment = segments.next().expect("signature");
        let signing_input = format!("{header_segment}.{payload_segment}");
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_segment.as_bytes())
            .expect("signature b64");
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.public_key)
            .verify(signing_input.as_bytes(), &signature_bytes)
            .expect("ring verification");

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_issuer(slice::from_ref(&self.issuer));
        validation.set_audience(slice::from_ref(&self.audience));
        let public_der = public_spki(&self.public_key);
        let public_pem = encode_pem("PUBLIC KEY", &public_der);
        decode::<Value>(
            &token,
            &DecodingKey::from_ed_pem(public_pem.as_bytes()).expect("decoding key"),
            &validation,
        )
        .expect("token self validation");

        token
    }
}

#[derive(Serialize)]
struct TestClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    tenant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<&'a str>,
    roles: &'a [String],
    actor: &'a str,
}

fn public_spki(raw: &[u8]) -> Vec<u8> {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + raw.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(raw);
    der
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut body = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).expect("utf8"));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}
