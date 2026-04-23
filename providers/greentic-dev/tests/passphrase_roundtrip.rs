use greentic_secrets_passphrase::{derive_master_key, random_salt};
use greentic_secrets_spec::{
    ContentType, EncryptionAlgorithm, Envelope, Scope, SecretMeta, SecretRecord, SecretUri,
    SecretsBackend, Visibility,
};
use secrecy::SecretString;
use secrets_provider_dev::{DevBackend, PassphraseKeyProvider};
use std::sync::Arc;

fn provider(passphrase: &str) -> (Arc<PassphraseKeyProvider>, [u8; 16]) {
    let salt = random_salt();
    let mk = derive_master_key(&SecretString::from(passphrase.to_string()), &salt).unwrap();
    (Arc::new(PassphraseKeyProvider::new(mk, salt)), salt)
}

fn sample_record(uri: &SecretUri) -> SecretRecord {
    let meta = SecretMeta::new(uri.clone(), Visibility::Team, ContentType::Text);
    let env = Envelope {
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        nonce: vec![],
        hkdf_salt: vec![],
        wrapped_dek: vec![],
    };
    SecretRecord::new(meta, b"hello".to_vec(), env)
}

fn marker_path(store: &std::path::Path) -> std::path::PathBuf {
    let mut p = store.to_path_buf();
    let name = p.file_name().unwrap().to_string_lossy().into_owned();
    p.set_file_name(format!("{name}.encrypted-marker"));
    p
}

#[test]
fn put_get_round_trip_with_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");
    let (p, _salt) = provider("correct horse battery staple");

    let scope = Scope::new("dev", "acme", Some("core".into())).unwrap();
    let uri = SecretUri::new(scope, "kv", "api-token").unwrap();

    {
        let backend =
            DevBackend::with_persistence_encrypted(&path, p.clone(), false).unwrap();
        backend.put(sample_record(&uri)).unwrap();
    }

    let raw = std::fs::read(&path).unwrap();
    assert!(
        raw.starts_with(b"# greentic-encrypted: v1\n"),
        "expected encrypted header, got: {:?}",
        std::str::from_utf8(&raw).unwrap_or("<non-utf8>")
    );
    assert!(
        !raw.windows(5).any(|w| w == b"hello"),
        "plaintext leak in: {:?}",
        std::str::from_utf8(&raw).unwrap_or("<non-utf8>")
    );
    assert!(marker_path(&path).exists(), "marker not written");

    let backend = DevBackend::with_persistence_encrypted(&path, p, false).unwrap();
    let got = backend.get(&uri, None).unwrap().unwrap();
    assert_eq!(got.record.unwrap().value, b"hello");
}

#[test]
fn wrong_passphrase_fails_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");
    let (p, _) = provider("correct horse battery staple");

    let scope = Scope::new("dev", "acme", Some("core".into())).unwrap();
    let uri = SecretUri::new(scope, "kv", "api-token").unwrap();

    {
        let backend = DevBackend::with_persistence_encrypted(&path, p, false).unwrap();
        backend.put(sample_record(&uri)).unwrap();
    }

    let salt = random_salt();
    let mk = derive_master_key(
        &SecretString::from("wrong passphrase value!".to_string()),
        &salt,
    )
    .unwrap();
    let bad_provider = Arc::new(PassphraseKeyProvider::new(mk, salt));

    let result = DevBackend::with_persistence_encrypted(&path, bad_provider, false);
    let err = result.err().expect("expected an error loading with wrong passphrase");
    assert!(matches!(
        err,
        greentic_secrets_spec::SecretsError::InvalidPassphrase
    ));
}

#[test]
fn legacy_file_auto_migrates_on_first_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");

    let scope = Scope::new("dev", "acme", Some("core".into())).unwrap();
    let uri = SecretUri::new(scope, "kv", "old-key").unwrap();

    {
        let backend = DevBackend::with_persistence_plaintext(&path).unwrap();
        backend.put(sample_record(&uri)).unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.starts_with(b"# greentic-encrypted:"));

    let (p, _) = provider("new strong passphrase!!");
    let backend = DevBackend::with_persistence_encrypted(&path, p.clone(), false).unwrap();
    let got = backend.get(&uri, None).unwrap();
    assert!(got.is_some(), "existing legacy record must be readable");

    let uri2 = SecretUri::new(
        Scope::new("dev", "acme", Some("core".into())).unwrap(),
        "kv",
        "new-key",
    )
    .unwrap();
    backend.put(sample_record(&uri2)).unwrap();

    let raw = std::fs::read(&path).unwrap();
    assert!(raw.starts_with(b"# greentic-encrypted: v1\n"));
}

#[test]
fn refuses_legacy_after_marker_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");

    let (p, _) = provider("correct horse battery staple");
    {
        let scope = Scope::new("dev", "acme", Some("core".into())).unwrap();
        let uri = SecretUri::new(scope, "kv", "k").unwrap();
        let backend = DevBackend::with_persistence_encrypted(&path, p.clone(), false).unwrap();
        backend.put(sample_record(&uri)).unwrap();
    }

    std::fs::write(&path, "SECRETS_BACKEND_STATE=eyJzZWNyZXRzIjpbXX0\n").unwrap();
    assert!(marker_path(&path).exists());

    let err = DevBackend::with_persistence_plaintext(&path)
        .err()
        .expect("expected downgrade error");
    let msg = format!("{err}");
    assert!(
        msg.contains("downgrade"),
        "expected downgrade error, got: {msg}"
    );
}

#[test]
fn allow_downgrade_bypasses_marker_guard() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");
    let (p, _) = provider("correct horse battery staple");
    {
        let scope = Scope::new("dev", "acme", Some("core".into())).unwrap();
        let uri = SecretUri::new(scope, "kv", "k").unwrap();
        let backend = DevBackend::with_persistence_encrypted(&path, p.clone(), false).unwrap();
        backend.put(sample_record(&uri)).unwrap();
    }
    std::fs::write(&path, "SECRETS_BACKEND_STATE=eyJzZWNyZXRzIjpbXX0\n").unwrap();

    let _ = DevBackend::with_persistence_encrypted(&path, p, true).unwrap();
}
