use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::secrets::{SecretFormat, SecretRequirement};
use secrets_core::{ApplyOptions, SecretsStore, apply_seed};
use std::sync::mpsc;
use std::time::Duration;

struct NoopStore;

#[async_trait::async_trait]
impl SecretsStore for NoopStore {
    async fn put(
        &self,
        _uri: &str,
        _format: SecretFormat,
        _bytes: &[u8],
    ) -> secrets_core::Result<()> {
        Ok(())
    }

    async fn get(&self, _uri: &str) -> secrets_core::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn sample_seed(count: usize) -> (SeedDoc, Vec<SecretRequirement>) {
    let entries = (0..count)
        .map(|index| SeedEntry {
            uri: format!("secrets://dev/acme/_/configs/secret-{index}"),
            format: SecretFormat::Text,
            description: None,
            value: SeedValue::Text {
                text: format!("value-{index}"),
            },
        })
        .collect();

    let requirements = (0..count)
        .map(|index| {
            let mut requirement = SecretRequirement::default();
            requirement.key = format!("configs/secret-{index}").into();
            requirement
        })
        .collect();

    (SeedDoc { entries }, requirements)
}

#[test]
fn apply_seed_workload_should_finish_quickly() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let store = NoopStore;
        let (seed, requirements) = sample_seed(1024);
        let report = runtime.block_on(apply_seed(
            &store,
            &seed,
            ApplyOptions {
                requirements: Some(requirements.as_slice()),
                validate_schema: false,
            },
        ));
        tx.send(report.ok).expect("send result");
    });

    let ok = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("apply_seed should finish before timeout");
    assert_eq!(ok, 1024);
}
