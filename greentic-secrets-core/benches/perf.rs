use criterion::{Criterion, criterion_group, criterion_main};
use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::secrets::{SecretFormat, SecretRequirement};
use secrets_core::{ApplyOptions, SecretUri, SecretsStore, apply_seed};
use std::hint::black_box;

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

fn bench_secret_uri_parse(c: &mut Criterion) {
    c.bench_function("secret_uri_parse", |b| {
        b.iter(|| {
            let parsed = SecretUri::parse(black_box("secrets://dev/acme/_/configs/db-password@42"))
                .expect("uri parse");
            black_box(parsed);
        })
    });
}

fn bench_apply_seed_validation(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let store = NoopStore;
    let (seed, requirements) = sample_seed(512);

    c.bench_function("apply_seed_validation_512", |b| {
        b.iter(|| {
            let report = runtime.block_on(apply_seed(
                &store,
                black_box(&seed),
                ApplyOptions {
                    requirements: Some(black_box(requirements.as_slice())),
                    validate_schema: false,
                },
            ));
            black_box(report);
        })
    });
}

criterion_group!(benches, bench_secret_uri_parse, bench_apply_seed_validation);
criterion_main!(benches);
