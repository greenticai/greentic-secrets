use greentic_secrets_spec::{SeedDoc, SeedEntry, SeedValue};
use greentic_types::secrets::{SecretFormat, SecretRequirement};
use secrets_core::{ApplyOptions, SecretsStore, apply_seed};
use std::time::{Duration, Instant};

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

fn run_workload(threads: usize) -> Duration {
    let total_runs = 64usize;
    let runs_per_thread = total_runs / threads.max(1);
    let start = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(move || {
                let runtime = tokio::runtime::Runtime::new().expect("runtime");
                let store = NoopStore;
                let (seed, requirements) = sample_seed(256);

                for _ in 0..runs_per_thread {
                    let report = runtime.block_on(apply_seed(
                        &store,
                        &seed,
                        ApplyOptions {
                            requirements: Some(requirements.as_slice()),
                            validate_schema: false,
                        },
                    ));
                    assert!(report.failed.is_empty());
                    assert_eq!(report.ok, seed.entries.len());
                }
            });
        }
    });

    start.elapsed()
}

#[test]
fn scaling_should_not_degrade_badly() {
    let t1 = run_workload(1);
    let t4 = run_workload(4);
    let t8 = run_workload(8);

    eprintln!("perf_scaling: t1={t1:?} t4={t4:?} t8={t8:?}");

    assert!(
        t4 <= t1.mul_f64(1.75),
        "4 threads slower than expected: t1={t1:?}, t4={t4:?}"
    );
    assert!(
        t8 <= t4.mul_f64(1.75),
        "8 threads slower than expected: t4={t4:?}, t8={t8:?}"
    );
}
