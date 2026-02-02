use secrets_core::{SecretDescribable, SecretSpec};

pub struct WeatherSecrets;

impl SecretDescribable for WeatherSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "WEATHERAPI_KEY",
            description: Some("API key from weatherapi.com dashboard."),
        }]
    }
}
