use secrets_core::{SecretDescribable, SecretSpec};

pub struct TelegramSecrets;

impl SecretDescribable for TelegramSecrets {
    fn secret_specs() -> &'static [SecretSpec] {
        &[SecretSpec {
            name: "TELEGRAM_TOKEN",
            description: Some("Bot token from @BotFather (format: 1234567890:AA...)"),
        }]
    }
}
