# greentic-secrets-passphrase

Passphrase-based key derivation, terminal prompts, and on-disk header
format for Greentic's encrypted secret stores. Used by
`greentic-secrets-provider-dev` and consumers (`greentic-setup`,
`greentic-runner`).

Crypto: Argon2id (m=64MiB, t=3, p=1) → 32-byte master key, paired with
AES-256-GCM at the provider layer.

`#![forbid(unsafe_code)]`. Audited RustCrypto deps only.
