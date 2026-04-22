# greentic-secrets-cli

Shared CLI helpers for Greentic binaries that consume encrypted secret
stores. Provides `passphrase::resolve(...)` selecting between TTY,
stdin, and file sources with consistent error messages.

Used by `greentic-setup` (`gtc setup`) and `greentic-runner` (`gtc start`)
so passphrase prompt UX stays identical across binaries.

`#![forbid(unsafe_code)]`. Re-exports the full surface of
`greentic-secrets-passphrase` so consumers only need this one dep.
