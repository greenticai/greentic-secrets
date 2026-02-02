# Seed Format

Secret seeds describe concrete values to be applied into a secrets store. The
format is shared across tooling (CLI scaffold/wizard/apply) and automated flows.

## Schema

```yaml
entries:
  - uri: secrets://<env>/<tenant>/<team-or-_>/<category>/<name>
    format: text | json | bytes
    description: Optional human hint
    value:
      type: text        # or json, bytes_b64
      text: "plain text"
      # json: {...}     # if type: json
      # bytes_b64: ""   # if type: bytes_b64, base64 encoded
```

## Scaffold template example

```yaml
entries:
  - uri: secrets://dev/example/_/configs/db_url
    format: text
    description: "Database connection string"
    value:
      type: text
      text: ""
  - uri: secrets://dev/example/_/configs/feature_flags
    format: json
    value:
      type: json
      json: {}
  - uri: secrets://dev/example/_/configs/blob
    format: bytes
    value:
      type: bytes_b64
      bytes_b64: ""
```

## Filled example

```yaml
entries:
  - uri: secrets://dev/example/_/configs/db_url
    format: text
    description: "Database connection string"
    value:
      type: text
      text: "postgres://user:pass@host/db"
  - uri: secrets://dev/example/_/configs/feature_flags
    format: json
    value:
      type: json
      json:
        enable_new_ui: true
    - uri: secrets://dev/example/_/configs/blob
    format: bytes
    value:
      type: bytes_b64
      bytes_b64: "YmluYXJ5LWRhdGE="
```

Pack-based scaffolding replaces the `configs` category with the pack's identifier (e.g., `secrets://dev/example/_/greentic.secrets.aws-sm/db_url`) so every pack keeps its secrets within its own namespace.

## Notes

- Bytes are represented as base64 to stay text-friendly.
- URIs follow the `secrets://env/tenant/team-or-_/category/name` convention; use
  `_` when no team is present.
- When a seed was generated from a pack metadata or `.gtpack`, the `category`
  segment is the pack_id (e.g.,
  `secrets://dev/example/_/greentic.secrets.aws-sm/db_url`) instead of `configs`.
- Validation is handled by the spec types (format enum, key validation, and
  structural parsing). Optional JSON schema validation can be layered on in the
  core apply pipeline.
