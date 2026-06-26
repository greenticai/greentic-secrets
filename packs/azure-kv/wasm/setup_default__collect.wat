(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"questions\":{\"config_required\":[\"tenant_id\",\"environment\",\"vault_url\",\"auth_mode\",\"namespace_prefix\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"secrets_required\":[]}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 171)
  )
)
