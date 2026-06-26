(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"plan\":{\"config_patch\":{\"tenant_id\":\"placeholder\",\"environment\":\"dev\",\"project_id\":\"placeholder\",\"auth_mode\":\"workload_identity\",\"namespace_prefix\":\"placeholder\",\"timeouts\":{\"connect_ms\":1,\"op_ms\":1},\"retry_policy\":{\"max_attempts\":1,\"base_backoff_ms\":1,\"max_backoff_ms\":1,\"jitter\":true},\"redaction_policy\":{\"redact_values\":true,\"log_secret_refs_only\":true}},\"secrets_patch\":{\"set\":{},\"delete\":[]},\"webhook_ops\":[],\"subscription_ops\":[],\"oauth_ops\":[],\"notes\":[]}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 464)
  )
)
