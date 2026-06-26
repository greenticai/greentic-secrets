(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"requirements\":{\"provider_id\":\"greentic.secrets.azure-kv\",\"config\":{\"required\":[\"tenant_id\",\"environment\",\"vault_url\",\"auth_mode\",\"namespace_prefix\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"optional\":[\"client_id\",\"labels\",\"audit\"],\"constraints\":{\"enum\":{\"environment\":[\"dev\",\"stage\",\"prod\"],\"auth_mode\":[\"managed_identity\",\"service_principal\",\"device_code\"]}}},\"secrets\":{\"required\":[],\"optional\":[\"azure_client_secret\",\"audit_sink_credentials\"],\"constraints\":{\"required_when\":{\"audit_sink_credentials\":{\"config_path\":\"audit.sink_type\",\"values\":[\"splunk\",\"azure\",\"gcp\",\"http\"]}}}},\"capabilities\":{\"supports_read\":true,\"supports_write\":true,\"supports_delete\":true},\"setup_needs\":{\"public_base_url\":false,\"oauth\":false,\"subscriptions\":false}}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 748)
  )
)
