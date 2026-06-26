(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"requirements\":{\"provider_id\":\"greentic.secrets.aws-sm\",\"config\":{\"required\":[\"tenant_id\",\"environment\",\"region\",\"namespace_prefix\",\"timeouts\",\"retry_policy\",\"redaction_policy\"],\"optional\":[\"assume_role_arn\",\"kms_key_id\",\"labels\",\"audit\"],\"constraints\":{\"enum\":{\"environment\":[\"dev\",\"stage\",\"prod\"]}}},\"secrets\":{\"required\":[],\"optional\":[\"aws_access_key_id\",\"aws_secret_access_key\",\"aws_web_identity_token_file\",\"audit_sink_credentials\"],\"constraints\":{\"required_when\":{\"audit_sink_credentials\":{\"config_path\":\"audit.sink_type\",\"values\":[\"splunk\",\"azure\",\"gcp\",\"http\"]}}}},\"capabilities\":{\"supports_read\":true,\"supports_write\":true,\"supports_delete\":true},\"setup_needs\":{\"public_base_url\":false,\"oauth\":false,\"subscriptions\":false}}}")
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0)
    (i32.const 735)
  )
)
