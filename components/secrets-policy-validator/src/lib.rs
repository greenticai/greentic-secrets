//! Stub implementation of the secrets policy validator component.
//! Validates that secret operations conform to configured policies.
//! This is a placeholder — full policy engine to be implemented.

#[cfg(not(target_arch = "wasm32"))]
use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
#[cfg(target_arch = "wasm32")]
mod bindings {
    include!("../../common/schema_core_api.rs");
}
#[cfg(target_arch = "wasm32")]
use bindings::exports::greentic::provider_schema_core::schema_core_api;

use serde_json::json;

fn ok(payload: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec())
}

fn err(msg: impl Into<String>) -> Vec<u8> {
    serde_json::to_vec(&json!({ "status": "error", "message": msg.into() }))
        .unwrap_or_else(|_| b"{\"status\":\"error\"}".to_vec())
}

pub struct PolicyValidator;

impl schema_core_api::Guest for PolicyValidator {
    fn describe() -> Vec<u8> {
        ok(json!({
            "provider_type": "policy_validator",
            "id": "greentic.secrets.policy_validator",
            "capabilities": ["validate_policy"],
            "ops": ["validate_policy"],
        }))
    }

    fn validate_config(config_json: Vec<u8>) -> schema_core_api::ValidationResult {
        match serde_json::from_slice::<serde_json::Value>(&config_json) {
            Ok(serde_json::Value::Object(_)) | Ok(serde_json::Value::Null) => {
                ok(json!({ "status": "ok" }))
            }
            Ok(_) => err("config must be a JSON object"),
            Err(e) => err(format!("invalid config json: {e}")),
        }
    }

    fn healthcheck() -> schema_core_api::HealthStatus {
        ok(json!({ "status": "ok" }))
    }

    fn invoke(op: String, _input_json: Vec<u8>) -> schema_core_api::InvokeResult {
        match op.as_str() {
            "validate_policy" => ok(json!({
                "status": "ok",
                "allowed": true,
                "violations": [],
            })),
            _ => err(format!("unsupported op `{op}`")),
        }
    }
}

macro_rules! export_provider {
    ($ty:ident) => {
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#describe")]
        unsafe extern "C" fn export_describe() -> *mut u8 {
            schema_core_api::_export_describe_cabi::<$ty>()
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#describe")]
        unsafe extern "C" fn _post_return_describe(arg0: *mut u8) {
            schema_core_api::__post_return_describe::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#validate-config")]
        unsafe extern "C" fn export_validate_config(arg0: *mut u8, arg1: usize) -> *mut u8 {
            schema_core_api::_export_validate_config_cabi::<$ty>(arg0, arg1)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#validate-config")]
        unsafe extern "C" fn _post_return_validate_config(arg0: *mut u8) {
            schema_core_api::__post_return_validate_config::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#healthcheck")]
        unsafe extern "C" fn export_healthcheck() -> *mut u8 {
            schema_core_api::_export_healthcheck_cabi::<$ty>()
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#healthcheck")]
        unsafe extern "C" fn _post_return_healthcheck(arg0: *mut u8) {
            schema_core_api::__post_return_healthcheck::<$ty>(arg0)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "greentic:provider-schema-core/schema-core-api@1.0.0#invoke")]
        unsafe extern "C" fn export_invoke(
            arg0: *mut u8,
            arg1: usize,
            arg2: *mut u8,
            arg3: usize,
        ) -> *mut u8 {
            schema_core_api::_export_invoke_cabi::<$ty>(arg0, arg1, arg2, arg3)
        }
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = "cabi_post_greentic:provider-schema-core/schema-core-api@1.0.0#invoke")]
        unsafe extern "C" fn _post_return_invoke(arg0: *mut u8) {
            schema_core_api::__post_return_invoke::<$ty>(arg0)
        }
    };
}

export_provider!(PolicyValidator);
