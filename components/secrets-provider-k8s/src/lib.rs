use base64::{engine::general_purpose, Engine};
#[cfg(target_arch = "wasm32")]
mod bindings {
    include!("../../common/schema_core_api.rs");
}
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

fn to_bytes(val: Value) -> Result<Vec<u8>, String> {
    match val {
        Value::String(s) => match general_purpose::STANDARD.decode(&s) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Ok(s.into_bytes()),
        },
        Value::Array(arr) => {
            let mut out = Vec::new();
            for v in arr {
                out.push(
                    v.as_u64()
                        .ok_or_else(|| "array must contain bytes".to_string())?
                        as u8,
                );
            }
            Ok(out)
        }
        _ => Err("value must be string (b64 or utf8) or byte array".to_string()),
    }
}

fn from_bytes(bytes: &[u8]) -> Value {
    Value::String(general_purpose::STANDARD.encode(bytes))
}

fn ok<T: Serialize>(payload: T) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap_or_else(|e| err(e.to_string()))
}

fn err(msg: impl Into<String>) -> Vec<u8> {
    ok(serde_json::json!({ "status": "error", "message": msg.into() }))
}

pub struct Provider;

#[cfg(not(target_arch = "wasm32"))]
mod host {
    use super::*;
    use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
    use kube::{api::Api, Client, Config as KubeConfig};
    use once_cell::sync::{Lazy, OnceCell};
    use serde::Deserialize;
    use tokio::runtime::Runtime;

    #[derive(Deserialize, Clone, Default)]
    struct Config {
        namespace: String,
        #[serde(default)]
        context: Option<String>,
        #[serde(default)]
        kubeconfig: Option<String>,
    }

    #[derive(Deserialize)]
    struct PutInput {
        key: String,
        value: Value,
    }

    #[derive(Deserialize)]
    struct KeyInput {
        key: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[allow(dead_code)]
    struct SecretData {
        #[serde(flatten)]
        data: HashMap<String, String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[allow(dead_code)]
    #[allow(non_snake_case)]
    struct Secret {
        apiVersion: String,
        kind: String,
        metadata: Metadata,
        data: Option<HashMap<String, String>>,
        stringData: Option<HashMap<String, String>>,
        #[serde(rename = "type")]
        type_field: Option<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[allow(dead_code)]
    struct Metadata {
        name: String,
        namespace: String,
    }

    struct K8sCtx {
        rt: Runtime,
        client: Client,
        namespace: String,
    }

    static CTX: OnceCell<K8sCtx> = OnceCell::new();
    static FAKE: Lazy<bool> =
        Lazy::new(|| std::env::var("GREENTIC_K8S_FAKE").is_ok() || cfg!(test));
    static STORE: Lazy<Mutex<HashMap<String, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    fn client_from_config(cfg: Config) -> Result<K8sCtx, String> {
        let rt = Runtime::new().map_err(|e| format!("runtime init: {e}"))?;
        let ns = cfg.namespace.clone();
        let client = rt.block_on(async move {
            if let Some(path) = &cfg.kubeconfig {
                std::env::set_var("KUBECONFIG", path);
            }
            let opts = kube::config::KubeConfigOptions {
                context: cfg.context.clone(),
                ..Default::default()
            };
            let kube_config = KubeConfig::from_kubeconfig(&opts)
                .await
                .map_err(|e| format!("kubeconfig: {e}"))?;
            Client::try_from(kube_config).map_err(|e| format!("kube client: {e}"))
        })?;
        Ok(K8sCtx {
            rt,
            client,
            namespace: ns,
        })
    }

    fn ctx(cfg_json: &[u8]) -> Result<&'static K8sCtx, String> {
        CTX.get_or_try_init(|| {
            let cfg: Config =
                serde_json::from_slice(cfg_json).map_err(|e| format!("config parse: {e}"))?;
            client_from_config(cfg)
        })
        .map_err(|e| e.to_string())
    }

    fn handle_put(ctx: Option<&K8sCtx>, key: String, value: Value) -> Vec<u8> {
        let bytes = match to_bytes(value) {
            Ok(b) => b,
            Err(e) => return err(e),
        };
        if *FAKE {
            let mut store = STORE.lock().expect("store lock");
            store.insert(key, bytes);
            return ok(serde_json::json!({ "status": "ok" }));
        }
        let ctx = match ctx {
            Some(c) => c,
            None => return err("context unavailable"),
        };
        let client = ctx.client.clone();
        let namespace = ctx.namespace.clone();
        let res = ctx.rt.block_on(async move {
            let api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client, &namespace);
            let mut data = std::collections::BTreeMap::new();
            data.insert(key.clone(), general_purpose::STANDARD.encode(bytes));
            let secret = k8s_openapi::api::core::v1::Secret {
                metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                    name: Some(key.clone()),
                    ..Default::default()
                },
                data: None,
                string_data: Some(data),
                type_: Some("Opaque".to_string()),
                ..Default::default()
            };
            match api
                .patch(
                    &key,
                    &kube::api::PatchParams::apply("greentic").force(),
                    &kube::api::Patch::Apply(&secret),
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("{e}")),
            }
        });
        match res {
            Ok(_) => ok(serde_json::json!({ "status": "ok" })),
            Err(e) => err(e),
        }
    }

    fn handle_get(ctx: Option<&K8sCtx>, key: String) -> Vec<u8> {
        if *FAKE {
            let store = STORE.lock().expect("store lock");
            let val = match store.get(&key) {
                Some(v) => v,
                None => return err("not found"),
            };
            return ok(serde_json::json!({ "value": from_bytes(val) }));
        }
        let ctx = match ctx {
            Some(c) => c,
            None => return err("context unavailable"),
        };
        let client = ctx.client.clone();
        let namespace = ctx.namespace.clone();
        let res = ctx.rt.block_on(async move {
            let api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client, &namespace);
            let sec = api.get(&key).await.map_err(|e| format!("{e}"))?;
            if let Some(data) = sec.string_data {
                if let Some(val) = data.get(&key) {
                    return general_purpose::STANDARD
                        .decode(val.as_bytes())
                        .or_else(|_e: base64::DecodeError| Ok(val.as_bytes().to_vec()))
                        .map_err(|e: base64::DecodeError| format!("{e}"));
                }
            }
            if let Some(data) = sec.data {
                if let Some(val) = data.get(&key) {
                    return Ok(val.0.clone());
                }
            }
            Err("not found".to_string())
        });
        match res {
            Ok(b) => ok(serde_json::json!({ "value": from_bytes(&b) })),
            Err(e) => err(e),
        }
    }

    fn handle_delete(ctx: Option<&K8sCtx>, key: String) -> Vec<u8> {
        if *FAKE {
            let mut store = STORE.lock().expect("store lock");
            store.remove(&key);
            return ok(serde_json::json!({ "status": "ok" }));
        }
        let ctx = match ctx {
            Some(c) => c,
            None => return err("context unavailable"),
        };
        let client = ctx.client.clone();
        let namespace = ctx.namespace.clone();
        let res = ctx.rt.block_on(async move {
            let api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client, &namespace);
            api.delete(&key, &Default::default())
                .await
                .map_err(|e| format!("{e}"))
                .map(|_| ())
        });
        match res {
            Ok(_) => ok(serde_json::json!({ "status": "ok" })),
            Err(e) => err(e),
        }
    }

    impl schema_core_api::Guest for Provider {
        fn describe() -> Vec<u8> {
            ok(serde_json::json!({
                "provider_type": "secrets",
                "id": "k8s",
                "capabilities": ["get", "put", "delete"],
                "ops": ["get", "put", "delete"]
            }))
        }

        fn validate_config(config_json: Vec<u8>) -> schema_core_api::ValidationResult {
            if serde_json::from_slice::<Config>(&config_json).is_err() {
                return err("invalid config json");
            }
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn healthcheck() -> schema_core_api::HealthStatus {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn invoke(op: String, input_json: Vec<u8>) -> schema_core_api::InvokeResult {
            let parsed: serde_json::Value = match serde_json::from_slice(&input_json) {
                Ok(v) => v,
                Err(e) => return err(format!("invalid input json: {e}")),
            };
            let ctx = if *FAKE {
                None
            } else {
                match ctx(&input_json) {
                    Ok(c) => Some(c),
                    Err(e) => return err(e),
                }
            };
            match op.as_str() {
                "put" => {
                    let input: PutInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid put input: {e}")),
                    };
                    handle_put(ctx, input.key, input.value)
                }
                "get" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid get input: {e}")),
                    };
                    handle_get(ctx, input.key)
                }
                "delete" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid delete input: {e}")),
                    };
                    handle_delete(ctx, input.key)
                }
                _ => err("unsupported op"),
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    #[allow(unused_imports)]
    use bindings::exports::greentic::provider_schema_core::schema_core_api;
    use once_cell::sync::Lazy;

    #[derive(Deserialize)]
    struct PutInput {
        key: String,
        value: Value,
    }

    #[derive(Deserialize)]
    struct KeyInput {
        key: String,
    }

    static STORE: Lazy<Mutex<HashMap<String, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    impl schema_core_api::Guest for Provider {
        fn describe() -> Vec<u8> {
            ok(serde_json::json!({
                "provider_type": "secrets",
                "id": "k8s",
                "capabilities": ["get", "put", "delete"],
                "ops": ["get", "put", "delete"]
            }))
        }

        fn validate_config(_config_json: Vec<u8>) -> schema_core_api::ValidationResult {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn healthcheck() -> schema_core_api::HealthStatus {
            ok(serde_json::json!({ "status": "ok" }))
        }

        fn invoke(op: String, input_json: Vec<u8>) -> schema_core_api::InvokeResult {
            let parsed: serde_json::Value = match serde_json::from_slice(&input_json) {
                Ok(v) => v,
                Err(e) => return err(format!("invalid input json: {e}")),
            };
            match op.as_str() {
                "put" => {
                    let input: PutInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid put input: {e}")),
                    };
                    let bytes = match to_bytes(input.value) {
                        Ok(b) => b,
                        Err(e) => return err(e),
                    };
                    let mut store = STORE.lock().expect("store lock");
                    store.insert(input.key, bytes);
                    ok(serde_json::json!({ "status": "ok" }))
                }
                "get" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid get input: {e}")),
                    };
                    let store = STORE.lock().expect("store lock");
                    let val = match store.get(&input.key) {
                        Some(v) => v,
                        None => return err("not found"),
                    };
                    ok(serde_json::json!({ "value": from_bytes(val) }))
                }
                "delete" => {
                    let input: KeyInput = match serde_json::from_value(parsed) {
                        Ok(v) => v,
                        Err(e) => return err(format!("invalid delete input: {e}")),
                    };
                    let mut store = STORE.lock().expect("store lock");
                    store.remove(&input.key);
                    ok(serde_json::json!({ "status": "ok" }))
                }
                _ => err("unsupported op"),
            }
        }
    }

    schema_core_api::__export_greentic_provider_schema_core_schema_core_api_1_0_0_cabi!(Provider with_types_in bindings::exports::greentic::provider_schema_core::schema_core_api);
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
    use schema_core_api::Guest;

    fn json_bytes(val: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&val).expect("json")
    }

    fn as_json(bytes: Vec<u8>) -> serde_json::Value {
        serde_json::from_slice(&bytes).expect("json")
    }

    #[test]
    fn roundtrip_put_get_delete() {
        std::env::set_var("GREENTIC_K8S_FAKE", "1");
        let meta = as_json(Provider::describe());
        assert_eq!(
            meta.get("provider_type").and_then(|v| v.as_str()),
            Some("secrets")
        );

        let validated = Provider::validate_config(
            serde_json::to_vec(&serde_json::json!({"namespace": "default"})).unwrap(),
        );
        assert_eq!(
            as_json(validated).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let put = Provider::invoke(
            "put".into(),
            json_bytes(serde_json::json!({"key": "k1", "value": "secret"})),
        );
        assert_eq!(
            as_json(put).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let get = Provider::invoke("get".into(), json_bytes(serde_json::json!({"key": "k1"})));
        let get_json = as_json(get);
        let val_b64 = get_json
            .get("value")
            .and_then(|v| v.as_str())
            .expect("value");
        let decoded = general_purpose::STANDARD
            .decode(val_b64)
            .unwrap_or_default();
        assert!(!decoded.is_empty());

        let del = Provider::invoke(
            "delete".into(),
            json_bytes(serde_json::json!({"key": "k1"})),
        );
        assert_eq!(
            as_json(del).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );
    }
}
