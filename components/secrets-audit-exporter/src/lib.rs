use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

#[cfg(not(target_arch = "wasm32"))]
use greentic_interfaces::bindings::generated::greentic_provider_schema_core_1_0_0_schema_core::exports::greentic::provider_schema_core::schema_core_api;
#[cfg(target_arch = "wasm32")]
mod bindings {
    include!("../../common/schema_core_api.rs");
}
#[cfg(target_arch = "wasm32")]
use bindings::exports::greentic::provider_schema_core::schema_core_api;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

static MEMORY_EVENTS: Lazy<Mutex<HashMap<String, Vec<Value>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const SUPPORTED_SINK_TYPES: &[&str] = &["splunk", "azure", "gcp", "http", "file"];
const DEFAULT_BATCH_LIMIT: usize = 100;

pub struct AuditExporter;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Sink {
    sink_type: String,
    sink_config_ref: String,
}

#[derive(Debug, Deserialize)]
struct EmitEventInput {
    sink: Sink,
    event: Value,
}

#[derive(Debug, Deserialize)]
struct ExportBatchInput {
    sink: Sink,
    #[serde(default)]
    cursor: Option<Value>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ExportSummary {
    exported_count: usize,
    total_available: usize,
    has_more: bool,
    sink_type: String,
}

fn ok<T: Serialize>(payload: T) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap_or_else(|e| err(e.to_string()))
}

fn err(msg: impl Into<String>) -> Vec<u8> {
    serde_json::to_vec(&json!({ "status": "error", "message": msg.into() })).unwrap_or_else(|_| {
        b"{\"status\":\"error\",\"message\":\"serialization failure\"}".to_vec()
    })
}

fn sink_key(sink: &Sink) -> String {
    format!("{}::{}", sink.sink_type, sink.sink_config_ref)
}

fn parse_input<T: for<'de> Deserialize<'de>>(
    input_json: Vec<u8>,
    label: &str,
) -> Result<T, Vec<u8>> {
    serde_json::from_slice(&input_json).map_err(|e| err(format!("invalid {label} input: {e}")))
}

fn validate_sink(sink: &Sink) -> Result<(), Vec<u8>> {
    if !SUPPORTED_SINK_TYPES.contains(&sink.sink_type.as_str()) {
        return Err(err(format!(
            "unsupported sink_type `{}`; expected one of {:?}",
            sink.sink_type, SUPPORTED_SINK_TYPES
        )));
    }
    if sink.sink_config_ref.trim().is_empty() {
        return Err(err("sink_config_ref must not be empty"));
    }
    Ok(())
}

fn parse_cursor(cursor: Option<Value>) -> Result<usize, Vec<u8>> {
    match cursor {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(|v| v as usize)
            .ok_or_else(|| err("cursor number must be a non-negative integer")),
        Some(Value::String(text)) => text
            .parse::<usize>()
            .map_err(|_| err("cursor string must be a non-negative integer")),
        Some(_) => Err(err("cursor must be null, a string, or an integer")),
    }
}

fn append_memory_event(sink: &Sink, event: &Value) {
    let mut store = MEMORY_EVENTS.lock().expect("memory events lock");
    store.entry(sink_key(sink)).or_default().push(event.clone());
}

fn read_memory_events(sink: &Sink) -> Vec<Value> {
    let store = MEMORY_EVENTS.lock().expect("memory events lock");
    store.get(&sink_key(sink)).cloned().unwrap_or_default()
}

fn append_file_event(path: &str, event: &Value) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create sink directory: {e}"))?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open sink file: {e}"))?;
    serde_json::to_writer(&mut file, event).map_err(|e| format!("serialize event: {e}"))?;
    file.write_all(b"\n")
        .map_err(|e| format!("write sink file: {e}"))?;
    Ok(())
}

fn read_file_events(path: &str) -> Result<Vec<Value>, String> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("open sink file: {e}")),
    };

    let mut events = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("read sink file: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(trimmed).map_err(|e| format!("parse sink file event: {e}"))?;
        events.push(value);
    }
    Ok(events)
}

fn emit_event(input: EmitEventInput) -> Vec<u8> {
    if let Err(e) = validate_sink(&input.sink) {
        return e;
    }

    append_memory_event(&input.sink, &input.event);
    if input.sink.sink_type == "file" {
        if let Err(e) = append_file_event(&input.sink.sink_config_ref, &input.event) {
            return err(e);
        }
    }

    ok(json!({
        "status": "ok",
        "accepted": 1,
        "sink_type": input.sink.sink_type,
    }))
}

fn export_batch(input: ExportBatchInput) -> Vec<u8> {
    if let Err(e) = validate_sink(&input.sink) {
        return e;
    }

    let offset = match parse_cursor(input.cursor) {
        Ok(offset) => offset,
        Err(e) => return e,
    };
    let limit = input.limit.unwrap_or(DEFAULT_BATCH_LIMIT).max(1);

    let events = if input.sink.sink_type == "file" {
        match read_file_events(&input.sink.sink_config_ref) {
            Ok(events) => events,
            Err(e) => return err(e),
        }
    } else {
        read_memory_events(&input.sink)
    };

    let total = events.len();
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let batch = events[start..end].to_vec();
    let next_cursor = (end < total).then(|| Value::String(end.to_string()));

    ok(json!({
        "summary": ExportSummary {
            exported_count: batch.len(),
            total_available: total,
            has_more: end < total,
            sink_type: input.sink.sink_type,
        },
        "cursor": next_cursor,
        "events": batch,
    }))
}

impl schema_core_api::Guest for AuditExporter {
    fn describe() -> Vec<u8> {
        ok(json!({
            "provider_type": "audit",
            "id": "audit-exporter",
            "capabilities": ["emit_event", "export_batch"],
            "ops": ["emit_event", "export_batch"],
        }))
    }

    fn validate_config(config_json: Vec<u8>) -> schema_core_api::ValidationResult {
        match serde_json::from_slice::<Value>(&config_json) {
            Ok(Value::Object(_)) => ok(json!({ "status": "ok" })),
            Ok(_) => err("config must be a JSON object"),
            Err(e) => err(format!("invalid config json: {e}")),
        }
    }

    fn healthcheck() -> schema_core_api::HealthStatus {
        ok(json!({ "status": "ok" }))
    }

    fn invoke(op: String, input_json: Vec<u8>) -> schema_core_api::InvokeResult {
        match op.as_str() {
            "emit_event" => match parse_input::<EmitEventInput>(input_json, "emit_event") {
                Ok(input) => emit_event(input),
                Err(e) => e,
            },
            "export_batch" => match parse_input::<ExportBatchInput>(input_json, "export_batch") {
                Ok(input) => export_batch(input),
                Err(e) => e,
            },
            _ => err(format!("unsupported op `{op}`")),
        }
    }
}

#[allow(unused_macros)]
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

export_provider!(AuditExporter);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use schema_core_api::Guest;

    fn json_bytes(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("json")
    }

    fn json_value(bytes: Vec<u8>) -> Value {
        serde_json::from_slice(&bytes).expect("json")
    }

    fn file_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("/tmp/greentic-audit-exporter-{nanos}.ndjson")
    }

    #[test]
    fn emits_and_exports_memory_events() {
        let sink = json!({
            "sink_type": "http",
            "sink_config_ref": "https://audit.example.test/ingest"
        });

        let first = AuditExporter::invoke(
            "emit_event".into(),
            json_bytes(json!({
                "sink": sink,
                "event": { "kind": "SECRET_READ", "correlation_id": "c1" }
            })),
        );
        assert_eq!(
            json_value(first).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let export = AuditExporter::invoke(
            "export_batch".into(),
            json_bytes(json!({
                "sink": {
                    "sink_type": "http",
                    "sink_config_ref": "https://audit.example.test/ingest"
                },
                "cursor": null,
                "limit": 10
            })),
        );
        let export = json_value(export);
        assert_eq!(export["summary"]["exported_count"].as_u64(), Some(1));
        assert_eq!(export["events"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn persists_file_sink_events() {
        let path = file_path();
        let sink = json!({
            "sink_type": "file",
            "sink_config_ref": path
        });

        let emit = AuditExporter::invoke(
            "emit_event".into(),
            json_bytes(json!({
                "sink": sink,
                "event": { "kind": "PROVIDER_VALIDATED", "status": "OK" }
            })),
        );
        assert_eq!(
            json_value(emit).get("status").and_then(|v| v.as_str()),
            Some("ok")
        );

        let export = AuditExporter::invoke(
            "export_batch".into(),
            json_bytes(json!({
                "sink": {
                    "sink_type": "file",
                    "sink_config_ref": path
                },
                "cursor": 0,
                "limit": 10
            })),
        );
        let export = json_value(export);
        assert_eq!(export["summary"]["exported_count"].as_u64(), Some(1));

        let _ = fs::remove_file(path);
    }
}
