//! MCP tool schema rewriter.
//!
//! Rewrites JSON Schema for MCP tool inputs:
//! - Strips named parameters from schemas (removing from `properties` and `required`)
//! - Strips parameters matching glob patterns at any nesting depth
//! - Applies parameter constraints (maximum, maxLength, maxItems, etc.)
//! - Handles nested schemas (objects within objects)
//!
//! This is proactive defense — the agent cannot construct tool calls with blocked
//! parameters because those parameters are absent from the schema it receives.
//!
//! See `docs/architecture.md` section 8.9 for design context.

use serde_json::Value;
use steward_types::config::{ParamConstraint, SchemaRewriteConfig};

/// Rewrites a JSON Schema by applying strip and constraint rules.
///
/// Takes a JSON Schema `Value` and a `SchemaRewriteConfig`, then:
/// 1. Removes all properties listed in `strip_params` from the schema's `properties`
///    and from the `required` array.
/// 2. Applies constraints from `constrain_params` to matching properties by setting
///    JSON Schema keywords (maximum, maxLength, maxItems, etc.).
///
/// Returns a new `Value` with the rewrites applied. The original is not modified.
pub fn rewrite_schema(schema: &Value, rewrites: &SchemaRewriteConfig) -> Value {
    let mut schema = schema.clone();

    // Strip named parameters
    for param in &rewrites.strip_params {
        strip_property(&mut schema, param);
    }

    // Apply constraints
    for (param_name, constraint) in &rewrites.constrain_params {
        apply_constraint(&mut schema, param_name, constraint);
    }

    schema
}

/// Removes all properties matching glob patterns from a JSON Schema.
///
/// Patterns use a simple glob syntax:
/// - `"*.bcc"` matches any property named `"bcc"` at any depth.
/// - `"arguments.forward_to"` matches the exact path `arguments` → `forward_to`.
///
/// Properties are removed from both `properties` and `required`.
pub fn strip_blocked_params(schema: &Value, patterns: &[String]) -> Value {
    let mut schema = schema.clone();

    for pattern in patterns {
        strip_by_pattern(&mut schema, pattern, "");
    }

    schema
}

/// Removes a named property from the top-level `properties` object and `required` array.
fn strip_property(schema: &mut Value, name: &str) {
    if let Some(obj) = schema.as_object_mut() {
        // Remove from properties
        if let Some(Value::Object(props)) = obj.get_mut("properties") {
            props.remove(name);
        }

        // Remove from required array
        if let Some(Value::Array(required)) = obj.get_mut("required") {
            required.retain(|v| v.as_str() != Some(name));
        }
    }
}

/// Applies a `ParamConstraint` to a named property in the schema.
///
/// Finds the property in `properties` and merges constraint keywords into it.
fn apply_constraint(schema: &mut Value, name: &str, constraint: &ParamConstraint) {
    let prop_schema = match schema
        .as_object_mut()
        .and_then(|obj| obj.get_mut("properties"))
        .and_then(|props| props.as_object_mut())
        .and_then(|props| props.get_mut(name))
    {
        Some(s) => s,
        None => return,
    };

    let prop_obj = match prop_schema.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    if let Some(v) = constraint.maximum {
        prop_obj.insert("maximum".to_string(), Value::from(v));
    }
    if let Some(v) = constraint.minimum {
        prop_obj.insert("minimum".to_string(), Value::from(v));
    }
    if let Some(v) = constraint.max_length {
        prop_obj.insert("maxLength".to_string(), Value::from(v));
    }
    if let Some(v) = constraint.min_length {
        prop_obj.insert("minLength".to_string(), Value::from(v));
    }
    if let Some(v) = constraint.max_items {
        prop_obj.insert("maxItems".to_string(), Value::from(v));
    }
    if let Some(v) = constraint.min_items {
        prop_obj.insert("minItems".to_string(), Value::from(v));
    }
    if let Some(ref v) = constraint.pattern {
        prop_obj.insert("pattern".to_string(), Value::from(v.clone()));
    }
}

/// Recursively strips properties matching a glob pattern.
///
/// `current_path` tracks the dotted path to the current schema level for
/// exact-path matching (e.g., `"arguments.forward_to"`).
fn strip_by_pattern(schema: &mut Value, pattern: &str, current_path: &str) {
    if !schema.is_object() {
        return;
    }

    // Phase 1: Collect property names to strip at this level.
    // We read `properties` immutably first to figure out which keys match.
    let props_to_strip: Vec<String> = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| {
            props
                .keys()
                .filter(|prop_name| {
                    let full_path = if current_path.is_empty() {
                        (*prop_name).to_string()
                    } else {
                        format!("{current_path}.{prop_name}")
                    };
                    matches_glob(pattern, prop_name, &full_path)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    // Phase 2: Strip matched properties (borrows schema mutably, then releases).
    for name in &props_to_strip {
        strip_property(schema, name);
    }

    // Phase 3: Collect keys of remaining properties for recursion.
    let remaining_keys: Vec<String> = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default();

    // Phase 4: Recurse into nested object properties.
    for key in remaining_keys {
        let nested_path = if current_path.is_empty() {
            key.clone()
        } else {
            format!("{current_path}.{key}")
        };
        // Temporarily take the property value out, recurse, then put it back.
        if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
            if let Some(mut prop_schema) = props.remove(&key) {
                strip_by_pattern(&mut prop_schema, pattern, &nested_path);
                // Also recurse into `items` for array-type properties.
                if let Some(items) = prop_schema.get_mut("items") {
                    strip_by_pattern(items, pattern, &nested_path);
                }
                props.insert(key, prop_schema);
            }
        }
    }

    // Phase 5: If this schema itself has `items` (top-level array schema),
    // recurse into it.
    if let Some(mut items) = schema.as_object_mut().and_then(|o| o.remove("items")) {
        strip_by_pattern(&mut items, pattern, current_path);
        schema
            .as_object_mut()
            .unwrap()
            .insert("items".to_string(), items);
    }
}

/// Checks whether a property matches a glob pattern.
///
/// - `"*.name"` matches any property called `"name"` at any depth (wildcard prefix).
/// - `"foo.bar"` matches the exact dotted path `"foo.bar"`.
fn matches_glob(pattern: &str, prop_name: &str, full_path: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: match property name at any depth
        prop_name == suffix
    } else {
        // Exact path match
        full_path == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    // ── Helper ──────────────────────────────────────────────

    fn gmail_send_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "to": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Recipient email addresses"
                },
                "cc": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "CC recipients"
                },
                "bcc": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "BCC recipients"
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject"
                },
                "body": {
                    "type": "string",
                    "description": "Email body"
                },
                "forward_to": {
                    "type": "string",
                    "description": "Auto-forward address"
                },
                "attachments": {
                    "type": "array",
                    "items": { "type": "object" },
                    "description": "File attachments"
                }
            },
            "required": ["to", "subject", "body"]
        })
    }

    fn calendar_create_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Event title"
                },
                "start_time": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Start time in ISO 8601"
                },
                "end_time": {
                    "type": "string",
                    "format": "date-time",
                    "description": "End time in ISO 8601"
                },
                "attendees": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "email": { "type": "string" },
                            "bcc": { "type": "string" },
                            "name": { "type": "string" }
                        },
                        "required": ["email"]
                    },
                    "description": "Event attendees"
                },
                "location": {
                    "type": "string",
                    "description": "Event location"
                },
                "description": {
                    "type": "string",
                    "description": "Event description"
                },
                "reminders": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "description": "Reminder offsets in minutes"
                }
            },
            "required": ["title", "start_time", "end_time"]
        })
    }

    // ── Test: strip single property from flat schema ────────

    #[test]
    fn test_strip_single_property() {
        let schema = gmail_send_schema();
        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["bcc".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);

        let props = result["properties"].as_object().unwrap();
        assert!(!props.contains_key("bcc"), "bcc should be stripped");
        assert!(props.contains_key("to"), "to should remain");
        assert!(props.contains_key("subject"), "subject should remain");
        assert!(props.contains_key("body"), "body should remain");
    }

    // ── Test: strip multiple properties ─────────────────────

    #[test]
    fn test_strip_multiple_properties() {
        let schema = gmail_send_schema();
        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["bcc".to_string(), "forward_to".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);

        let props = result["properties"].as_object().unwrap();
        assert!(!props.contains_key("bcc"));
        assert!(!props.contains_key("forward_to"));
        assert!(props.contains_key("to"));
        assert!(props.contains_key("subject"));
    }

    // ── Test: required array updated when property stripped ──

    #[test]
    fn test_required_updated_on_strip() {
        let mut schema = gmail_send_schema();
        // Add "bcc" to required so we can verify it gets removed
        schema["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("bcc"));

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["bcc".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);

        let required: Vec<&str> = result["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        assert!(
            !required.contains(&"bcc"),
            "bcc should be removed from required"
        );
        assert!(required.contains(&"to"), "to should remain in required");
        assert!(
            required.contains(&"subject"),
            "subject should remain in required"
        );
        assert!(required.contains(&"body"), "body should remain in required");
    }

    // ── Test: strip from nested schema ──────────────────────

    #[test]
    fn test_strip_from_nested_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "message": {
                    "type": "object",
                    "properties": {
                        "to": { "type": "string" },
                        "bcc": { "type": "string" },
                        "body": { "type": "string" }
                    },
                    "required": ["to", "body", "bcc"]
                }
            },
            "required": ["message"]
        });

        let result = strip_blocked_params(&schema, &["message.bcc".to_string()]);

        let nested = &result["properties"]["message"];
        let nested_props = nested["properties"].as_object().unwrap();
        assert!(
            !nested_props.contains_key("bcc"),
            "nested bcc should be stripped"
        );
        assert!(nested_props.contains_key("to"), "nested to should remain");
        assert!(
            nested_props.contains_key("body"),
            "nested body should remain"
        );

        // Verify required is updated in the nested schema
        let nested_required: Vec<&str> = nested["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!nested_required.contains(&"bcc"));
        assert!(nested_required.contains(&"to"));
        assert!(nested_required.contains(&"body"));
    }

    // ── Test: glob pattern matching at multiple depths ──────

    #[test]
    fn test_glob_pattern_any_depth() {
        let schema = json!({
            "type": "object",
            "properties": {
                "bcc": { "type": "string" },
                "message": {
                    "type": "object",
                    "properties": {
                        "bcc": { "type": "string" },
                        "subject": { "type": "string" }
                    },
                    "required": ["bcc", "subject"]
                }
            },
            "required": ["bcc", "message"]
        });

        let result = strip_blocked_params(&schema, &["*.bcc".to_string()]);

        // Top-level bcc stripped
        let top_props = result["properties"].as_object().unwrap();
        assert!(
            !top_props.contains_key("bcc"),
            "top-level bcc should be stripped"
        );
        assert!(top_props.contains_key("message"), "message should remain");

        // Nested bcc stripped
        let nested_props = result["properties"]["message"]["properties"]
            .as_object()
            .unwrap();
        assert!(
            !nested_props.contains_key("bcc"),
            "nested bcc should be stripped"
        );
        assert!(
            nested_props.contains_key("subject"),
            "subject should remain"
        );

        // Required arrays updated at both levels
        let top_required: Vec<&str> = result["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!top_required.contains(&"bcc"));
        assert!(top_required.contains(&"message"));

        let nested_required: Vec<&str> = result["properties"]["message"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!nested_required.contains(&"bcc"));
        assert!(nested_required.contains(&"subject"));
    }

    // ── Test: exact path match doesn't strip wrong level ────

    #[test]
    fn test_exact_path_match_only() {
        let schema = json!({
            "type": "object",
            "properties": {
                "forward_to": { "type": "string" },
                "nested": {
                    "type": "object",
                    "properties": {
                        "forward_to": { "type": "string" }
                    }
                }
            }
        });

        // Only strip the nested one
        let result = strip_blocked_params(&schema, &["nested.forward_to".to_string()]);

        let top_props = result["properties"].as_object().unwrap();
        assert!(
            top_props.contains_key("forward_to"),
            "top-level forward_to should remain"
        );

        let nested_props = result["properties"]["nested"]["properties"]
            .as_object()
            .unwrap();
        assert!(
            !nested_props.contains_key("forward_to"),
            "nested forward_to should be stripped"
        );
    }

    // ── Test: constraint application ────────────────────────

    #[test]
    fn test_apply_maximum_constraint() {
        let schema = json!({
            "type": "object",
            "properties": {
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return"
                }
            }
        });

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "max_results".to_string(),
            ParamConstraint {
                maximum: Some(50.0),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(result["properties"]["max_results"]["maximum"], json!(50.0));
        // Original fields preserved
        assert_eq!(
            result["properties"]["max_results"]["type"],
            json!("integer")
        );
    }

    #[test]
    fn test_apply_max_items_constraint() {
        let schema = gmail_send_schema();

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "to".to_string(),
            ParamConstraint {
                max_items: Some(5),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(result["properties"]["to"]["maxItems"], json!(5));
        assert_eq!(result["properties"]["to"]["type"], json!("array"));
    }

    #[test]
    fn test_apply_max_length_constraint() {
        let schema = gmail_send_schema();

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "subject".to_string(),
            ParamConstraint {
                max_length: Some(200),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(result["properties"]["subject"]["maxLength"], json!(200));
        assert_eq!(result["properties"]["subject"]["type"], json!("string"));
    }

    #[test]
    fn test_apply_multiple_constraints_to_one_property() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "description": "Item count"
                }
            }
        });

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "count".to_string(),
            ParamConstraint {
                minimum: Some(1.0),
                maximum: Some(100.0),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(result["properties"]["count"]["minimum"], json!(1.0));
        assert_eq!(result["properties"]["count"]["maximum"], json!(100.0));
    }

    #[test]
    fn test_apply_pattern_constraint() {
        let schema = json!({
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "Email address"
                }
            }
        });

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "email".to_string(),
            ParamConstraint {
                pattern: Some(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(
            result["properties"]["email"]["pattern"],
            json!(r"^[^@]+@[^@]+\.[^@]+$")
        );
    }

    // ── Test: empty schema remains valid ────────────────────

    #[test]
    fn test_empty_schema_remains_valid() {
        let schema = json!({});

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["nonexistent".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);
        assert_eq!(result, json!({}));

        let result2 = strip_blocked_params(&schema, &["*.bcc".to_string()]);
        assert_eq!(result2, json!({}));
    }

    #[test]
    fn test_schema_with_no_properties_key() {
        let schema = json!({
            "type": "object"
        });

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["anything".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);
        assert_eq!(result["type"], json!("object"));
    }

    // ── Test: strip + constrain combined ────────────────────

    #[test]
    fn test_strip_and_constrain_combined() {
        let schema = gmail_send_schema();

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "to".to_string(),
            ParamConstraint {
                max_items: Some(5),
                ..Default::default()
            },
        );
        constrain_params.insert(
            "attachments".to_string(),
            ParamConstraint {
                max_items: Some(10),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["bcc".to_string(), "forward_to".to_string()],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        let props = result["properties"].as_object().unwrap();
        assert!(!props.contains_key("bcc"));
        assert!(!props.contains_key("forward_to"));
        assert_eq!(result["properties"]["to"]["maxItems"], json!(5));
        assert_eq!(result["properties"]["attachments"]["maxItems"], json!(10));
    }

    // ── Test: constraint on nonexistent property is no-op ───

    #[test]
    fn test_constraint_on_missing_property_is_noop() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "nonexistent".to_string(),
            ParamConstraint {
                maximum: Some(10.0),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        // Schema unchanged — no "nonexistent" property added
        let props = result["properties"].as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(!props.contains_key("nonexistent"));
    }

    // ── Test: real-world Gmail send schema ───────────────────

    #[test]
    fn test_real_world_gmail_send_schema() {
        let schema = gmail_send_schema();

        // Simulate the manifest from architecture doc section 8.9
        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "to".to_string(),
            ParamConstraint {
                max_items: Some(5),
                ..Default::default()
            },
        );
        constrain_params.insert(
            "attachments".to_string(),
            ParamConstraint {
                max_items: Some(10),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["bcc".to_string(), "forward_to".to_string()],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        // Blocked params gone
        let props = result["properties"].as_object().unwrap();
        assert!(!props.contains_key("bcc"));
        assert!(!props.contains_key("forward_to"));

        // Constraints applied
        assert_eq!(result["properties"]["to"]["maxItems"], json!(5));
        assert_eq!(result["properties"]["attachments"]["maxItems"], json!(10));

        // Other properties intact
        assert!(props.contains_key("to"));
        assert!(props.contains_key("cc"));
        assert!(props.contains_key("subject"));
        assert!(props.contains_key("body"));
        assert!(props.contains_key("attachments"));

        // Required still valid
        let required: Vec<&str> = result["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(required.contains(&"to"));
        assert!(required.contains(&"subject"));
        assert!(required.contains(&"body"));
    }

    // ── Test: real-world Calendar create schema ─────────────

    #[test]
    fn test_real_world_calendar_create_schema() {
        let schema = calendar_create_schema();

        let mut constrain_params = HashMap::new();
        constrain_params.insert(
            "attendees".to_string(),
            ParamConstraint {
                max_items: Some(20),
                ..Default::default()
            },
        );
        constrain_params.insert(
            "description".to_string(),
            ParamConstraint {
                max_length: Some(5000),
                ..Default::default()
            },
        );
        constrain_params.insert(
            "reminders".to_string(),
            ParamConstraint {
                max_items: Some(5),
                ..Default::default()
            },
        );

        let rewrites = SchemaRewriteConfig {
            strip_params: vec![],
            constrain_params,
        };

        let result = rewrite_schema(&schema, &rewrites);

        assert_eq!(result["properties"]["attendees"]["maxItems"], json!(20));
        assert_eq!(
            result["properties"]["description"]["maxLength"],
            json!(5000)
        );
        assert_eq!(result["properties"]["reminders"]["maxItems"], json!(5));

        // Verify schema structure is preserved
        assert_eq!(result["properties"]["title"]["type"], json!("string"));
        assert_eq!(
            result["properties"]["start_time"]["format"],
            json!("date-time")
        );

        // Also test glob stripping on calendar — strip bcc from nested attendee schema
        let result2 = strip_blocked_params(&result, &["*.bcc".to_string()]);

        let attendee_items = &result2["properties"]["attendees"]["items"];
        let attendee_props = attendee_items["properties"].as_object().unwrap();
        assert!(
            !attendee_props.contains_key("bcc"),
            "bcc should be stripped from nested attendee schema"
        );
        assert!(attendee_props.contains_key("email"));
        assert!(attendee_props.contains_key("name"));
    }

    // ── Test: glob strips from deeply nested schemas ────────

    #[test]
    fn test_glob_deeply_nested() {
        let schema = json!({
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": {
                            "type": "object",
                            "properties": {
                                "secret": { "type": "string" },
                                "name": { "type": "string" }
                            },
                            "required": ["secret", "name"]
                        }
                    }
                }
            }
        });

        let result = strip_blocked_params(&schema, &["*.secret".to_string()]);

        let deep_props = result["properties"]["level1"]["properties"]["level2"]["properties"]
            .as_object()
            .unwrap();
        assert!(!deep_props.contains_key("secret"));
        assert!(deep_props.contains_key("name"));

        let deep_required: Vec<&str> = result["properties"]["level1"]["properties"]["level2"]
            ["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!deep_required.contains(&"secret"));
        assert!(deep_required.contains(&"name"));
    }

    // ── Test: multiple glob patterns applied together ────────

    #[test]
    fn test_multiple_glob_patterns() {
        let schema = json!({
            "type": "object",
            "properties": {
                "bcc": { "type": "string" },
                "forward_to": { "type": "string" },
                "to": { "type": "string" },
                "subject": { "type": "string" }
            },
            "required": ["to", "subject"]
        });

        let result =
            strip_blocked_params(&schema, &["*.bcc".to_string(), "*.forward_to".to_string()]);

        let props = result["properties"].as_object().unwrap();
        assert!(!props.contains_key("bcc"));
        assert!(!props.contains_key("forward_to"));
        assert!(props.contains_key("to"));
        assert!(props.contains_key("subject"));
    }

    // ── Test: non-object schema is returned as-is ───────────

    #[test]
    fn test_non_object_schema_passthrough() {
        let schema = json!("not an object");

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["x".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);
        assert_eq!(result, json!("not an object"));

        let result2 = strip_blocked_params(&schema, &["*.x".to_string()]);
        assert_eq!(result2, json!("not an object"));
    }

    // ── Test: stripping nonexistent property is harmless ────

    #[test]
    fn test_strip_nonexistent_property() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            },
            "required": ["name"]
        });

        let rewrites = SchemaRewriteConfig {
            strip_params: vec!["does_not_exist".to_string()],
            constrain_params: HashMap::new(),
        };

        let result = rewrite_schema(&schema, &rewrites);

        let props = result["properties"].as_object().unwrap();
        assert!(props.contains_key("name"));

        let required: Vec<&str> = result["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(required.contains(&"name"));
    }
}
