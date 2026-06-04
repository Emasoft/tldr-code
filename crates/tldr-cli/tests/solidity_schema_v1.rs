//! solidity-schema-v1 (v0.5.0 SOL-002)
//!
//! Schema extensions to accommodate Solidity-unique constructs:
//!
//! 1. `ClassInfo.kind: Option<String>` — distinguishes "contract" vs
//!    "interface" vs "library". Optional + `skip_serializing_if =
//!    Option::is_none` so non-Solidity classes do not gain a null
//!    `kind` field. Backwards-compatible for all existing JSON
//!    consumers.
//!
//! 2. `ModifierInfo` — Solidity's `modifier onlyOwner() { ... }`
//!    declaration. Modifiers are NOT callable; they wrap function
//!    bodies via name reference on the function decl
//!    (`function withdraw() onlyOwner { ... }`). Distinct from
//!    `FunctionInfo` because of this non-callable semantics + the
//!    body-present flag (`_;` placeholder etc.).
//!
//! 3. `EventInfo` — Solidity's `event Transfer(address indexed
//!    from, address indexed to, uint256 value)`. Each param carries
//!    an `indexed: bool` flag (max 3 indexed per event); fully
//!    captured here for downstream taint/security tooling.
//!
//! 4. `ErrorInfo` — Solidity 0.8.4+ custom errors. `error
//!    InsufficientBalance(uint256 available, uint256 requested);`.
//!    Distinct from `revert(string)` since custom errors are typed
//!    + gas-efficient + extracted into the ABI.
//!
//! 5. `ModuleInfo` AND `ClassInfo` each get `modifiers`, `events`,
//!    `errors` vec fields — Solidity allows all three at both
//!    file-scope (free) and contract-scope (member). Both fields
//!    are `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
//!    so non-Solidity output is unchanged.
//!
//! ## Backwards-compat invariants verified
//!
//! - `ClassInfo { kind: None, ... }` does NOT emit a `"kind"` key.
//! - `ModuleInfo { modifiers: vec![], events: vec![], errors:
//!   vec![] }` does NOT emit any of those keys.
//! - All existing fields keep their canonical position + ordering
//!   in the custom `Serialize` impl.

use serde_json::{json, Value};
use std::path::PathBuf;
use tldr_core::types::{
    ClassInfo, ErrorInfo, EventInfo, EventParamInfo, FunctionInfo, IntraFileCallGraph, Language,
    ModifierInfo, ModuleInfo, ParamInfo,
};

// =============================================================================
// ClassInfo.kind — Solidity contract/interface/library distinction
// =============================================================================

#[test]
fn classinfo_default_kind_is_none() {
    let ci = ClassInfo {
        name: "Foo".to_string(),
        bases: vec![],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 1,
        line_end: 5,
        kind: None,
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    assert!(ci.kind.is_none());
}

#[test]
fn classinfo_kind_none_omits_field_in_json() {
    let ci = ClassInfo {
        name: "Foo".to_string(),
        bases: vec![],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 1,
        line_end: 5,
        kind: None,
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&ci).unwrap();
    assert!(
        v.get("kind").is_none(),
        "ClassInfo with kind=None must NOT emit a `kind` field (skip_serializing_if), got: {v}"
    );
}

#[test]
fn classinfo_kind_contract_serializes() {
    let ci = ClassInfo {
        name: "ERC20".to_string(),
        bases: vec!["IERC20".to_string()],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 10,
        line_end: 100,
        kind: Some("contract".to_string()),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&ci).unwrap();
    assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("contract"));
}

#[test]
fn classinfo_kind_interface_serializes() {
    let ci = ClassInfo {
        name: "IERC20".to_string(),
        bases: vec![],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 5,
        line_end: 30,
        kind: Some("interface".to_string()),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&ci).unwrap();
    assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("interface"));
}

#[test]
fn classinfo_kind_library_serializes() {
    let ci = ClassInfo {
        name: "SafeMath".to_string(),
        bases: vec![],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 1,
        line_end: 50,
        kind: Some("library".to_string()),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&ci).unwrap();
    assert_eq!(v.get("kind").and_then(|x| x.as_str()), Some("library"));
}

#[test]
fn classinfo_kind_roundtrips_via_json() {
    let ci = ClassInfo {
        name: "ERC20".to_string(),
        bases: vec!["IERC20".to_string()],
        docstring: Some("ERC20 token implementation.".to_string()),
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 10,
        line_end: 100,
        kind: Some("contract".to_string()),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let s = serde_json::to_string(&ci).unwrap();
    let back: ClassInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "ERC20");
    assert_eq!(back.kind.as_deref(), Some("contract"));
    assert_eq!(back.bases, vec!["IERC20".to_string()]);
}

// =============================================================================
// ModifierInfo — Solidity `modifier onlyOwner { _; }`
// =============================================================================

#[test]
fn modifierinfo_construction_and_json_roundtrip() {
    let m = ModifierInfo {
        name: "onlyOwner".to_string(),
        line_number: 12,
        params: vec![],
        is_virtual: false,
        is_override: false,
        body_present: true,
    };
    let s = serde_json::to_string(&m).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("onlyOwner"));
    assert_eq!(v.get("line_number").and_then(|x| x.as_u64()), Some(12));
    assert_eq!(v.get("is_virtual").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(v.get("is_override").and_then(|x| x.as_bool()), Some(false));
    assert_eq!(v.get("body_present").and_then(|x| x.as_bool()), Some(true));

    let back: ModifierInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "onlyOwner");
    assert_eq!(back.line_number, 12);
    assert!(back.body_present);
}

#[test]
fn modifierinfo_with_params_and_virtual_override() {
    let m = ModifierInfo {
        name: "onlyRole".to_string(),
        line_number: 42,
        params: vec![ParamInfo {
            name: "role".to_string(),
            type_: Some("bytes32".to_string()),
            default_value: None,
        }],
        is_virtual: true,
        is_override: true,
        body_present: true,
    };
    let v: Value = serde_json::to_value(&m).unwrap();
    assert_eq!(v.get("is_virtual").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(v.get("is_override").and_then(|x| x.as_bool()), Some(true));
    let params = v.get("params").and_then(|x| x.as_array()).unwrap();
    assert_eq!(params.len(), 1);
    assert_eq!(
        params[0].get("type").and_then(|x| x.as_str()),
        Some("bytes32")
    );
}

// =============================================================================
// EventInfo — Solidity `event Transfer(address indexed from, ...)`
// =============================================================================

#[test]
fn eventinfo_with_indexed_params_roundtrips() {
    let e = EventInfo {
        name: "Transfer".to_string(),
        line_number: 7,
        params: vec![
            EventParamInfo {
                name: "from".to_string(),
                type_: "address".to_string(),
                indexed: true,
            },
            EventParamInfo {
                name: "to".to_string(),
                type_: "address".to_string(),
                indexed: true,
            },
            EventParamInfo {
                name: "value".to_string(),
                type_: "uint256".to_string(),
                indexed: false,
            },
        ],
        is_anonymous: false,
    };
    let s = serde_json::to_string(&e).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("Transfer"));
    assert_eq!(
        v.get("is_anonymous").and_then(|x| x.as_bool()),
        Some(false)
    );
    let params = v.get("params").and_then(|x| x.as_array()).unwrap();
    assert_eq!(params.len(), 3);
    assert_eq!(
        params[0].get("name").and_then(|x| x.as_str()),
        Some("from")
    );
    assert_eq!(
        params[0].get("type").and_then(|x| x.as_str()),
        Some("address")
    );
    assert_eq!(params[0].get("indexed").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(
        params[2].get("indexed").and_then(|x| x.as_bool()),
        Some(false)
    );

    let back: EventInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "Transfer");
    assert_eq!(back.params.len(), 3);
    assert!(back.params[0].indexed);
    assert!(!back.params[2].indexed);
}

#[test]
fn eventinfo_anonymous_serializes() {
    let e = EventInfo {
        name: "RawLog".to_string(),
        line_number: 99,
        params: vec![],
        is_anonymous: true,
    };
    let v: Value = serde_json::to_value(&e).unwrap();
    assert_eq!(v.get("is_anonymous").and_then(|x| x.as_bool()), Some(true));
}

// =============================================================================
// ErrorInfo — Solidity 0.8.4+ custom errors
// =============================================================================

#[test]
fn errorinfo_with_params_roundtrips() {
    let e = ErrorInfo {
        name: "InsufficientBalance".to_string(),
        line_number: 21,
        params: vec![
            ParamInfo {
                name: "available".to_string(),
                type_: Some("uint256".to_string()),
                default_value: None,
            },
            ParamInfo {
                name: "requested".to_string(),
                type_: Some("uint256".to_string()),
                default_value: None,
            },
        ],
    };
    let s = serde_json::to_string(&e).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(
        v.get("name").and_then(|x| x.as_str()),
        Some("InsufficientBalance")
    );
    let params = v.get("params").and_then(|x| x.as_array()).unwrap();
    assert_eq!(params.len(), 2);
    assert_eq!(
        params[0].get("name").and_then(|x| x.as_str()),
        Some("available")
    );
    assert_eq!(
        params[0].get("type").and_then(|x| x.as_str()),
        Some("uint256")
    );

    let back: ErrorInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "InsufficientBalance");
    assert_eq!(back.params.len(), 2);
    assert_eq!(back.params[0].name, "available");
    assert_eq!(back.params[0].type_.as_deref(), Some("uint256"));
}

#[test]
fn errorinfo_no_params_roundtrips() {
    let e = ErrorInfo {
        name: "Unauthorized".to_string(),
        line_number: 5,
        params: vec![],
    };
    let s = serde_json::to_string(&e).unwrap();
    let back: ErrorInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "Unauthorized");
    assert!(back.params.is_empty());
}

// =============================================================================
// ModuleInfo extensions — file-scope modifiers/events/errors
// =============================================================================

fn empty_module() -> ModuleInfo {
    ModuleInfo {
        file_path: PathBuf::from("/tmp/x.sol"),
        language: Language::Solidity,
        docstring: None,
        imports: vec![],
        functions: vec![],
        classes: vec![],
        constants: vec![],
        call_graph: IntraFileCallGraph::default(),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    }
}

#[test]
fn moduleinfo_empty_solidity_lists_omit_keys() {
    let m = empty_module();
    let v: Value = serde_json::to_value(&m).unwrap();
    assert!(
        v.get("modifiers").is_none(),
        "empty `modifiers` must not be emitted: {v}"
    );
    assert!(
        v.get("events").is_none(),
        "empty `events` must not be emitted: {v}"
    );
    assert!(
        v.get("errors").is_none(),
        "empty `errors` must not be emitted: {v}"
    );
}

#[test]
fn moduleinfo_with_solidity_lists_emits_keys() {
    let mut m = empty_module();
    m.modifiers.push(ModifierInfo {
        name: "onlyOwner".to_string(),
        line_number: 10,
        params: vec![],
        is_virtual: false,
        is_override: false,
        body_present: true,
    });
    m.events.push(EventInfo {
        name: "Approval".to_string(),
        line_number: 20,
        params: vec![],
        is_anonymous: false,
    });
    m.errors.push(ErrorInfo {
        name: "Unauthorized".to_string(),
        line_number: 30,
        params: vec![],
    });
    let v: Value = serde_json::to_value(&m).unwrap();
    assert_eq!(
        v.get("modifiers")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        v.get("events").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        v.get("errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1)
    );
}

#[test]
fn moduleinfo_solidity_lists_roundtrip() {
    let mut m = empty_module();
    m.modifiers.push(ModifierInfo {
        name: "nonReentrant".to_string(),
        line_number: 4,
        params: vec![],
        is_virtual: true,
        is_override: false,
        body_present: true,
    });
    m.events.push(EventInfo {
        name: "Transfer".to_string(),
        line_number: 8,
        params: vec![EventParamInfo {
            name: "to".to_string(),
            type_: "address".to_string(),
            indexed: true,
        }],
        is_anonymous: false,
    });
    m.errors.push(ErrorInfo {
        name: "BadAmount".to_string(),
        line_number: 12,
        params: vec![ParamInfo {
            name: "v".to_string(),
            type_: Some("uint256".to_string()),
            default_value: None,
        }],
    });

    let s = serde_json::to_string(&m).unwrap();
    let back: ModuleInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.modifiers.len(), 1);
    assert_eq!(back.modifiers[0].name, "nonReentrant");
    assert!(back.modifiers[0].is_virtual);
    assert_eq!(back.events.len(), 1);
    assert_eq!(back.events[0].params.len(), 1);
    assert!(back.events[0].params[0].indexed);
    assert_eq!(back.errors.len(), 1);
    assert_eq!(back.errors[0].params.len(), 1);
    assert_eq!(back.errors[0].params[0].type_.as_deref(), Some("uint256"));
}

// =============================================================================
// ClassInfo extensions — contract-scope modifiers/events/errors
// =============================================================================

fn empty_contract(name: &str) -> ClassInfo {
    ClassInfo {
        name: name.to_string(),
        bases: vec![],
        docstring: None,
        methods: vec![],
        fields: vec![],
        decorators: vec![],
        line_number: 1,
        line_end: 100,
        kind: Some("contract".to_string()),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    }
}

#[test]
fn classinfo_empty_solidity_lists_omit_keys() {
    let c = empty_contract("ERC20");
    let v: Value = serde_json::to_value(&c).unwrap();
    assert!(
        v.get("modifiers").is_none(),
        "empty `modifiers` must not be emitted on ClassInfo: {v}"
    );
    assert!(
        v.get("events").is_none(),
        "empty `events` must not be emitted on ClassInfo: {v}"
    );
    assert!(
        v.get("errors").is_none(),
        "empty `errors` must not be emitted on ClassInfo: {v}"
    );
}

#[test]
fn classinfo_with_solidity_lists_emits_keys() {
    let mut c = empty_contract("ERC20");
    c.modifiers.push(ModifierInfo {
        name: "onlyOwner".to_string(),
        line_number: 10,
        params: vec![],
        is_virtual: false,
        is_override: false,
        body_present: true,
    });
    c.events.push(EventInfo {
        name: "Transfer".to_string(),
        line_number: 20,
        params: vec![],
        is_anonymous: false,
    });
    c.errors.push(ErrorInfo {
        name: "InsufficientBalance".to_string(),
        line_number: 30,
        params: vec![],
    });
    let v: Value = serde_json::to_value(&c).unwrap();
    assert_eq!(
        v.get("modifiers")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(1),
        "got: {v}"
    );
    assert_eq!(
        v.get("events").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        v.get("errors").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        v.get("kind").and_then(|x| x.as_str()),
        Some("contract"),
        "kind should be emitted when Some: {v}"
    );
}

#[test]
fn classinfo_solidity_lists_roundtrip() {
    let mut c = empty_contract("Vault");
    c.modifiers.push(ModifierInfo {
        name: "onlyOwner".to_string(),
        line_number: 5,
        params: vec![],
        is_virtual: false,
        is_override: false,
        body_present: true,
    });
    c.events.push(EventInfo {
        name: "Deposit".to_string(),
        line_number: 10,
        params: vec![EventParamInfo {
            name: "user".to_string(),
            type_: "address".to_string(),
            indexed: true,
        }],
        is_anonymous: false,
    });
    c.errors.push(ErrorInfo {
        name: "ZeroAmount".to_string(),
        line_number: 15,
        params: vec![],
    });

    let s = serde_json::to_string(&c).unwrap();
    let back: ClassInfo = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "Vault");
    assert_eq!(back.kind.as_deref(), Some("contract"));
    assert_eq!(back.modifiers.len(), 1);
    assert_eq!(back.modifiers[0].name, "onlyOwner");
    assert_eq!(back.events.len(), 1);
    assert_eq!(back.events[0].params.len(), 1);
    assert!(back.events[0].params[0].indexed);
    assert_eq!(back.errors.len(), 1);
    assert_eq!(back.errors[0].name, "ZeroAmount");
}

// =============================================================================
// Cross-cutting: a non-Solidity ClassInfo serializes identically to pre-v1
// =============================================================================

#[test]
fn non_solidity_classinfo_json_shape_unchanged() {
    // Simulate what a Python/Rust extractor would emit: no kind, no
    // Solidity-only vec fields populated.
    let ci = ClassInfo {
        name: "MyClass".to_string(),
        bases: vec!["Base".to_string()],
        docstring: Some("doc".to_string()),
        methods: vec![],
        fields: vec![],
        decorators: vec!["dataclass".to_string()],
        line_number: 1,
        line_end: 10,
        kind: None,
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&ci).unwrap();
    // None of the new keys should appear in output.
    assert!(v.get("kind").is_none(), "kind leaked: {v}");
    assert!(v.get("modifiers").is_none(), "modifiers leaked: {v}");
    assert!(v.get("events").is_none(), "events leaked: {v}");
    assert!(v.get("errors").is_none(), "errors leaked: {v}");
    // And the legacy shape is preserved.
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("MyClass"));
    assert_eq!(
        v.get("bases").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert_eq!(
        v.get("decorators")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(1)
    );
}

#[test]
fn non_solidity_moduleinfo_json_shape_unchanged() {
    let m = ModuleInfo {
        file_path: PathBuf::from("/tmp/x.py"),
        language: Language::Python,
        docstring: None,
        imports: vec![],
        functions: vec![],
        classes: vec![],
        constants: vec![],
        call_graph: IntraFileCallGraph::default(),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&m).unwrap();
    assert!(v.get("modifiers").is_none(), "modifiers leaked: {v}");
    assert!(v.get("events").is_none(), "events leaked: {v}");
    assert!(v.get("errors").is_none(), "errors leaked: {v}");
}

// =============================================================================
// Schema sanity: a constructed ModuleInfo with mixed Solidity content
// produces a JSON shape consumers can navigate.
// =============================================================================

#[test]
fn solidity_module_full_shape() {
    let contract = ClassInfo {
        name: "ERC20".to_string(),
        bases: vec!["IERC20".to_string(), "Context".to_string()],
        docstring: Some("Standard ERC20.".to_string()),
        methods: vec![FunctionInfo {
            name: "transfer".to_string(),
            params: vec!["address to".to_string(), "uint256 amount".to_string()],
            return_type: Some("bool".to_string()),
            docstring: None,
            is_method: true,
            is_async: false,
            decorators: vec![],
            visibility: Some("public".to_string()),
            line_number: 50,
            line_end: 55,
            state_mutability: None,
        }],
        fields: vec![],
        decorators: vec![],
        line_number: 10,
        line_end: 100,
        kind: Some("contract".to_string()),
        modifiers: vec![ModifierInfo {
            name: "onlyOwner".to_string(),
            line_number: 12,
            params: vec![],
            is_virtual: false,
            is_override: false,
            body_present: true,
        }],
        events: vec![EventInfo {
            name: "Transfer".to_string(),
            line_number: 15,
            params: vec![EventParamInfo {
                name: "from".to_string(),
                type_: "address".to_string(),
                indexed: true,
            }],
            is_anonymous: false,
        }],
        errors: vec![ErrorInfo {
            name: "InsufficientBalance".to_string(),
            line_number: 18,
            params: vec![ParamInfo {
                name: "available".to_string(),
                type_: Some("uint256".to_string()),
                default_value: None,
            }],
        }],
    };
    let m = ModuleInfo {
        file_path: PathBuf::from("/tmp/ERC20.sol"),
        language: Language::Solidity,
        docstring: None,
        imports: vec![],
        functions: vec![],
        classes: vec![contract],
        constants: vec![],
        call_graph: IntraFileCallGraph::default(),
        modifiers: vec![],
        events: vec![],
        errors: vec![],
    };
    let v: Value = serde_json::to_value(&m).unwrap();
    let expected = json!({
        "name": "ERC20",
        "kind": "contract",
    });
    let contract_json = &v["classes"][0];
    assert_eq!(contract_json["name"], expected["name"]);
    assert_eq!(contract_json["kind"], expected["kind"]);
    assert_eq!(
        contract_json["modifiers"][0]["name"].as_str(),
        Some("onlyOwner")
    );
    assert_eq!(
        contract_json["events"][0]["params"][0]["indexed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        contract_json["errors"][0]["name"].as_str(),
        Some("InsufficientBalance")
    );
}
