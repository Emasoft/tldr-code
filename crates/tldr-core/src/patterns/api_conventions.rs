//! API convention pattern detection
//!
//! Detects API patterns:
//! - Framework usage (FastAPI, Flask, Express, etc.)
//! - RESTful patterns
//! - ORM usage (SQLAlchemy, Prisma, GORM, etc.)
//! - GraphQL definitions

use super::signals::PatternSignals;
use crate::types::ApiConventionPattern;

/// Returns true if the analyzed sources import the given top-level package
/// (`import pkg`, `from pkg import x`, or `from pkg.sub import y`).
///
/// The import module names are extracted from the AST during the single
/// pattern-detection pass (see `PythonSemantics::detect_import`), so this is a
/// data-driven check over already-parsed import statements — not a textual
/// scan of the source.
fn imports_package(signals: &PatternSignals, pkg: &str) -> bool {
    let prefix = format!("{pkg}.");
    signals
        .import_patterns
        .absolute_imports
        .iter()
        .any(|(module, _)| module == pkg || module.starts_with(&prefix))
}

/// Resolve the primary web framework, disambiguating the FastAPI/Flask overlap.
///
/// Flask 2.0+ exposes `@app.get` / `@app.post` / `@app.put` / `@app.delete`
/// route shortcuts that are byte-identical to FastAPI's, so they are collected
/// into `fastapi_decorators` and the raw signal would report `fastapi`. That is
/// only correct when the project actually imports `fastapi`; absent a real
/// `fastapi` import, a `flask` import re-attributes those routes to Flask.
fn resolve_framework(signals: &PatternSignals) -> Option<String> {
    match signals.api_conventions.detect_framework() {
        Some(fw)
            if fw == "fastapi"
                && !imports_package(signals, "fastapi")
                && imports_package(signals, "flask") =>
        {
            Some("flask".to_string())
        }
        other => other,
    }
}

/// Convert signals to API convention pattern
pub fn signals_to_pattern(
    signals: &PatternSignals,
    evidence_limit: usize,
) -> Option<ApiConventionPattern> {
    let api_conventions = &signals.api_conventions;

    if !api_conventions.has_signals() {
        return None;
    }

    let confidence = api_conventions.calculate_confidence();

    // Detect framework (gating the ambiguous FastAPI/Flask route-shortcut
    // overlap on an actual `fastapi` import — see `resolve_framework`).
    let framework = resolve_framework(signals);

    // Detect patterns
    let mut patterns = Vec::new();

    if !api_conventions.fastapi_decorators.is_empty()
        || !api_conventions.flask_decorators.is_empty()
        || !api_conventions.express_routes.is_empty()
    {
        patterns.push("rest_crud".to_string());
    }

    if !api_conventions.restful_patterns.is_empty() {
        patterns.push("restful_naming".to_string());
    }

    if !api_conventions.graphql_defs.is_empty() {
        patterns.push("graphql".to_string());
    }

    // Detect ORM
    let orm_usage = api_conventions.detect_orm();

    // Collect evidence (limited)
    let mut evidence = Vec::new();
    evidence.extend(
        api_conventions
            .fastapi_decorators
            .iter()
            .take(evidence_limit)
            .cloned(),
    );
    evidence.extend(
        api_conventions
            .flask_decorators
            .iter()
            .take(evidence_limit)
            .cloned(),
    );
    evidence.extend(
        api_conventions
            .express_routes
            .iter()
            .take(evidence_limit)
            .cloned(),
    );
    evidence.extend(
        api_conventions
            .restful_patterns
            .iter()
            .take(evidence_limit)
            .cloned(),
    );
    evidence.extend(
        api_conventions
            .orm_models
            .iter()
            .take(evidence_limit)
            .map(|(_, e)| e.clone()),
    );
    evidence.truncate(evidence_limit);

    Some(ApiConventionPattern {
        confidence,
        framework,
        patterns,
        orm_usage,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Evidence;

    #[test]
    fn test_no_signals_returns_none() {
        let signals = PatternSignals::default();
        assert!(signals_to_pattern(&signals, 3).is_none());
    }

    #[test]
    fn test_fastapi_detected() {
        let mut signals = PatternSignals::default();
        signals
            .api_conventions
            .fastapi_decorators
            .push(Evidence::new("routes.py", 10, "@app.get('/users')"));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("fastapi".to_string()));
        assert!(pattern.patterns.contains(&"rest_crud".to_string()));
    }

    #[test]
    fn test_flask_detected() {
        let mut signals = PatternSignals::default();
        signals.api_conventions.flask_decorators.push(Evidence::new(
            "routes.py",
            10,
            "@app.route('/users', methods=['GET'])",
        ));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("flask".to_string()));
    }

    #[test]
    fn test_express_detected() {
        let mut signals = PatternSignals::default();
        signals.api_conventions.express_routes.push(Evidence::new(
            "routes.ts",
            10,
            "app.get('/users', (req, res) => { ... })",
        ));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("express".to_string()));
    }

    #[test]
    fn test_orm_detected() {
        let mut signals = PatternSignals::default();
        signals.api_conventions.orm_models.push((
            "sqlalchemy".to_string(),
            Evidence::new("models.py", 5, "class User(Base):"),
        ));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.orm_usage, Some("sqlalchemy".to_string()));
    }

    // fix-PW4-bug1-patterns-py-fastapi: Flask 2.0+ exposes @app.get/@app.post/...
    // route shortcuts that are byte-identical to FastAPI's, so they land in
    // `fastapi_decorators`. The framework verdict must be gated on an actual
    // `fastapi` import; with a `flask` import and no `fastapi` import the routes
    // belong to Flask.
    #[test]
    fn test_flask_shortcut_with_flask_import_detected_as_flask() {
        let mut signals = PatternSignals::default();
        signals
            .api_conventions
            .fastapi_decorators
            .push(Evidence::new("app.py", 7, "@app.get(\"/users\")"));
        signals
            .api_conventions
            .flask_decorators
            .push(Evidence::new("app.py", 4, "@app.route(\"/\")"));
        signals
            .import_patterns
            .absolute_imports
            .push(("flask".to_string(), "app.py".to_string()));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("flask".to_string()));
    }

    // Even when Flask only uses the new shortcut form (no @app.route at all),
    // a `flask` import must still re-attribute the routes to Flask.
    #[test]
    fn test_flask_shortcut_only_with_flask_import_detected_as_flask() {
        let mut signals = PatternSignals::default();
        signals
            .api_conventions
            .fastapi_decorators
            .push(Evidence::new("app.py", 7, "@app.post(\"/users\")"));
        signals
            .import_patterns
            .absolute_imports
            .push(("flask".to_string(), "app.py".to_string()));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("flask".to_string()));
    }

    // Counterpart: a genuine FastAPI repo (imports fastapi) must remain fastapi.
    #[test]
    fn test_fastapi_shortcut_with_fastapi_import_detected_as_fastapi() {
        let mut signals = PatternSignals::default();
        signals
            .api_conventions
            .fastapi_decorators
            .push(Evidence::new("api.py", 5, "@app.get(\"/users\")"));
        signals
            .import_patterns
            .absolute_imports
            .push(("fastapi".to_string(), "api.py".to_string()));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("fastapi".to_string()));
    }

    // `from fastapi.routing import APIRouter` records module `fastapi.routing`;
    // the gate keys on the top-level package, so this still resolves to fastapi.
    #[test]
    fn test_fastapi_submodule_import_detected_as_fastapi() {
        let mut signals = PatternSignals::default();
        signals
            .api_conventions
            .fastapi_decorators
            .push(Evidence::new("api.py", 5, "@router.get(\"/users\")"));
        signals
            .import_patterns
            .absolute_imports
            .push(("fastapi.routing".to_string(), "api.py".to_string()));

        let pattern = signals_to_pattern(&signals, 3).unwrap();
        assert_eq!(pattern.framework, Some("fastapi".to_string()));
    }
}
