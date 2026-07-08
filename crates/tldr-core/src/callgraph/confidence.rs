//! Confidence and provenance labels for call-resolution edges.

use serde::{Deserialize, Serialize};

/// Coarse confidence tier emitted on resolved call edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidenceTier {
    /// High confidence: exact imports, lexical scope, self/super, or typed dispatch.
    T1,
    /// Lower confidence: suffix aliases, name-match fallbacks, or other guesses.
    T2,
}

impl ConfidenceTier {
    /// Stable JSON spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::T1 => "T1",
            Self::T2 => "T2",
        }
    }
}

/// The concrete resolver rung that produced a call edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResolutionRung {
    /// Constructor method selected from the language constructor table.
    ConstructorMethod,
    /// Constructor call fell back to the class definition itself.
    ConstructorClassFallback,
    /// Local lexical/intra-file function lookup.
    LocalFunction,
    /// Local lexical/intra-file method lookup.
    LocalMethod,
    /// Exact import-map lookup, preserving the import path.
    ImportMapExact,
    /// Import-map lookup through a bare/simple module alias.
    ImportMapAlias,
    /// Python re-export chain traced to the definition.
    ReExportTrace,
    /// Function reference resolved through an import.
    RefImport,
    /// Function reference resolved in the caller's local module.
    RefLocal,
    /// Cross-file free function visible without an import.
    GlobalFreeFunction,
    /// Static call resolved through current module or class-qualified lookup.
    StaticQualified,
    /// Method resolved in the named class.
    MethodInClass,
    /// Method resolved through an inherited base class.
    MethodInBase,
    /// C++ out-of-line `Class::method` fallback.
    CppOutOfLineMethod,
    /// PHP magic `__call` redirect.
    PhpMagicCall,
    /// Typed receiver dispatch.
    ReceiverType,
    /// `self`/`this`/`cls` receiver in the current file.
    SelfReceiver,
    /// Module receiver import lookup.
    ModuleImportReceiver,
    /// Import-map receiver lookup.
    ImportMapReceiver,
    /// Local qualified receiver lookup such as `Module.func`.
    LocalQualifiedReceiver,
    /// OCaml sibling module receiver lookup.
    OcamlModuleReceiver,
    /// Capitalized receiver name guess such as `user` -> `User`.
    CapitalizedReceiverGuess,
    /// Same-file name-match fallback for untyped receiver calls.
    LocalFuzzyMatch,
    /// Global name-match fallback for untyped receiver calls.
    GlobalFuzzyMatch,
    /// Last-resort type-aware fallback after normal typed dispatch declined.
    TypeAwareFallback,
    /// Super/parent/base constructor or method dispatch.
    SuperDispatch,
}

impl ResolutionRung {
    /// Stable raw rung identifier emitted in JSON provenance.
    pub fn id(self) -> &'static str {
        match self {
            Self::ConstructorMethod => "constructor_method",
            Self::ConstructorClassFallback => "constructor_class_fallback",
            Self::LocalFunction => "local_function",
            Self::LocalMethod => "local_method",
            Self::ImportMapExact => "import_map_exact",
            Self::ImportMapAlias => "import_map_alias",
            Self::ReExportTrace => "reexport_trace",
            Self::RefImport => "ref_import",
            Self::RefLocal => "ref_local",
            Self::GlobalFreeFunction => "global_free_function",
            Self::StaticQualified => "static_qualified",
            Self::MethodInClass => "method_in_class",
            Self::MethodInBase => "method_in_base",
            Self::CppOutOfLineMethod => "cpp_out_of_line_method",
            Self::PhpMagicCall => "php_magic_call",
            Self::ReceiverType => "receiver_type",
            Self::SelfReceiver => "self_receiver",
            Self::ModuleImportReceiver => "module_import_receiver",
            Self::ImportMapReceiver => "import_map_receiver",
            Self::LocalQualifiedReceiver => "local_qualified_receiver",
            Self::OcamlModuleReceiver => "ocaml_module_receiver",
            Self::CapitalizedReceiverGuess => "capitalized_receiver_guess",
            Self::LocalFuzzyMatch => "local_fuzzy_match",
            Self::GlobalFuzzyMatch => "global_fuzzy_match",
            Self::TypeAwareFallback => "type_aware_fallback",
            Self::SuperDispatch => "super_dispatch",
        }
    }

    /// Short human-facing mechanism label emitted in JSON provenance.
    pub fn mechanism(self) -> &'static str {
        match self {
            Self::ConstructorMethod => "constructor method",
            Self::ConstructorClassFallback => "constructor class fallback",
            Self::LocalFunction => "local function",
            Self::LocalMethod => "local method",
            Self::ImportMapExact => "exact import map",
            Self::ImportMapAlias => "import alias",
            Self::ReExportTrace => "re-export trace",
            Self::RefImport => "imported reference",
            Self::RefLocal => "local reference",
            Self::GlobalFreeFunction => "global free function",
            Self::StaticQualified => "static qualified lookup",
            Self::MethodInClass => "class method lookup",
            Self::MethodInBase => "base method lookup",
            Self::CppOutOfLineMethod => "cpp out-of-line method",
            Self::PhpMagicCall => "php magic call",
            Self::ReceiverType => "receiver type",
            Self::SelfReceiver => "self receiver",
            Self::ModuleImportReceiver => "module import receiver",
            Self::ImportMapReceiver => "import map receiver",
            Self::LocalQualifiedReceiver => "local qualified receiver",
            Self::OcamlModuleReceiver => "ocaml module receiver",
            Self::CapitalizedReceiverGuess => "capitalized receiver guess",
            Self::LocalFuzzyMatch => "local fuzzy match",
            Self::GlobalFuzzyMatch => "global fuzzy match",
            Self::TypeAwareFallback => "type-aware fallback",
            Self::SuperDispatch => "super dispatch",
        }
    }
}

/// Map a concrete resolution rung to the coarse confidence tier.
pub fn confidence_tier(rung: ResolutionRung) -> ConfidenceTier {
    match rung {
        ResolutionRung::ConstructorMethod
        | ResolutionRung::LocalFunction
        | ResolutionRung::LocalMethod
        | ResolutionRung::ImportMapExact
        | ResolutionRung::ReExportTrace
        | ResolutionRung::RefImport
        | ResolutionRung::StaticQualified
        | ResolutionRung::MethodInClass
        | ResolutionRung::MethodInBase
        | ResolutionRung::CppOutOfLineMethod
        | ResolutionRung::PhpMagicCall
        | ResolutionRung::SelfReceiver
        | ResolutionRung::ModuleImportReceiver
        | ResolutionRung::ImportMapReceiver
        | ResolutionRung::LocalQualifiedReceiver
        | ResolutionRung::OcamlModuleReceiver
        | ResolutionRung::SuperDispatch => ConfidenceTier::T1,

        ResolutionRung::ConstructorClassFallback
        | ResolutionRung::ImportMapAlias
        | ResolutionRung::RefLocal // VAL-032b: measured 1 TP / 34 FP, precision 0.029 on 35 samples.
        | ResolutionRung::GlobalFreeFunction
        | ResolutionRung::ReceiverType // VAL-032b: measured 34 TP / 37 FP, precision 0.479 on 71 samples.
        | ResolutionRung::CapitalizedReceiverGuess
        | ResolutionRung::LocalFuzzyMatch
        | ResolutionRung::GlobalFuzzyMatch
        | ResolutionRung::TypeAwareFallback => ConfidenceTier::T2,
    }
}
