use crate::types::Language;

use super::super::SurfaceLanguageProfile;

const NOISE_DIRS: &[&str] = &[
    "benchmark",
    "benchmarks",
    "doc",
    "docs",
    "example",
    "examples",
    "node_modules",
    "test",
    "tests",
    "vendor",
];
// why: missing leading separator matched any file whose name merely ended in
// these letters (e.g. "latest.php", "manifest.php", "workbench.php"); every
// other language profile uses a `_`/`.` delimited suffix, so match that here.
const NOISE_FILE_SUFFIXES: &[&str] =
    &["_benchmark.php", "_bench.php", "_test.php", "_tests.php"];
const DROP_SEGMENTS: &[&str] = &["lib", "src"];
const PREFIX_SRC: &[&str] = &["src"];
const PREFIX_LIB: &[&str] = &["lib"];
const DROP_PREFIXES: &[&[&str]] = &[PREFIX_SRC, PREFIX_LIB];
const PREFERRED_ROOTS: &[&str] = &["src", "lib"];
const ENTRYPOINTS: &[&str] = &["composer.json", "src", "lib"];

pub(super) const PROFILE: SurfaceLanguageProfile = SurfaceLanguageProfile {
    language: Language::Php,
    noise_dirs: NOISE_DIRS,
    noise_file_suffixes: NOISE_FILE_SUFFIXES,
    drop_segments: DROP_SEGMENTS,
    drop_prefixes: DROP_PREFIXES,
    preferred_roots: PREFERRED_ROOTS,
    entrypoints: ENTRYPOINTS,
};
