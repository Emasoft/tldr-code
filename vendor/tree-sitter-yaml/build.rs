fn main() {
    let src_dir = std::path::Path::new("src");

    let mut c_config = cc::Build::new();
    c_config.std("c11").include(src_dir);
    c_config
        .flag_if_supported("-Wno-unused-but-set-variable")
        .flag_if_supported("-Wno-unused-value")
        .flag_if_supported("-Wno-implicit-fallthrough");

    #[cfg(target_env = "msvc")]
    c_config.flag("-utf-8");

    // FIX-1b (F9a): track the whole `src` directory, not just the two
    // compiled translation units. `parser.c` #includes `schema.core.c`
    // (and `schema.json.c` ships beside it), and the `src/tree_sitter`
    // headers feed every unit — none of those triggered a rebuild under
    // the parser.c/scanner.c-only watch, so editing an #included schema
    // file silently kept building the stale objects. A directory path
    // makes cargo watch it recursively; the two file lines below stay as
    // explicit (now redundant) belt-and-suspenders.
    println!("cargo:rerun-if-changed={}", src_dir.display());

    let parser_path = src_dir.join("parser.c");
    c_config.file(&parser_path);
    println!("cargo:rerun-if-changed={}", parser_path.to_str().unwrap());

    let scanner_path = src_dir.join("scanner.c");
    c_config.file(&scanner_path);
    println!("cargo:rerun-if-changed={}", scanner_path.to_str().unwrap());

    c_config.compile("tree-sitter-yaml");
}
