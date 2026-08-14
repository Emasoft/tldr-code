//! TEMPORARY PROBE — not a real test. Dumps, per language, the tree-sitter node kinds involved
//! when an anonymous callable is passed to a call. Its output fills the two per-language tables
//! (`anonymous_callable_kinds` / `call_like_kinds`) with names read off THESE grammars at THESE
//! versions, instead of names recalled from memory — grammar node kinds differ between versions
//! and between languages that look similar.
//!
//! Run: cargo test -p tldr-core --test anon_callback_kinds_probe -- --nocapture
//! Delete once the tables are filled and the real assertions exist.

use tldr_core::ast::parser::parse;
use tldr_core::Language;
use tree_sitter::Node;

/// One sample per language: a call that receives an anonymous callable spanning >1 line, in the
/// idiom that language's own test framework or stdlib actually uses.
fn samples() -> Vec<(Language, &'static str, &'static str)> {
    vec![
        (Language::JavaScript, "js", "suiteSetup(async function () {\n  const a = 1;\n  return a;\n});\n"),
        (Language::TypeScript, "ts", "test('a title', async () => {\n  const a: number = 1;\n  return a;\n});\n"),
        (Language::Python, "py", "sorted(items, key=lambda a:\n    a.b\n)\n"),
        (Language::Ruby, "rb", "it 'does a thing' do\n  expect(1).to eq(1)\nend\n"),
        (Language::Go, "go", "func main() {\n\thttp.HandleFunc(\"/\", func(w int, r int) {\n\t\tprintln(w)\n\t})\n}\n"),
        (Language::Rust, "rs", "fn main() {\n    thread::spawn(|| {\n        println!(\"x\");\n    });\n}\n"),
        (Language::Java, "java", "class A {\n  void m() {\n    list.forEach(x -> {\n      System.out.println(x);\n    });\n  }\n}\n"),
        (Language::CSharp, "cs", "class A {\n  void M() {\n    list.ForEach(x => {\n      Console.WriteLine(x);\n    });\n  }\n}\n"),
        (Language::Cpp, "cpp", "int main() {\n  run([](int x) {\n    return x + 1;\n  });\n}\n"),
        (Language::Kotlin, "kt", "fun main() {\n  runBlocking {\n    delay(1)\n  }\n}\n"),
        (Language::Swift, "swift", "describe(\"a thing\") {\n  let x = 1\n  print(x)\n}\n"),
        (Language::Scala, "scala", "object A {\n  list.foreach { x =>\n    println(x)\n  }\n}\n"),
        (Language::Php, "php", "<?php\n$f = array_map(function ($x) {\n    return $x + 1;\n}, $items);\n"),
        (Language::Lua, "lua", "setup(function ()\n  local a = 1\n  return a\nend)\n"),
        (Language::Luau, "luau", "setup(function ()\n  local a = 1\n  return a\nend)\n"),
        (Language::Elixir, "ex", "test \"a title\" do\n  assert 1 == 1\nend\n"),
        (Language::Ocaml, "ml", "let () =\n  List.iter (fun x ->\n    print_int x\n  ) items\n"),
        (Language::C, "c", "int main(void) {\n  return 0;\n}\n"),
    ]
}

/// Kinds that look like an anonymous callable in SOME grammar. Deliberately broad — the probe's
/// job is to report which ones this grammar actually produces, not to be right up front.
const CANDIDATE_CALLABLE: &[&str] = &[
    "arrow_function", "function_expression", "lambda", "lambda_expression", "lambda_literal",
    "anonymous_function", "anonymous_function_creation_expression", "anonymous_method_expression",
    "closure_expression", "func_literal", "function_definition", "function_literal", "block",
    "do_block", "fun_expression", "function", "short_function", "curly_bracketed_block",
];

fn walk<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if CANDIDATE_CALLABLE.contains(&node.kind()) {
        out.push(node);
    }
    let mut c = node.walk();
    for child in node.children(&mut c) {
        walk(child, out);
    }
}

#[test]
fn probe_anonymous_callable_and_call_kinds() {
    println!("\n{:<12} {:<34} {:<28} {}", "LANG", "CALLABLE KIND (lines)", "PARENT CHAIN", "CALLEE TEXT");
    println!("{}", "-".repeat(120));
    for (lang, ext, src) in samples() {
        let tree = match parse(src, lang) {
            Ok(t) => t,
            Err(e) => {
                println!("{:<12} PARSE FAILED: {e}", format!("{lang:?}"));
                continue;
            }
        };
        let mut hits = Vec::new();
        walk(tree.root_node(), &mut hits);
        if hits.is_empty() {
            println!("{:<12} (.{ext}) NO anonymous-callable candidate found", format!("{lang:?}"));
            continue;
        }
        for h in hits {
            // Only the multi-line ones matter — a one-liner owns no region worth mapping.
            let lines = h.end_position().row - h.start_position().row + 1;
            // Walk up to 3 ancestors so the real call-node kind is visible whatever the grammar
            // wraps it in (argument_list, arguments, call_suffix, …).
            let mut chain = Vec::new();
            let mut callee = String::from("-");
            let mut cur = h.parent();
            for _ in 0..4 {
                match cur {
                    Some(p) => {
                        chain.push(p.kind().to_string());
                        if callee == "-" {
                            if let Some(f) = p.child_by_field_name("function").or_else(|| p.child(0)) {
                                if let Ok(t) = f.utf8_text(src.as_bytes()) {
                                    if !t.contains('\n') && t.len() < 40 {
                                        callee = t.to_string();
                                    }
                                }
                            }
                        }
                        cur = p.parent();
                    }
                    None => break,
                }
            }
            println!(
                "{:<12} {:<34} {:<28} {}",
                format!("{lang:?}"),
                format!("{} (L{}-{}, {} ln)", h.kind(), h.start_position().row + 1, h.end_position().row + 1, lines),
                chain.join(" < "),
                callee.replace('\n', " ")
            );
        }
    }
    println!();
}
