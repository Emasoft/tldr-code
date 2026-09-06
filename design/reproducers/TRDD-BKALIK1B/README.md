# TRDD-BKALIK1B reproducer — a UTF-16 file is reported as analysed with zero symbols

Three tiny Python files. `control.py` and `bad.py` hold **byte-identical source text**; they
differ only in encoding. That is the whole point of the fixture — it removes every explanation
except the encoding.

| file | encoding | content | symbols `tldr structure` found (before the fix) |
|---|---|---|---|
| `good.py` | UTF-8 | `alpha`, `beta` | 2 |
| `control.py` | UTF-8 | `gamma`, `delta` | 2 |
| `bad.py` | UTF-16 LE + BOM | `gamma`, `delta` — identical text to `control.py` | **0** |

## Reproduce

```sh
tldr structure design/reproducers/TRDD-BKALIK1B
```

Before the fix, `bad.py` appears in the JSON with `"definitions": []`, `"classes": []`,
`"imports": []`, and the command **exits 0 with no warning**.

## Why this is worse than "the file was skipped"

The file is not skipped. It is *listed as successfully analysed* and reported to have no
functions. A caller cannot distinguish that from a genuinely empty file, so a tree containing
UTF-16 sources yields a confidently wrong, silently incomplete answer — and the exit code says
everything is fine.

## Root cause

`crates/tldr-core/src/ast/parser.rs`, in the pool's `parse_file_with_lang`:

```rust
let bytes = std::fs::read(path)?;
let source = String::from_utf8_lossy(&bytes).to_string();
```

`String::from_utf8_lossy` does **not** fail on UTF-16 input. It substitutes U+FFFD for every
invalid sequence and returns a `String` full of replacement characters, which then parses
cleanly to zero symbols. Nothing anywhere reports an error, because by the type system's lights
nothing went wrong.

That function is the single chokepoint for every parse-based command — `structure`, `calls`,
`smells`, `dead`, `secure` — which is why the same silent-wrong-answer reaches all of them, and
why the fix belongs there rather than at each caller. The file-size policy is enforced at the
same spot for the same reason.

## Regenerating `bad.py`

It is committed because a UTF-16 file cannot be produced by a text editor's default settings and
a corrupted copy would silently turn this fixture into a UTF-8 one, i.e. into a test that passes
for the wrong reason. To rebuild it:

```sh
python3 -c "open('bad.py','wb').write(b'\xff\xfe'+'def gamma():\n    return 3\n\ndef delta():\n    return 4\n'.encode('utf-16-le'))"
```

Verify with `file bad.py` — it must say `UTF-16, little-endian`, not `ASCII text`.
