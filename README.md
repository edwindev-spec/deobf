# Lua Unveil 1.0.0

Static deobfuscation toolkit for Lua/Luau source and profile-driven analysis of stack-based virtual machines. The package uses only the Python standard library and never executes the input Lua source or the bytecode being analyzed.

## Requirements

- Python 3.10 or newer
- No runtime third-party dependencies

## Install

```bash
python -m pip install .
```

## Deobfuscate a Lua/Luau file

```bash
lua-unveil sample.lua -o sample.deobfuscated.lua --report sample.report.json
```

The default pipeline normalizes safe Lua escapes, folds literal `string.char` / `utf8.char` / simple `table.concat` expressions, resolves immutable local string arrays indexed by constant integers, and resolves only provably constant `if` branches. It preserves all other source text and comments. The `--rename` option enables conservative renaming for uniquely declared, short or otherwise obfuscated-looking locals.

An XOR key is never guessed. To try a known repeating multi-byte key:

```bash
lua-unveil sample.lua -o output.lua --xor-key 0x31 --xor-key 0x7a
```

The XOR operation only replaces literals whose decoded contents pass the configured printable-text ratio. Rolling XOR and additive-byte transforms are available through `--rolling-xor-key` / `--rolling-xor-step` and `--additive-key` / `--additive-step`. Adjust `--xor-printable-ratio` only when analyzing a known encoding. Python users can register additional pure byte decoders through `CipherRegistry`.

## Stack VM analysis

The built-in `stack-v1` profile is a documented example format, not a claim that arbitrary commercial protectors use it. It supports a profile-driven decoder, byte-offset control-flow validation, stack-depth verification, symbolic lifting for straight-line bytecode, and a label-preserving Lua dispatcher lift for branches.

```bash
lua-unveil --vm-bytecode program.vm --constants constants.json -o lifted.lua
```

A custom JSON profile can define opcodes using the supported operand encodings `u8`, `i8`, `u16`, `i16`, `u32`, and `i32`. Supported semantics are the built-in stack instruction set; new semantics require implementing and testing their stack effects and emitters in `vm.py`.

A custom static cipher can be registered through the Python API:

```python
from lua_unveil import StringDecryptor

def reverse_bytes(data: bytes, parameters: dict[str, object]) -> bytes:
    return data[::-1]

strings = StringDecryptor()
strings.ciphers.register("reverse-bytes", reverse_bytes)
source, replacements = strings.apply_cipher_to_literals(
    'local value = "!dlroW olleH"',
    "reverse-bytes",
    {},
)
```

## Python API

```python
from lua_unveil import Deobfuscator, DeobfuscatorConfig

engine = Deobfuscator(DeobfuscatorConfig(max_layers=4, rename_identifiers=False))
result = engine.deobfuscate_file("sample.lua")

print(result.source)
print(result.report.to_dict())
```

## Safety and analysis boundaries

- No `exec`, `eval`, subprocess, Roblox runtime, or Lua interpreter is used.
- The parser validates lexical delimiters and block balance; it is not a complete Lua/Luau grammar or compiler.
- Fingerprinting is heuristic. A product family marker does not reliably establish a precise protector version.
- Encrypted string algorithms require their key and exact algorithm. XOR, rolling-XOR, and additive transforms are opt-in; one base85 primitive is exposed for analysis but does not unpack an entire protector container.
- Static branch elimination only changes branches when every preceding condition is proven constant.
- Dead-code removal beyond provably unreachable constant branches is deliberately conservative.
- Commercial VM formats such as Luraph use custom serialization, state initialization, operand encodings, and dispatch semantics. The built-in VM profile is not an automatic Luraph unpacker; such formats need a family/version-specific decoder and verified opcode semantics.

## Tests

```bash
python -m unittest discover -s tests -v
```
