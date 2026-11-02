"""Static Lua string normalization and opt-in byte-cipher decoders."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Any

from .lexer import LuaLexer
from .models import Token, TokenKind, TransformEvent


@dataclass(frozen=True, slots=True)
class StringDecodeResult:
    """A decoded byte/string payload and its transformation label."""

    value: str
    algorithm: str


class CipherRegistry:
    """Registry for deterministic byte-to-byte decoders supplied by analysts."""

    def __init__(self) -> None:
        self._decoders: dict[str, Callable[[bytes, Mapping[str, Any]], bytes]] = {}

    def register(
        self,
        name: str,
        decoder: Callable[[bytes, Mapping[str, Any]], bytes],
        replace: bool = False,
    ) -> None:
        """Register a pure decoder callback under a stable algorithm name."""
        if not name or not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Cipher name must contain only letters, digits, '-' or '_'")
        if name in self._decoders and not replace:
            raise ValueError(f"Cipher {name!r} is already registered")
        self._decoders[name] = decoder

    def decode(self, name: str, data: bytes, parameters: Mapping[str, Any]) -> bytes:
        """Apply a registered decoder and validate its return type."""
        try:
            decoder = self._decoders[name]
        except KeyError as exc:
            raise ValueError(f"Unknown cipher: {name}") from exc
        result = decoder(data, parameters)
        if not isinstance(result, bytes):
            raise TypeError(f"Cipher {name!r} must return bytes")
        return result

    @property
    def names(self) -> tuple[str, ...]:
        """Return registered cipher names in deterministic order."""
        return tuple(sorted(self._decoders))


class StringDecryptor:
    """Decode literal escapes and common byte encodings without running Lua.

    Cipher transforms are opt-in because guessing a key and rewriting arbitrary
    literals can corrupt program semantics.
    """

    def __init__(self, lexer: LuaLexer | None = None, ciphers: CipherRegistry | None = None) -> None:
        self.lexer = lexer or LuaLexer()
        self.ciphers = ciphers or CipherRegistry()
        for name, decoder in (
            ("xor", _xor_cipher),
            ("rolling-xor", _rolling_xor_cipher),
            ("additive", _additive_cipher),
        ):
            if name not in self.ciphers.names:
                self.ciphers.register(name, decoder)

    def normalize_literals(self, source: str) -> tuple[str, int]:
        """Resolve Lua escape sequences into equivalent readable literals."""
        tokens = self.lexer.tokenize(source)
        replacements: list[tuple[int, int, str]] = []
        for token in tokens:
            if token.kind is not TokenKind.STRING:
                continue
            decoded = decode_lua_string(token.raw)
            if decoded is None or has_high_byte_escape(token.raw):
                continue
            new_raw = quote_lua_string(decoded)
            if new_raw != token.raw:
                replacements.append((token.start, token.end, new_raw))
        return apply_replacements(source, replacements), len(replacements)

    def decode_char_calls(self, source: str) -> tuple[str, int]:
        """Fold literal string.char/utf8.char/table.concat calls."""
        all_tokens = self.lexer.tokenize(source)
        sig = self.lexer.significant(all_tokens)
        replacements: list[tuple[int, int, str]] = []
        i = 0
        while i < len(sig):
            start = i
            function_name: str | None = None
            if (
                i + 3 < len(sig)
                and sig[i].kind is TokenKind.IDENTIFIER
                and sig[i + 1].value == "."
                and sig[i + 2].kind is TokenKind.IDENTIFIER
                and sig[i + 3].value == "("
            ):
                owner = sig[i].value
                member = sig[i + 2].value
                if (owner, member) in {("string", "char"), ("utf8", "char"), ("table", "concat")}:
                    function_name = f"{owner}.{member}"
                    open_index = i + 3
            if function_name is None:
                i += 1
                continue

            close_index = find_matching_paren(sig, open_index)
            if close_index is None:
                i += 1
                continue
            args = sig[open_index + 1:close_index]
            decoded: str | None = None
            if function_name in {"string.char", "utf8.char"}:
                values = parse_integer_list(args)
                if values is not None:
                    try:
                        if function_name == "string.char" and all(0 <= n <= 255 for n in values):
                            decoded = bytes(values).decode("latin-1")
                        elif function_name == "utf8.char" and all(
                            0 <= n <= 0x10FFFF and not 0xD800 <= n <= 0xDFFF for n in values
                        ):
                            decoded = "".join(chr(n) for n in values)
                    except (ValueError, OverflowError):
                        decoded = None
            else:
                decoded = decode_table_concat(args)

            if decoded is not None:
                first = sig[start]
                last = sig[close_index]
                byte_mode = function_name in {"string.char", "table.concat"}
                replacements.append((first.start, last.end, quote_lua_string(decoded, byte_mode=byte_mode)))
                i = close_index + 1
            else:
                i += 1
        return apply_replacements(source, replacements), len(replacements)

    def decode_string_arrays(self, source: str) -> tuple[str, int]:
        """Resolve local arrays of literal strings with constant numeric indexes.

        A table is removed only when every non-declaration use is a read of a
        constant in-range array element. Mutated, aliased, keyed, or escaped table
        references are deliberately left untouched.
        """
        tokens = self.lexer.tokenize(source)
        sig = self.lexer.significant(tokens)
        edits: list[tuple[int, int, str]] = []
        array_count = 0
        i = 0
        while i + 4 < len(sig):
            if not (
                sig[i].value == "local"
                and sig[i + 1].kind is TokenKind.IDENTIFIER
                and sig[i + 2].value == "="
                and sig[i + 3].value == "{"
            ):
                i += 1
                continue
            name_index = i + 1
            name = sig[name_index].value
            close = self._find_matching_token(sig, i + 3, "{", "}")
            if close is None:
                i += 1
                continue
            entries = parse_string_array(sig[i + 4:close])
            if entries is None:
                i = close + 1
                continue
            local_edits: list[tuple[int, int, str]] = []
            safe = True
            reads = 0
            cursor = 0
            while cursor < len(sig):
                token = sig[cursor]
                if cursor == name_index or token.kind is not TokenKind.IDENTIFIER or token.value != name:
                    cursor += 1
                    continue
                previous = sig[cursor - 1].value if cursor > 0 else ""
                if previous in {".", ":", "::"}:
                    cursor += 1
                    continue
                if (
                    cursor + 3 < len(sig)
                    and sig[cursor + 1].value == "["
                    and sig[cursor + 2].kind is TokenKind.NUMBER
                    and sig[cursor + 3].value == "]"
                ):
                    try:
                        numeric_index = sig[cursor + 2].value.replace("_", "")
                        if numeric_index.lower().startswith("0x"):
                            index_value = int(numeric_index, 16)
                        elif numeric_index.lower().startswith("0b"):
                            index_value = int(numeric_index[2:], 2)
                        else:
                            index_value = int(numeric_index, 10)
                    except ValueError:
                        safe = False
                        break
                    following = sig[cursor + 4].value if cursor + 4 < len(sig) else ""
                    if following in {"=", "+=", "-=", "*=", "/="} or not 1 <= index_value <= len(entries):
                        safe = False
                        break
                    local_edits.append((sig[cursor].start, sig[cursor + 3].end, entries[index_value - 1]))
                    reads += 1
                    cursor += 4
                    continue
                safe = False
                break
            if safe and reads:
                edits.extend(local_edits)
                edits.append((sig[i].start, sig[close].end, ""))
                array_count += 1
            i = close + 1
        return apply_replacements(source, edits), array_count

    @staticmethod
    def _find_matching_token(tokens: list[Token], start: int, opening: str, closing: str) -> int | None:
        depth = 0
        for index in range(start, len(tokens)):
            if tokens[index].value == opening:
                depth += 1
            elif tokens[index].value == closing:
                depth -= 1
                if depth == 0:
                    return index
        return None

    def apply_cipher_to_literals(
        self,
        source: str,
        cipher_name: str,
        parameters: Mapping[str, Any],
        min_printable_ratio: float = 0.88,
        source_encoding: str = "utf-8",
    ) -> tuple[str, int]:
        """Apply a named registered cipher to short/long string literal payloads."""
        if not 0.0 <= min_printable_ratio <= 1.0:
            raise ValueError("min_printable_ratio must be between 0 and 1")
        replacements: list[tuple[int, int, str]] = []
        normalized_encoding = "utf-8" if source_encoding == "utf-8-sig" else source_encoding
        for token in self.lexer.tokenize(source):
            if token.kind is not TokenKind.STRING:
                continue
            decoded = decode_lua_string(token.raw)
            if decoded is None:
                continue
            try:
                payload = lua_string_to_bytes(token.raw, normalized_encoding)
            except (ValueError, UnicodeError):
                continue
            transformed = self.ciphers.decode(cipher_name, payload, parameters)
            if not transformed or printable_ratio(transformed) < min_printable_ratio:
                continue
            try:
                value = transformed.decode("utf-8")
                byte_mode = False
            except UnicodeDecodeError:
                value = transformed.decode("latin-1")
                byte_mode = True
            if transformed != payload:
                replacements.append((token.start, token.end, quote_lua_string(value, byte_mode=byte_mode)))
        return apply_replacements(source, replacements), len(replacements)

    def xor_bytes(self, data: bytes, keys: bytes, offset: int = 0) -> bytes:
        """Apply repeating multi-byte XOR with a deterministic stream offset."""
        if not keys:
            raise ValueError("XOR key cannot be empty")
        return bytes(value ^ keys[(index + offset) % len(keys)] for index, value in enumerate(data))

    def rolling_xor(self, data: bytes, key: int, step: int = 0) -> bytes:
        """Apply a common byte-wise rolling-XOR transform."""
        if not 0 <= key <= 255 or not 0 <= step <= 255:
            raise ValueError("key and step must be byte values")
        return bytes(value ^ ((key + index * step) & 0xFF) for index, value in enumerate(data))

    def xor_literal_payloads(
        self,
        source: str,
        keys: bytes,
        min_printable_ratio: float = 0.88,
        source_encoding: str = "utf-8",
    ) -> tuple[str, int]:
        """Decode repeating multi-byte XOR string literals when text-like."""
        return self.apply_cipher_to_literals(
            source, "xor", {"key": keys}, min_printable_ratio, source_encoding
        )

    def rolling_xor_literal_payloads(
        self,
        source: str,
        key: int,
        step: int = 0,
        min_printable_ratio: float = 0.88,
        source_encoding: str = "utf-8",
    ) -> tuple[str, int]:
        """Decode literals using a byte-wise rolling XOR key stream."""
        return self.apply_cipher_to_literals(
            source, "rolling-xor", {"key": key, "step": step}, min_printable_ratio, source_encoding
        )

    def additive_literal_payloads(
        self,
        source: str,
        key: int,
        step: int = 0,
        min_printable_ratio: float = 0.88,
        source_encoding: str = "utf-8",
    ) -> tuple[str, int]:
        """Decode literals using a repeating additive byte transform."""
        return self.apply_cipher_to_literals(
            source, "additive", {"key": key, "step": step}, min_printable_ratio, source_encoding
        )


def decode_lua_string(raw: str) -> str | None:
    """Decode one Lua short or long string token; return None if malformed."""
    if raw.startswith(("'", '"')):
        if len(raw) < 2 or raw[-1] != raw[0]:
            return None
        body = raw[1:-1]
        result: list[str] = []
        i = 0
        escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"'}
        while i < len(body):
            char = body[i]
            if char != "\\":
                result.append(char)
                i += 1
                continue
            i += 1
            if i >= len(body):
                return None
            esc = body[i]
            if esc in escapes:
                result.append(escapes[esc])
                i += 1
            elif esc == "z":
                i += 1
                while i < len(body) and body[i].isspace():
                    i += 1
            elif esc == "x" and i + 2 < len(body) and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 1:i + 3]):
                result.append(chr(int(body[i + 1:i + 3], 16)))
                i += 3
            elif esc == "u" and i + 1 < len(body) and body[i + 1] == "{":
                close = body.find("}", i + 2)
                if close < 0:
                    return None
                digits = body[i + 2:close]
                try:
                    point = int(digits, 16)
                    result.append(chr(point))
                except (ValueError, OverflowError):
                    return None
                i = close + 1
            elif esc.isdigit():
                end = i
                while end < min(i + 3, len(body)) and body[end].isdigit():
                    end += 1
                value = int(body[i:end], 10)
                if value > 255:
                    return None
                result.append(chr(value))
                i = end
            elif esc in "\r\n":
                if esc == "\r" and i + 1 < len(body) and body[i + 1] == "\n":
                    i += 1
                result.append("\n")
                i += 1
            else:
                return None
        return "".join(result)

    if raw.startswith("["):
        match = re.match(r"\[(=*)\[", raw)
        if not match:
            return None
        delimiter = "]" + match.group(1) + "]"
        if not raw.endswith(delimiter):
            return None
        body = raw[match.end():-len(delimiter)]
        if body.startswith("\r\n"):
            body = body[2:]
        elif body.startswith(("\n", "\r")):
            body = body[1:]
        return body
    return None


def quote_lua_string(value: str, byte_mode: bool = False) -> str:
    """Emit a double-quoted Lua literal.

    In byte mode, Latin-1 code points represent arbitrary string bytes and are
    emitted as decimal escapes to avoid UTF-8 source encoding changing the data.
    """
    out = ['"']
    for char in value:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 32 or code == 127 or (byte_mode and 127 <= code <= 255):
            out.append(f"\\{code:03d}")
        elif code > 0x7E and code > 255:
            out.append(f"\\u{{{code:x}}}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def decode_luraph_style_base85(data: str) -> bytes:
    """Decode five ASCII digits into four bytes using base-85 little-endian limbs.

    This primitive mirrors a common 85-character custom alphabet layout used by
    some Lua protectors. It is not a full Luraph container decoder: framing,
    padding, keys, and subsequent decompression remain protector-specific.
    """
    if len(data) % 5:
        raise ValueError("Base85 payload length must be a multiple of five")
    output = bytearray()
    for offset in range(0, len(data), 5):
        group = data[offset:offset + 5]
        values = [ord(char) - 33 for char in group]
        if any(value < 0 or value >= 85 for value in values):
            raise ValueError(f"Invalid custom base85 character in block at offset {offset}")
        number = sum(value * (85 ** index) for index, value in enumerate(values))
        if number > 0xFFFFFFFF:
            raise ValueError(f"Custom base85 block overflows 32 bits at offset {offset}")
        output.extend(number.to_bytes(4, "little"))
    return bytes(output)


def apply_replacements(source: str, replacements: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping source edits from right to left."""
    ordered = sorted(replacements, key=lambda item: item[0], reverse=True)
    last_start = len(source) + 1
    result = source
    for start, end, text in ordered:
        if not (0 <= start <= end <= len(source)) or end > last_start:
            raise ValueError("Overlapping or invalid source replacement")
        result = result[:start] + text + result[end:]
        last_start = start
    return result


def find_matching_paren(tokens: list[Token], open_index: int) -> int | None:
    """Find the matching ')' in significant tokens."""
    depth = 0
    for index in range(open_index, len(tokens)):
        if tokens[index].value == "(":
            depth += 1
        elif tokens[index].value == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def parse_integer_list(tokens: list[Token]) -> list[int] | None:
    """Parse comma-separated integer literals and no other expressions."""
    if not tokens:
        return []
    values: list[int] = []
    expect_number = True
    for token in tokens:
        if expect_number:
            if token.kind is not TokenKind.NUMBER:
                return None
            raw = token.value.replace("_", "")
            try:
                values.append(int(raw, 0))
            except ValueError:
                return None
        elif token.value != ",":
            return None
        expect_number = not expect_number
    if expect_number:
        return None
    return values


def decode_table_concat(args: list[Token]) -> str | None:
    """Decode table.concat({<integer literals>}) with no custom separator."""
    if len(args) < 2 or args[0].value != "{" or args[-1].value != "}":
        return None
    values = parse_integer_list(args[1:-1])
    if values is None or any(value < 0 or value > 255 for value in values):
        return None
    return bytes(values).decode("latin-1")


def printable_ratio(data: bytes) -> float:
    """Return the fraction of bytes likely to be readable text."""
    if not data:
        return 0.0
    accepted = sum(byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 160 for byte in data)
    return accepted / len(data)


def lua_string_to_bytes(raw: str, source_encoding: str = "utf-8") -> bytes:
    """Decode a Lua literal to its runtime byte sequence.

    Unescaped source characters use the file encoding, numeric and hex escapes
    contribute one raw byte, and Unicode escapes contribute UTF-8 bytes.
    """
    if raw.startswith(("'", '"')):
        if len(raw) < 2 or raw[-1] != raw[0]:
            raise ValueError("Malformed short string literal")
        body = raw[1:-1]
        out = bytearray()
        i = 0
        escapes = {
            "a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
            "\\": 92, "'": 39, '"': 34,
        }
        while i < len(body):
            char = body[i]
            if char != "\\":
                out.extend(char.encode(source_encoding))
                i += 1
                continue
            i += 1
            if i >= len(body):
                raise ValueError("Trailing backslash in string literal")
            esc = body[i]
            if esc in escapes:
                out.append(escapes[esc])
                i += 1
            elif esc == "z":
                i += 1
                while i < len(body) and body[i].isspace():
                    i += 1
            elif esc == "x":
                if i + 2 >= len(body) or not re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 1:i + 3]):
                    raise ValueError("Malformed hexadecimal escape")
                out.append(int(body[i + 1:i + 3], 16))
                i += 3
            elif esc == "u" and i + 1 < len(body) and body[i + 1] == "{":
                close = body.find("}", i + 2)
                if close < 0:
                    raise ValueError("Malformed Unicode escape")
                point = int(body[i + 2:close], 16)
                out.extend(chr(point).encode("utf-8"))
                i = close + 1
            elif esc.isdigit():
                end = i
                while end < min(i + 3, len(body)) and body[end].isdigit():
                    end += 1
                number = int(body[i:end], 10)
                if number > 255:
                    raise ValueError("Decimal escape exceeds one byte")
                out.append(number)
                i = end
            elif esc in "\r\n":
                if esc == "\r" and i + 1 < len(body) and body[i + 1] == "\n":
                    i += 1
                out.append(10)
                i += 1
            else:
                raise ValueError(f"Unsupported Lua escape \\{esc}")
        return bytes(out)

    match = re.match(r"\[(=*)\[", raw)
    if not match:
        raise ValueError("Malformed long string literal")
    close = "]" + match.group(1) + "]"
    if not raw.endswith(close):
        raise ValueError("Malformed long string terminator")
    body = raw[match.end():-len(close)]
    if body.startswith("\r\n"):
        body = body[2:]
    elif body.startswith(("\n", "\r")):
        body = body[1:]
    return body.encode(source_encoding)


def has_high_byte_escape(raw: str) -> bool:
    """Detect numeric/hex escapes that represent bytes outside ASCII."""
    if re.search(r"\\x(?:[89a-fA-F][0-9a-fA-F])", raw):
        return True
    for match in re.finditer(r"\\([0-9]{1,3})", raw):
        if int(match.group(1), 10) > 127:
            return True
    return False


def parse_string_array(tokens: list[Token]) -> list[str] | None:
    """Parse a literal-only positional table constructor."""
    if not tokens:
        return []
    values: list[str] = []
    expect_string = True
    for token in tokens:
        if expect_string:
            if token.value == ",":
                if values and token is tokens[-1]:
                    return values
                return None
            if token.kind is not TokenKind.STRING:
                return None
            if decode_lua_string(token.value) is None:
                return None
            values.append(token.raw)
            expect_string = False
        else:
            if token.value != ",":
                return None
            expect_string = True
    return values


def _xor_cipher(data: bytes, parameters: Mapping[str, Any]) -> bytes:
    key = parameters.get("key")
    if not isinstance(key, bytes) or not key:
        raise ValueError("XOR cipher requires a non-empty bytes 'key'")
    offset = int(parameters.get("offset", 0))
    return bytes(value ^ key[(index + offset) % len(key)] for index, value in enumerate(data))


def _rolling_xor_cipher(data: bytes, parameters: Mapping[str, Any]) -> bytes:
    key = int(parameters.get("key", -1))
    step = int(parameters.get("step", 0))
    if not 0 <= key <= 255 or not 0 <= step <= 255:
        raise ValueError("rolling XOR key and step must be byte values")
    return bytes(value ^ ((key + index * step) & 0xFF) for index, value in enumerate(data))


def _additive_cipher(data: bytes, parameters: Mapping[str, Any]) -> bytes:
    key = int(parameters.get("key", -1))
    step = int(parameters.get("step", 0))
    if not 0 <= key <= 255 or not 0 <= step <= 255:
        raise ValueError("additive key and step must be byte values")
    return bytes((value - ((key + index * step) & 0xFF)) & 0xFF for index, value in enumerate(data))
