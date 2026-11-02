"""Input loading and structural Lua validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import LoadError, ParseError
from .lexer import LuaLexer
from .models import Token, TokenKind


@dataclass(frozen=True, slots=True)
class LoadedSource:
    """Decoded input source and its provenance metadata."""

    text: str
    name: str
    size_bytes: int
    encoding: str


class Loader:
    """Load bounded source files without executing or importing them."""

    def __init__(self, max_bytes: int = 16 * 1024 * 1024) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes

    def load(self, path: str | Path) -> LoadedSource:
        """Read UTF-8 (with BOM) or fall back to Latin-1 for byte preservation."""
        source_path = Path(path)
        try:
            data = source_path.read_bytes()
        except OSError as exc:
            raise LoadError(f"Cannot read {source_path}: {exc}") from exc
        if len(data) > self.max_bytes:
            raise LoadError(
                f"Input is {len(data)} bytes; configured limit is {self.max_bytes} bytes."
            )
        if data.startswith(b"\xef\xbb\xbf"):
            text = data.decode("utf-8-sig")
            encoding = "utf-8-sig"
        else:
            try:
                text = data.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                text = data.decode("latin-1")
                encoding = "latin-1"
        return LoadedSource(text, source_path.name, len(data), encoding)


class LuaParser:
    """Perform structural validation required by conservative transforms.

    This is a delimiter/block validator, not a complete Lua or Luau grammar
    implementation. It does not claim that structurally balanced input compiles.
    """

    _OPEN_BLOCKS = {"if", "function", "do", "repeat"}

    def __init__(self, lexer: LuaLexer | None = None) -> None:
        self.lexer = lexer or LuaLexer()

    def validate(self, source: str) -> list[Token]:
        """Tokenize and reject unbalanced delimiters or block terminators."""
        tokens = self.lexer.tokenize(source)
        significant = self.lexer.significant(tokens)
        delimiter_stack: list[tuple[str, Token]] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        for token in significant:
            if token.kind is TokenKind.SYMBOL and token.value in "([{":
                delimiter_stack.append((token.value, token))
            elif token.kind is TokenKind.SYMBOL and token.value in pairs:
                if not delimiter_stack or delimiter_stack[-1][0] != pairs[token.value]:
                    raise ParseError(
                        f"Unmatched {token.value!r} at line {token.line}, column {token.column}."
                    )
                delimiter_stack.pop()
        if delimiter_stack:
            opener, token = delimiter_stack[-1]
            raise ParseError(
                f"Unclosed {opener!r} from line {token.line}, column {token.column}."
            )

        block_stack: list[str] = []
        for token in significant:
            if token.kind is not TokenKind.KEYWORD:
                continue
            if token.value in self._OPEN_BLOCKS:
                block_stack.append(token.value)
            elif token.value == "end":
                if not block_stack or block_stack[-1] == "repeat":
                    raise ParseError(f"Unexpected 'end' at line {token.line}.")
                block_stack.pop()
            elif token.value == "until":
                if not block_stack or block_stack[-1] != "repeat":
                    raise ParseError(f"Unexpected 'until' at line {token.line}.")
                block_stack.pop()
        if block_stack:
            raise ParseError(f"Unclosed Lua block: {block_stack[-1]!r}.")
        return tokens
