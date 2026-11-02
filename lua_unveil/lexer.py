"""Conservative Lua/Luau lexer that retains trivia and source positions."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .errors import LexError
from .models import Token, TokenKind


_KEYWORDS = frozenset(
    {
        "and", "break", "do", "else", "elseif", "end", "false", "for",
        "function", "goto", "if", "in", "local", "nil", "not", "or",
        "repeat", "return", "then", "true", "until", "while",
    }
)
_OPERATORS = (
    "...", "..", "==", "~=", "<=", ">=", "//", "<<", ">>", "::",
    "+=", "-=", "*=", "/=", "%=", "^=", "..=", "->",
)
_NUMBER_RE = re.compile(
    r"(?:"
    r"0[xX][0-9a-fA-F_]+(?:\.[0-9a-fA-F_]*)?(?:[pP][+-]?[0-9_]+)?"
    r"|0[bB][01_]+"
    r"|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?"
    r")"
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class LuaLexer:
    """Tokenize common Lua and Luau syntax without normalizing source text."""

    def tokenize(self, source: str) -> list[Token]:
        """Return all tokens, including whitespace and comments.

        The lexer intentionally does not parse Lua grammar. It recognizes lexical
        constructs needed for safe source-to-source edits and structural analysis.
        """
        tokens: list[Token] = []
        i = 0
        line = 1
        column = 1
        length = len(source)

        while i < length:
            start = i
            start_line = line
            start_column = column
            char = source[i]

            if char.isspace():
                i += 1
                while i < length and source[i].isspace():
                    i += 1
                raw = source[start:i]
                tokens.append(Token(TokenKind.WHITESPACE, raw, raw, start, i, start_line, start_column))
                line, column = self._advance_position(raw, line, column)
                continue

            if source.startswith("--", i):
                long_end = self._long_bracket_end(source, i + 2)
                if long_end is not None:
                    i = long_end
                else:
                    newline = source.find("\n", i)
                    i = length if newline < 0 else newline
                raw = source[start:i]
                tokens.append(Token(TokenKind.COMMENT, raw, raw, start, i, start_line, start_column))
                line, column = self._advance_position(raw, line, column)
                continue

            if char in "'\"":
                i = self._short_string_end(source, i, char)
                raw = source[start:i]
                tokens.append(Token(TokenKind.STRING, raw, raw, start, i, start_line, start_column))
                line, column = self._advance_position(raw, line, column)
                continue

            if char == "[":
                long_end = self._long_bracket_end(source, i)
                if long_end is not None:
                    i = long_end
                    raw = source[start:i]
                    tokens.append(Token(TokenKind.STRING, raw, raw, start, i, start_line, start_column))
                    line, column = self._advance_position(raw, line, column)
                    continue

            identifier = _IDENTIFIER_RE.match(source, i)
            if identifier:
                i = identifier.end()
                raw = source[start:i]
                kind = TokenKind.KEYWORD if raw in _KEYWORDS else TokenKind.IDENTIFIER
                tokens.append(Token(kind, raw, raw, start, i, start_line, start_column))
                column += i - start
                continue

            number = _NUMBER_RE.match(source, i)
            if number:
                i = number.end()
                raw = source[start:i]
                tokens.append(Token(TokenKind.NUMBER, raw, raw, start, i, start_line, start_column))
                column += i - start
                continue

            operator = next((item for item in _OPERATORS if source.startswith(item, i)), None)
            if operator is not None:
                i += len(operator)
                raw = operator
            else:
                i += 1
                raw = source[start:i]
            tokens.append(Token(TokenKind.SYMBOL, raw, raw, start, i, start_line, start_column))
            column += i - start

        return tokens

    @staticmethod
    def significant(tokens: list[Token]) -> list[Token]:
        """Filter trivia while preserving token order."""
        return [token for token in tokens if token.kind not in {TokenKind.WHITESPACE, TokenKind.COMMENT}]

    @staticmethod
    def _advance_position(raw: str, line: int, column: int) -> tuple[int, int]:
        newlines = raw.count("\n")
        if newlines:
            return line + newlines, len(raw.rsplit("\n", 1)[-1]) + 1
        return line, column + len(raw)

    @staticmethod
    def _long_bracket_end(source: str, start: int) -> int | None:
        if start >= len(source) or source[start] != "[":
            return None
        cursor = start + 1
        while cursor < len(source) and source[cursor] == "=":
            cursor += 1
        if cursor >= len(source) or source[cursor] != "[":
            return None
        close = "]" + ("=" * (cursor - start - 1)) + "]"
        end = source.find(close, cursor + 1)
        if end < 0:
            raise LexError(f"Unterminated long bracket at character {start}.")
        return end + len(close)

    @staticmethod
    def _short_string_end(source: str, start: int, quote: str) -> int:
        i = start + 1
        while i < len(source):
            char = source[i]
            if char == quote:
                return i + 1
            if char == "\\":
                i += 1
                if i >= len(source):
                    break
                if source[i] == "z":
                    i += 1
                    while i < len(source) and source[i].isspace():
                        i += 1
                    continue
                if source[i] == "\r" and i + 1 < len(source) and source[i + 1] == "\n":
                    i += 2
                    continue
                i += 1
                continue
            if char in "\r\n":
                raise LexError(f"Unescaped newline in short string at character {start}.")
            i += 1
        raise LexError(f"Unterminated short string at character {start}.")
