"""Conservative cleanup and symbol renaming."""

from __future__ import annotations

import re
from collections import Counter

from .lexer import LuaLexer
from .models import Token, TokenKind, TransformEvent
from .strings import apply_replacements


class Cleaner:
    """Apply safe lexical cleanup and optionally rename unambiguous locals."""

    def __init__(self, lexer: LuaLexer | None = None) -> None:
        self.lexer = lexer or LuaLexer()

    def clean(self, source: str, rename: bool = False) -> tuple[str, list[TransformEvent]]:
        """Run conservative identifier cleanup.

        Renaming is opt-in. Only identifiers with one declaration in the entire
        source and a deliberately obfuscated-looking spelling are considered.
        Ambiguous, shadowed, member, and table-key occurrences are left alone.
        """
        if not rename:
            return source, []
        tokens = self.lexer.tokenize(source)
        sig = self.lexer.significant(tokens)
        declarations = self._collect_declarations(sig)
        declaration_counts = Counter(name for name, _, _ in declarations)
        used_names = {token.value for token in sig if token.kind is TokenKind.IDENTIFIER}
        replacements: list[tuple[int, int, str]] = []
        renamed = 0
        serials = {"local": 0, "argument": 0, "function": 0}

        for name, token_index, role in declarations:
            if declaration_counts[name] != 1 or not self._looks_obfuscated(name):
                continue
            candidate = self._next_name(role, serials, used_names)
            used_names.add(candidate)
            for index, token in enumerate(sig):
                if token.kind is not TokenKind.IDENTIFIER or token.value != name:
                    continue
                if index != token_index and self._is_non_binding_identifier(sig, index):
                    continue
                replacements.append((token.start, token.end, candidate))
            renamed += 1

        if not replacements:
            return source, []
        cleaned = apply_replacements(source, replacements)
        return cleaned, [
            TransformEvent(
                "renamer",
                "Renamed unambiguous obfuscated local symbols",
                renamed,
                {"identifier_replacements": len(replacements)},
            )
        ]

    def _collect_declarations(self, sig: list[Token]) -> list[tuple[str, int, str]]:
        declarations: list[tuple[str, int, str]] = []
        i = 0
        while i < len(sig):
            token = sig[i]
            if token.kind is TokenKind.KEYWORD and token.value == "local":
                cursor = i + 1
                if cursor < len(sig) and sig[cursor].value == "function":
                    cursor += 1
                    if cursor < len(sig) and sig[cursor].kind is TokenKind.IDENTIFIER:
                        declarations.append((sig[cursor].value, cursor, "function"))
                    open_paren = self._find_next_value(sig, cursor + 1, "(")
                    if open_paren is not None:
                        close_paren = self._matching(sig, open_paren, "(", ")")
                        if close_paren is not None:
                            for param_index in self._parameter_indices(sig, open_paren + 1, close_paren):
                                declarations.append((sig[param_index].value, param_index, "argument"))
                            i = close_paren
                        else:
                            i = cursor + 1
                    else:
                        i = cursor + 1
                    continue
                while cursor < len(sig):
                    if sig[cursor].kind is not TokenKind.IDENTIFIER:
                        break
                    declarations.append((sig[cursor].value, cursor, "local"))
                    cursor += 1
                    if cursor < len(sig) and sig[cursor].value == ":":
                        break
                    if cursor < len(sig) and sig[cursor].value == ",":
                        cursor += 1
                        continue
                    break
            elif token.kind is TokenKind.KEYWORD and token.value == "function":
                open_paren = self._find_next_value(sig, i + 1, "(")
                if open_paren is not None:
                    close_paren = self._matching(sig, open_paren, "(", ")")
                    if close_paren is not None:
                        for param_index in self._parameter_indices(sig, open_paren + 1, close_paren):
                            declarations.append((sig[param_index].value, param_index, "argument"))
            elif token.kind is TokenKind.KEYWORD and token.value == "for":
                cursor = i + 1
                while cursor < len(sig) and sig[cursor].value not in {"=", "in", "do"}:
                    if sig[cursor].kind is TokenKind.IDENTIFIER:
                        declarations.append((sig[cursor].value, cursor, "local"))
                    if sig[cursor].value not in {",", "<", ">", "const", "close"}:
                        if sig[cursor].kind is not TokenKind.IDENTIFIER:
                            break
                    cursor += 1
            i += 1
        return declarations

    @staticmethod
    def _find_next_value(sig: list[Token], start: int, value: str) -> int | None:
        for index in range(start, len(sig)):
            if sig[index].value == value:
                return index
            if sig[index].value in {";", "then", "do"}:
                return None
        return None

    @staticmethod
    def _matching(sig: list[Token], start: int, opening: str, closing: str) -> int | None:
        depth = 0
        for index in range(start, len(sig)):
            if sig[index].value == opening:
                depth += 1
            elif sig[index].value == closing:
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _parameter_indices(sig: list[Token], start: int, end: int) -> list[int]:
        result: list[int] = []
        expect_name = True
        for index in range(start, end):
            token = sig[index]
            if expect_name and token.kind is TokenKind.IDENTIFIER:
                result.append(index)
                expect_name = False
            elif token.value == ",":
                expect_name = True
            elif token.value == "...":
                expect_name = False
        return result

    @staticmethod
    def _is_non_binding_identifier(sig: list[Token], index: int) -> bool:
        previous = sig[index - 1].value if index > 0 else ""
        following = sig[index + 1].value if index + 1 < len(sig) else ""
        if previous in {".", ":", "::"}:
            return True
        if following == "=" and previous in {"{", ",", ";"}:
            return True
        if following == "::":
            return True
        return False

    @staticmethod
    def _looks_obfuscated(name: str) -> bool:
        if len(name) <= 2:
            return True
        if re.fullmatch(r"_?0[xX][0-9a-fA-F_]{4,}", name):
            return True
        if re.fullmatch(r"[A-Za-z]{1,2}\d{2,}", name):
            return True
        return len(name) >= 18 and len(set(name)) <= 8

    @staticmethod
    def _next_name(role: str, serials: dict[str, int], used: set[str]) -> str:
        prefix = {"local": "local", "argument": "arg", "function": "function"}[role]
        while True:
            serials[role] += 1
            name = f"{prefix}_{serials[role]:03d}"
            if name not in used:
                return name
