"""Conservative constant folding and opaque-branch elimination."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .lexer import LuaLexer
from .models import Token, TokenKind, TransformEvent
from .strings import apply_replacements, decode_lua_string


_UNKNOWN = object()


class ConstantExpressionEvaluator:
    """Evaluate a bounded subset of side-effect-free Lua constant expressions."""

    _PRECEDENCE = {
        "or": 1,
        "and": 2,
        "<": 3, ">": 3, "<=": 3, ">=": 3, "~=": 3, "==": 3,
        "|": 4,
        "~": 5,
        "&": 6,
        "<<": 7, ">>": 7,
        "..": 8,
        "+": 9, "-": 9,
        "*": 10, "/": 10, "//": 10, "%": 10,
        "^": 12,
    }

    def evaluate(self, tokens: list[Token]) -> Any:
        """Return a Python primitive or a private unknown sentinel."""
        self.tokens = [
            token for token in tokens
            if token.kind not in {TokenKind.WHITESPACE, TokenKind.COMMENT}
        ]
        self.position = 0
        if not self.tokens:
            return _UNKNOWN
        try:
            value = self._parse_expression(1)
        except (ArithmeticError, TypeError, ValueError, OverflowError):
            return _UNKNOWN
        if self.position != len(self.tokens):
            return _UNKNOWN
        return value

    def is_known(self, tokens: list[Token]) -> tuple[bool, Any]:
        """Evaluate an expression and return an explicit known/value pair."""
        value = self.evaluate(tokens)
        return value is not _UNKNOWN, value

    def _parse_expression(self, minimum_precedence: int) -> Any:
        left = self._parse_unary()
        while self.position < len(self.tokens):
            operator = self.tokens[self.position].value
            precedence = self._PRECEDENCE.get(operator)
            if precedence is None or precedence < minimum_precedence:
                break
            self.position += 1
            next_minimum = precedence if operator in {"^", ".."} else precedence + 1
            right = self._parse_expression(next_minimum)
            if left is _UNKNOWN or right is _UNKNOWN:
                left = _UNKNOWN
                continue
            left = self._apply_binary(operator, left, right)
        return left

    def _parse_unary(self) -> Any:
        if self.position < len(self.tokens):
            operator = self.tokens[self.position].value
            if operator in {"not", "-", "~", "#"}:
                self.position += 1
                value = self._parse_expression(3 if operator == "not" else 11)
                if value is _UNKNOWN:
                    return _UNKNOWN
                if operator == "not":
                    return not lua_truthy(value)
                if operator == "-":
                    return -value if isinstance(value, (int, float)) and not isinstance(value, bool) else _UNKNOWN
                if operator == "~":
                    return ~value if isinstance(value, int) and not isinstance(value, bool) else _UNKNOWN
                if operator == "#":
                    if isinstance(value, (str, list, tuple)):
                        return len(value)
                    return _UNKNOWN
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        if self.position >= len(self.tokens):
            return _UNKNOWN
        token = self.tokens[self.position]
        self.position += 1
        if token.value == "(":
            value = self._parse_expression(1)
            if self.position >= len(self.tokens) or self.tokens[self.position].value != ")":
                return _UNKNOWN
            self.position += 1
            return value
        if token.value == "true":
            return True
        if token.value == "false":
            return False
        if token.value == "nil":
            return None
        if token.kind is TokenKind.NUMBER:
            return parse_lua_number(token.value)
        if token.kind is TokenKind.STRING:
            value = decode_lua_string(token.value)
            return _UNKNOWN if value is None else value
        return _UNKNOWN

    @staticmethod
    def _apply_binary(operator: str, left: Any, right: Any) -> Any:
        if operator == "and":
            return right if lua_truthy(left) else left
        if operator == "or":
            return left if lua_truthy(left) else right
        if operator == "==":
            return left == right
        if operator == "~=":
            return left != right
        if operator == "<":
            return left < right
        if operator == ">":
            return left > right
        if operator == "<=":
            return left <= right
        if operator == ">=":
            return left >= right
        if operator == "..":
            if isinstance(left, (str, int, float)) and isinstance(right, (str, int, float)):
                return lua_tostring(left) + lua_tostring(right)
            return _UNKNOWN
        if operator in {"+", "-", "*", "/", "//", "%", "^"}:
            if not is_lua_number(left) or not is_lua_number(right):
                return _UNKNOWN
            if operator == "^" and abs(right) > 128:
                return _UNKNOWN
            operations = {
                "+": lambda: left + right,
                "-": lambda: left - right,
                "*": lambda: left * right,
                "/": lambda: left / right,
                "//": lambda: left // right,
                "%": lambda: left % right,
                "^": lambda: left ** right,
            }
            result = operations[operator]()
            if isinstance(result, float) and not math.isfinite(result):
                return _UNKNOWN
            if isinstance(result, int) and result.bit_length() > 4096:
                return _UNKNOWN
            return result
        if operator in {"&", "|", "~", "<<", ">>"}:
            if not isinstance(left, int) or isinstance(left, bool) or not isinstance(right, int) or isinstance(right, bool):
                return _UNKNOWN
            if operator == "&":
                return left & right
            if operator == "|":
                return left | right
            if operator == "~":
                return left ^ right
            if abs(right) > 1024:
                return _UNKNOWN
            return left << right if operator == "<<" else left >> right
        return _UNKNOWN


def parse_lua_number(raw: str) -> int | float | object:
    """Parse Lua decimal, hexadecimal, and binary numeric literal forms."""
    value = raw.replace("_", "")
    try:
        if value.lower().startswith("0x"):
            if "p" in value.lower() or "." in value:
                return float.fromhex(value)
            return int(value, 16)
        if value.lower().startswith("0b"):
            return int(value, 2)
        if any(char in value for char in ".eE"):
            return float(value)
        return int(value, 10)
    except ValueError:
        return _UNKNOWN


def is_lua_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def lua_truthy(value: Any) -> bool:
    return value is not None and value is not False


def lua_tostring(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True, slots=True)
class _Branch:
    condition: list[Token] | None
    body_start_char: int
    body_end_char: int


class ControlFlowReconstructor:
    """Resolve constant `if` branches while leaving ambiguous code untouched."""

    def __init__(self, lexer: LuaLexer | None = None, max_passes: int = 8) -> None:
        self.lexer = lexer or LuaLexer()
        self.evaluator = ConstantExpressionEvaluator()
        self.max_passes = max_passes

    def reconstruct(self, source: str) -> tuple[str, list[TransformEvent]]:
        """Repeatedly fold statically decidable `if` statements."""
        events: list[TransformEvent] = []
        current = source
        for pass_index in range(self.max_passes):
            tokens = self.lexer.tokenize(current)
            sig = self.lexer.significant(tokens)
            edits: list[tuple[int, int, str]] = []
            i = 0
            while i < len(sig):
                if sig[i].kind is TokenKind.KEYWORD and sig[i].value == "if":
                    resolved = self._resolve_if(current, sig, i)
                    if resolved is not None:
                        end_index, replacement = resolved
                        edits.append((sig[i].start, sig[end_index].end, replacement))
                        i = end_index + 1
                        continue
                i += 1
            if not edits:
                break
            current = apply_replacements(current, edits)
            events.append(
                TransformEvent(
                    "control-flow",
                    "Resolved constant/opaque conditional branch",
                    len(edits),
                    {"pass": pass_index + 1},
                )
            )
        return current, events

    def _resolve_if(self, source: str, sig: list[Token], if_index: int) -> tuple[int, str] | None:
        parsed = self._parse_if(sig, if_index)
        if parsed is None:
            return None
        end_index, branches = parsed
        selected: _Branch | None = None
        decided = False
        for branch in branches:
            if branch.condition is None:
                selected = branch
                decided = True
                break
            known, value = self.evaluator.is_known(branch.condition)
            if not known:
                return None
            if lua_truthy(value):
                selected = branch
                decided = True
                break
        if not decided:
            selected = None
        replacement = ""
        if selected is not None:
            replacement = source[selected.body_start_char:selected.body_end_char]
        return end_index, replacement

    def _parse_if(self, sig: list[Token], if_index: int) -> tuple[int, list[_Branch]] | None:
        then_index = self._find_header_then(sig, if_index + 1)
        if then_index is None:
            return None
        condition = sig[if_index + 1:then_index]
        branches: list[_Branch] = []
        body_start = then_index + 1
        cursor = body_start
        while cursor < len(sig):
            boundary = self._find_branch_boundary(sig, cursor)
            if boundary is None:
                return None
            marker, marker_index = boundary
            branches.append(_Branch(condition, sig[then_index].end if not branches else sig[body_start - 1].end, sig[marker_index].start))
            if marker == "end":
                return marker_index, branches
            if marker == "else":
                end_index = self._find_outer_end(sig, marker_index + 1)
                if end_index < 0:
                    return None
                branches.append(_Branch(None, sig[marker_index].end, sig[end_index].start))
                return end_index, branches
            next_then = self._find_header_then(sig, marker_index + 1)
            if next_then is None:
                return None
            condition = sig[marker_index + 1:next_then]
            body_start = next_then + 1
            cursor = body_start
        return None

    @staticmethod
    def _find_header_then(sig: list[Token], start: int) -> int | None:
        depth = 0
        for index in range(start, len(sig)):
            token = sig[index]
            if token.kind is TokenKind.KEYWORD:
                if token.value in {"function", "if", "do", "repeat"}:
                    depth += 1
                elif token.value == "then":
                    if depth == 0:
                        return index
                elif token.value in {"end", "until"} and depth > 0:
                    depth -= 1
        return None

    @staticmethod
    def _find_branch_boundary(sig: list[Token], start: int) -> tuple[str, int] | None:
        depth = 0
        for index in range(start, len(sig)):
            token = sig[index]
            if token.kind is not TokenKind.KEYWORD:
                continue
            value = token.value
            if depth == 0 and value in {"elseif", "else", "end"}:
                return value, index
            if value in {"function", "if", "do", "repeat"}:
                depth += 1
            elif value in {"end", "until"} and depth > 0:
                depth -= 1
        return None

    @classmethod
    def _find_outer_end(cls, sig: list[Token], start: int) -> int:
        boundary = cls._find_branch_boundary(sig, start)
        if boundary is None or boundary[0] != "end":
            return -1
        return boundary[1]
