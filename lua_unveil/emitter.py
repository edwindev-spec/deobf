"""Lua source and VM intermediate-representation emitters."""

from __future__ import annotations

from .models import Token


class Emitter:
    """Emit transformed Lua while retaining untouched whitespace/comments."""

    def emit(self, source: str) -> str:
        """Return source as transformed by preceding source-preserving passes."""
        return source

    def emit_tokens(self, tokens: list[Token]) -> str:
        """Concatenate original token spellings in source order."""
        return "".join(token.raw for token in tokens)

    @staticmethod
    def emit_vm_listing(program: object) -> str:
        """Render a decoded VM program as a readable, non-executable listing."""
        instructions = getattr(program, "instructions")
        lines = ["-- Lua Unveil VM disassembly", "-- Offsets are byte offsets; operands are decoded values."]
        for instruction in instructions:
            args = ", ".join(repr(value) for value in instruction.operands)
            lines.append(f"-- {instruction.offset:06x}: {instruction.mnemonic:<16} {args}".rstrip())
        return "\n".join(lines) + "\n"
