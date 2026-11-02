"""Profile-driven stack-VM decoder, verifier, and conservative devirtualizer."""

from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import VMError


@dataclass(frozen=True, slots=True)
class VMInstructionSpec:
    """Opcode metadata used to decode a variable-width instruction."""

    mnemonic: str
    operands: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VMInstruction:
    """A decoded instruction at a bytecode offset."""

    offset: int
    opcode: int
    mnemonic: str
    operands: tuple[int, ...]
    size: int


@dataclass(frozen=True, slots=True)
class VMProgram:
    """Decoded bytecode plus verified instruction-level stack information."""

    instructions: tuple[VMInstruction, ...]
    stack_depths: dict[int, int]
    profile_name: str


@dataclass(frozen=True, slots=True)
class VMProfile:
    """A declarative opcode profile; it never executes user-defined code."""

    name: str
    opcodes: dict[int, VMInstructionSpec]

    @classmethod
    def stack_v1(cls) -> "VMProfile":
        """Return the built-in portable stack bytecode profile."""
        specs = {
            0x01: VMInstructionSpec("PUSH_CONST", ("u16",)),
            0x02: VMInstructionSpec("PUSH_INT", ("i32",)),
            0x03: VMInstructionSpec("LOAD_LOCAL", ("u8",)),
            0x04: VMInstructionSpec("STORE_LOCAL", ("u8",)),
            0x10: VMInstructionSpec("ADD"),
            0x11: VMInstructionSpec("SUB"),
            0x12: VMInstructionSpec("MUL"),
            0x13: VMInstructionSpec("DIV"),
            0x14: VMInstructionSpec("MOD"),
            0x15: VMInstructionSpec("POW"),
            0x16: VMInstructionSpec("CONCAT"),
            0x17: VMInstructionSpec("EQ"),
            0x18: VMInstructionSpec("LT"),
            0x19: VMInstructionSpec("LE"),
            0x1A: VMInstructionSpec("NOT"),
            0x1B: VMInstructionSpec("NEG"),
            0x20: VMInstructionSpec("DUP"),
            0x21: VMInstructionSpec("POP"),
            0x30: VMInstructionSpec("JMP", ("i16",)),
            0x31: VMInstructionSpec("JUMP_IF_FALSE", ("i16",)),
            0x40: VMInstructionSpec("RETURN"),
            0x41: VMInstructionSpec("RETURN_VOID"),
        }
        return cls("stack-v1", specs)

    @classmethod
    def from_json(cls, path: str | Path) -> "VMProfile":
        """Load a JSON profile containing only known instruction formats."""
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VMError(f"Cannot load VM profile {path}: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("opcodes"), dict):
            raise VMError("VM profile must contain an 'opcodes' object")
        opcodes: dict[int, VMInstructionSpec] = {}
        for raw_opcode, raw_spec in raw["opcodes"].items():
            try:
                opcode = int(raw_opcode, 0)
            except (TypeError, ValueError) as exc:
                raise VMError(f"Invalid opcode value: {raw_opcode!r}") from exc
            if not 0 <= opcode <= 255 or not isinstance(raw_spec, dict):
                raise VMError(f"Invalid opcode specification for {raw_opcode!r}")
            mnemonic = raw_spec.get("mnemonic")
            operands = raw_spec.get("operands", [])
            if not isinstance(mnemonic, str) or not mnemonic.isidentifier():
                raise VMError(f"Invalid mnemonic for opcode {raw_opcode!r}")
            if not isinstance(operands, list) or any(item not in {"u8", "i8", "u16", "i16", "u32", "i32"} for item in operands):
                raise VMError(f"Invalid operand format for opcode {raw_opcode!r}")
            opcodes[opcode] = VMInstructionSpec(mnemonic.upper(), tuple(operands))
        return cls(str(raw.get("name", "custom-profile")), opcodes)


class VMDecoder:
    """Decode and verify the profile's bytecode without executing it."""

    _FORMATS = {
        "u8": (1, "<B"), "i8": (1, "<b"),
        "u16": (2, "<H"), "i16": (2, "<h"),
        "u32": (4, "<I"), "i32": (4, "<i"),
    }
    _BINARY_OPS = {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "CONCAT", "EQ", "LT", "LE"}
    _UNARY_OPS = {"NOT", "NEG"}

    def __init__(self, profile: VMProfile | None = None) -> None:
        self.profile = profile or VMProfile.stack_v1()

    def decode(self, bytecode: bytes) -> VMProgram:
        """Decode all instructions and verify branch targets and stack depth."""
        instructions: list[VMInstruction] = []
        offset = 0
        while offset < len(bytecode):
            start = offset
            opcode = bytecode[offset]
            offset += 1
            spec = self.profile.opcodes.get(opcode)
            if spec is None:
                raise VMError(f"Unknown opcode 0x{opcode:02x} at byte offset 0x{start:x}")
            operands: list[int] = []
            for operand_format in spec.operands:
                size, fmt = self._FORMATS[operand_format]
                if offset + size > len(bytecode):
                    raise VMError(f"Truncated {spec.mnemonic} operand at byte offset 0x{start:x}")
                operands.append(struct.unpack_from(fmt, bytecode, offset)[0])
                offset += size
            instructions.append(
                VMInstruction(start, opcode, spec.mnemonic, tuple(operands), offset - start)
            )

        if not instructions:
            raise VMError("Bytecode is empty")
        by_offset = {instruction.offset: instruction for instruction in instructions}
        bytecode_end = len(bytecode)
        for instruction in instructions:
            if instruction.mnemonic in {"JMP", "JUMP_IF_FALSE"}:
                target = instruction.offset + instruction.size + instruction.operands[0]
                if target not in by_offset and target != bytecode_end:
                    raise VMError(
                        f"Branch at 0x{instruction.offset:x} targets non-instruction offset 0x{target:x}"
                    )
        depths = self._verify_stack(instructions, by_offset, bytecode_end)
        return VMProgram(tuple(instructions), depths, self.profile.name)

    def _verify_stack(
        self,
        instructions: list[VMInstruction],
        by_offset: dict[int, VMInstruction],
        bytecode_end: int,
    ) -> dict[int, int]:
        worklist: list[tuple[int, int]] = [(instructions[0].offset, 0)]
        depths: dict[int, int] = {}
        while worklist:
            offset, depth = worklist.pop()
            if offset == bytecode_end:
                continue
            existing = depths.get(offset)
            if existing is not None:
                if existing != depth:
                    raise VMError(f"Inconsistent stack depth at control-flow merge 0x{offset:x}")
                continue
            depths[offset] = depth
            instruction = by_offset[offset]
            delta, minimum = stack_effect(instruction)
            if depth < minimum:
                raise VMError(f"Stack underflow at 0x{offset:x} ({instruction.mnemonic})")
            next_depth = depth + delta
            next_offset = offset + instruction.size
            if instruction.mnemonic == "JMP":
                worklist.append((next_offset + instruction.operands[0], next_depth))
            elif instruction.mnemonic == "JUMP_IF_FALSE":
                worklist.append((next_offset + instruction.operands[0], next_depth))
                worklist.append((next_offset, next_depth))
            elif instruction.mnemonic not in {"RETURN", "RETURN_VOID"}:
                worklist.append((next_offset, next_depth))
        return depths


class StackVMDevirtualizer:
    """Lift verified stack bytecode into readable Lua or symbolic expressions."""

    def __init__(self, decoder: VMDecoder | None = None) -> None:
        self.decoder = decoder or VMDecoder()

    def devirtualize(
        self,
        bytecode: bytes,
        constants: list[Any] | None = None,
    ) -> tuple[VMProgram, str, str]:
        """Decode bytecode and return (program, output, lifting mode).

        Straight-line bytecode is symbolically lifted to ordinary local-variable
        expressions. Programs with branches are emitted as a label-based Lua
        stack interpreter, preserving bytecode control flow rather than guessing
        a higher-level source structure.
        """
        program = self.decoder.decode(bytecode)
        constant_pool = constants or []
        has_control_flow = any(
            instruction.mnemonic in {"JMP", "JUMP_IF_FALSE"}
            for instruction in program.instructions
        )
        if has_control_flow:
            return program, self._emit_control_flow(program, constant_pool, len(bytecode)), "dispatcher"
        return program, self._lift_linear(program, constant_pool), "symbolic"

    def _lift_linear(self, program: VMProgram, constants: list[Any]) -> str:
        stack: list[str] = []
        locals_map: dict[int, str] = {}
        lines = ["-- Lua Unveil: symbolic stack-VM lift"]
        temp = 0

        def new_temp(expression: str) -> str:
            nonlocal temp
            temp += 1
            name = f"value_{temp:04d}"
            lines.append(f"local {name} = {expression}")
            return name

        for instruction in program.instructions:
            op = instruction.mnemonic
            arg = instruction.operands[0] if instruction.operands else None
            if op == "PUSH_CONST":
                if arg is None or arg >= len(constants):
                    raise VMError(f"Constant index {arg} is outside the supplied constant pool")
                stack.append(lua_literal(constants[arg]))
            elif op == "PUSH_INT":
                stack.append(str(arg))
            elif op == "LOAD_LOCAL":
                if arg not in locals_map:
                    name = f"local_{arg:03d}"
                    locals_map[arg] = name
                    lines.append(f"local {name}")
                stack.append(locals_map[arg])
            elif op == "STORE_LOCAL":
                value = pop_stack(stack, instruction)
                name = locals_map.get(arg)
                if name is None:
                    name = f"local_{arg:03d}"
                    locals_map[arg] = name
                    lines.append(f"local {name} = {value}")
                else:
                    lines.append(f"{name} = {value}")
            elif op in VMDecoder._BINARY_OPS:
                right = pop_stack(stack, instruction)
                left = pop_stack(stack, instruction)
                expression = render_binary(op, left, right)
                stack.append(new_temp(expression))
            elif op in VMDecoder._UNARY_OPS:
                operand = pop_stack(stack, instruction)
                expression = f"not {operand}" if op == "NOT" else f"(-{operand})"
                stack.append(new_temp(expression))
            elif op == "DUP":
                if not stack:
                    raise VMError(f"Stack underflow at 0x{instruction.offset:x}")
                stack.append(stack[-1])
            elif op == "POP":
                pop_stack(stack, instruction)
            elif op == "RETURN":
                lines.append(f"return {pop_stack(stack, instruction)}")
            elif op == "RETURN_VOID":
                lines.append("return")
            else:
                raise VMError(f"Cannot symbolically lift opcode {op!r}")
        if not any(line.strip().startswith("return") for line in lines):
            lines.append("-- No explicit return instruction in this bytecode.")
        return "\n".join(lines) + "\n"

    def _emit_control_flow(self, program: VMProgram, constants: list[Any], bytecode_length: int) -> str:
        lines = [
            "-- Lua Unveil: verified stack-VM dispatcher lift",
            "-- This preserves bytecode semantics; it is not a reconstruction of original source.",
            f"local constants = {lua_literal(constants)}",
            "local stack, top, locals = {}, 0, {}",
        ]
        for instruction in program.instructions:
            lines.append(f"::L_{instruction.offset:06X}::")
            lines.append(f"-- {instruction.mnemonic} at bytecode offset 0x{instruction.offset:x}")
            op = instruction.mnemonic
            args = instruction.operands
            next_offset = instruction.offset + instruction.size
            if op == "PUSH_CONST":
                lines.append(f"top = top + 1; stack[top] = constants[{args[0] + 1}]")
            elif op == "PUSH_INT":
                lines.append(f"top = top + 1; stack[top] = {args[0]}")
            elif op == "LOAD_LOCAL":
                lines.append(f"top = top + 1; stack[top] = locals[{args[0]}]")
            elif op == "STORE_LOCAL":
                lines.append(f"locals[{args[0]}] = stack[top]; stack[top] = nil; top = top - 1")
            elif op in VMDecoder._BINARY_OPS:
                expr = runtime_binary(op, "stack[top - 1]", "stack[top]")
                lines.append(f"stack[top - 1] = {expr}; stack[top] = nil; top = top - 1")
            elif op == "NOT":
                lines.append("stack[top] = not stack[top]")
            elif op == "NEG":
                lines.append("stack[top] = -stack[top]")
            elif op == "DUP":
                lines.append("top = top + 1; stack[top] = stack[top - 1]")
            elif op == "POP":
                lines.append("stack[top] = nil; top = top - 1")
            elif op == "JMP":
                target = next_offset + args[0]
                if target == bytecode_length:
                    lines.append("return")
                else:
                    lines.append(f"goto L_{target:06X}")
            elif op == "JUMP_IF_FALSE":
                target = next_offset + args[0]
                if target == bytecode_length:
                    lines.append("if not stack[top] then stack[top] = nil; top = top - 1; return end")
                    lines.append("stack[top] = nil; top = top - 1")
                else:
                    lines.append(f"if not stack[top] then stack[top] = nil; top = top - 1; goto L_{target:06X} end")
                    lines.append("stack[top] = nil; top = top - 1")
            elif op == "RETURN":
                lines.append("return stack[top]")
            elif op == "RETURN_VOID":
                lines.append("return")
            else:
                raise VMError(f"No runtime emitter for opcode {op!r}")
            if op not in {"JMP", "RETURN", "RETURN_VOID"} and next_offset < bytecode_length:
                lines.append(f"goto L_{next_offset:06X}")
            elif op not in {"JMP", "RETURN", "RETURN_VOID"} and next_offset == bytecode_length:
                lines.append("return")
        return "\n".join(lines) + "\n"


def stack_effect(instruction: VMInstruction) -> tuple[int, int]:
    """Return (net stack delta, minimum input depth) for an opcode."""
    op = instruction.mnemonic
    if op in {"PUSH_CONST", "PUSH_INT", "LOAD_LOCAL"}:
        return 1, 0
    if op == "STORE_LOCAL" or op == "POP" or op == "JUMP_IF_FALSE" or op == "RETURN":
        return -1, 1
    if op in VMDecoder._BINARY_OPS:
        return -1, 2
    if op in VMDecoder._UNARY_OPS:
        return 0, 1
    if op == "DUP":
        return 1, 1
    if op in {"JMP", "RETURN_VOID"}:
        return 0, 0
    raise VMError(f"No stack-effect definition for opcode {op!r}")


def pop_stack(stack: list[str], instruction: VMInstruction) -> str:
    if not stack:
        raise VMError(f"Symbolic stack underflow at 0x{instruction.offset:x}")
    return stack.pop()


def lua_literal(value: Any) -> str:
    """Serialize JSON-like constants as Lua literals."""
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise VMError("Non-finite numeric constants are not supported")
        return repr(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
        return f'"{escaped}"'
    if isinstance(value, list):
        return "{" + ", ".join(lua_literal(item) for item in value) + "}"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise VMError("Only string-keyed dictionaries can be emitted as Lua tables")
        return "{" + ", ".join(f"[{lua_literal(key)}] = {lua_literal(item)}" for key, item in value.items()) + "}"
    raise VMError(f"Unsupported constant type: {type(value).__name__}")


def render_binary(opcode: str, left: str, right: str) -> str:
    operators = {
        "ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%",
        "POW": "^", "CONCAT": "..", "EQ": "==", "LT": "<", "LE": "<=",
    }
    return f"({left} {operators[opcode]} {right})"


def runtime_binary(opcode: str, left: str, right: str) -> str:
    return render_binary(opcode, left, right)
