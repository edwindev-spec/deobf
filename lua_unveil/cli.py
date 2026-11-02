"""Command-line interface for Lua Unveil."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Sequence

from .errors import LuaUnveilError
from .pipeline import Deobfuscator, DeobfuscatorConfig
from .vm import StackVMDevirtualizer, VMDecoder, VMProfile

_LOG = logging.getLogger("lua_unveil")


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the complete argparse interface."""
    parser = argparse.ArgumentParser(
        prog="lua-unveil",
        description="Static Lua/Luau deobfuscation and profile-driven stack-VM analysis.",
        epilog="Input is never executed. VM lifting requires a compatible bytecode profile.",
    )
    parser.add_argument("input", nargs="?", help="Lua/Luau source file")
    parser.add_argument("-o", "--output", help="Output file (Lua source or VM lift)")
    parser.add_argument("--report", help="Write a JSON analysis report")
    parser.add_argument("--max-layers", type=int, default=4, help="Maximum iterative passes (1-32)")
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024, help="Maximum source size")
    parser.add_argument("--rename", action="store_true", help="Rename uniquely declared obfuscated locals")
    parser.add_argument("--no-literal-normalization", action="store_true", help="Keep Lua escape sequences unchanged")
    parser.add_argument("--no-char-folding", action="store_true", help="Do not fold string.char/utf8.char/table.concat")
    parser.add_argument("--no-control-flow", action="store_true", help="Disable static conditional reconstruction")
    parser.add_argument(
        "--xor-key",
        action="append",
        default=[],
        metavar="BYTE",
        help="Opt-in repeating XOR key byte (decimal or 0x-prefixed); may be repeated",
    )
    parser.add_argument("--rolling-xor-key", type=parse_byte, help="Opt-in rolling-XOR byte key")
    parser.add_argument("--rolling-xor-step", type=parse_byte, default=0, help="Rolling-XOR key increment")
    parser.add_argument("--additive-key", type=parse_byte, help="Opt-in subtractive byte-cipher key")
    parser.add_argument("--additive-step", type=parse_byte, default=0, help="Additive key increment")
    parser.add_argument(
        "--xor-printable-ratio",
        type=float,
        default=0.88,
        help="Minimum printable output ratio for XOR literal replacement (default: 0.88)",
    )
    parser.add_argument("--vm-bytecode", help="Analyze a raw stack-v1 or profiled bytecode file")
    parser.add_argument("--vm-profile", help="JSON opcode profile; defaults to built-in stack-v1")
    parser.add_argument("--constants", help="JSON array used as the VM constant pool")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    parser.add_argument("--version", action="version", version="Lua Unveil 1.0.0")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI operations and convert expected failures into exit codes."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        if args.vm_bytecode:
            if args.input:
                parser.error("Do not combine positional input with --vm-bytecode")
            return _run_vm(args)
        if not args.input:
            parser.error("Provide a Lua source file or --vm-bytecode")
        keys = tuple(parse_byte(value) for value in args.xor_key)
        config = DeobfuscatorConfig(
            max_layers=args.max_layers,
            max_source_bytes=args.max_bytes,
            normalize_literals=not args.no_literal_normalization,
            fold_char_calls=not args.no_char_folding,
            reconstruct_control_flow=not args.no_control_flow,
            rename_identifiers=args.rename,
            xor_keys=keys,
            rolling_xor_key=args.rolling_xor_key,
            rolling_xor_step=args.rolling_xor_step,
            additive_key=args.additive_key,
            additive_step=args.additive_step,
            min_xor_printable_ratio=args.xor_printable_ratio,
        )
        result = Deobfuscator(config).deobfuscate_file(args.input)
        output_path = Path(args.output) if args.output else default_output_path(args.input)
        output_encoding = result.report.detected_encodings
        output_path.write_text(result.source, encoding=output_encoding, newline="")
        _LOG.info("Wrote transformed source to %s", output_path)
        for finding in result.report.findings:
            _LOG.info("Fingerprint: %s (confidence %.2f)", finding.name, finding.confidence)
            for evidence in finding.evidence:
                _LOG.debug("  evidence: %s", evidence)
        for event in result.report.events:
            _LOG.info("%s: %s (%d)", event.stage, event.description, event.count)
        for warning in result.report.warnings:
            _LOG.warning("%s", warning)
        if args.report:
            Path(args.report).write_text(
                json.dumps(result.report.to_dict(), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            _LOG.info("Wrote report to %s", args.report)
        return 0
    except (LuaUnveilError, OSError, ValueError, json.JSONDecodeError) as exc:
        _LOG.error("%s", exc)
        return 2


def _run_vm(args: argparse.Namespace) -> int:
    bytecode_path = Path(args.vm_bytecode)
    try:
        bytecode = bytecode_path.read_bytes()
    except OSError as exc:
        raise LuaUnveilError(f"Cannot read VM bytecode {bytecode_path}: {exc}") from exc
    profile = VMProfile.from_json(args.vm_profile) if args.vm_profile else VMProfile.stack_v1()
    constants: list[object] = []
    if args.constants:
        parsed = json.loads(Path(args.constants).read_text(encoding="utf-8"))
        if not isinstance(parsed, list):
            raise ValueError("--constants must point to a JSON array")
        constants = parsed
    lifter = StackVMDevirtualizer(VMDecoder(profile))
    program, output, mode = lifter.devirtualize(bytecode, constants)
    output_path = Path(args.output) if args.output else bytecode_path.with_suffix(".lifted.lua")
    output_path.write_text(output, encoding="utf-8", newline="")
    _LOG.info(
        "Decoded %d instructions using profile %s; lift mode=%s; max verified stack depth=%d",
        len(program.instructions),
        program.profile_name,
        mode,
        max(program.stack_depths.values(), default=0),
    )
    _LOG.info("Wrote VM lift to %s", output_path)
    if args.report:
        report = {
            "profile": program.profile_name,
            "instruction_count": len(program.instructions),
            "stack_depths": {hex(key): value for key, value in program.stack_depths.items()},
            "lift_mode": mode,
            "instructions": [
                {
                    "offset": item.offset,
                    "opcode": item.opcode,
                    "mnemonic": item.mnemonic,
                    "operands": list(item.operands),
                    "size": item.size,
                }
                for item in program.instructions
            ],
        }
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


def parse_byte(value: str) -> int:
    """Parse a CLI byte value expressed in decimal or Python-style base notation."""
    try:
        result = int(value, 0)
    except ValueError:
        result = int(value, 10)
    if not 0 <= result <= 255:
        raise ValueError(f"XOR key must be a byte value: {value}")
    return result


def default_output_path(input_path: str) -> Path:
    path = Path(input_path)
    return path.with_name(path.stem + ".deobfuscated.lua")
