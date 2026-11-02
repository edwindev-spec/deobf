"""Orchestration layer for static Lua deobfuscation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .cleaner import Cleaner
from .emitter import Emitter
from .fingerprint import ObfuscatorDetector
from .flow import ControlFlowReconstructor
from .lexer import LuaLexer
from .loader import Loader, LuaParser
from .models import AnalysisReport, TransformEvent
from .strings import StringDecryptor


@dataclass(frozen=True, slots=True)
class DeobfuscatorConfig:
    """Runtime configuration for the static transformation pipeline."""

    max_layers: int = 4
    max_source_bytes: int = 16 * 1024 * 1024
    normalize_literals: bool = True
    fold_char_calls: bool = True
    reconstruct_control_flow: bool = True
    rename_identifiers: bool = False
    xor_keys: tuple[int, ...] = ()
    rolling_xor_key: int | None = None
    rolling_xor_step: int = 0
    additive_key: int | None = None
    additive_step: int = 0
    min_xor_printable_ratio: float = 0.88

    def __post_init__(self) -> None:
        if self.max_layers < 1 or self.max_layers > 32:
            raise ValueError("max_layers must be between 1 and 32")
        if self.max_source_bytes <= 0:
            raise ValueError("max_source_bytes must be positive")
        if any(not 0 <= key <= 255 for key in self.xor_keys):
            raise ValueError("XOR keys must be byte values")
        for key in (self.rolling_xor_key, self.additive_key):
            if key is not None and not 0 <= key <= 255:
                raise ValueError("Cipher keys must be byte values")
        if not 0 <= self.rolling_xor_step <= 255 or not 0 <= self.additive_step <= 255:
            raise ValueError("Cipher steps must be byte values")
        if not 0.0 <= self.min_xor_printable_ratio <= 1.0:
            raise ValueError("min_xor_printable_ratio must be between 0 and 1")


@dataclass(slots=True)
class DeobfuscationResult:
    """Transformed Lua source and its analysis report."""

    source: str
    report: AnalysisReport


class Deobfuscator:
    """Coordinate independent analysis and transformation stages."""

    def __init__(self, config: DeobfuscatorConfig | None = None) -> None:
        self.config = config or DeobfuscatorConfig()
        self.lexer = LuaLexer()
        self.loader = Loader(self.config.max_source_bytes)
        self.parser = LuaParser(self.lexer)
        self.detector = ObfuscatorDetector()
        self.strings = StringDecryptor(self.lexer)
        self.flow = ControlFlowReconstructor(self.lexer)
        self.cleaner = Cleaner(self.lexer)
        self.emitter = Emitter()

    def deobfuscate_file(self, path: str | Path) -> DeobfuscationResult:
        """Load and deobfuscate a file without executing the input."""
        loaded = self.loader.load(path)
        return self.deobfuscate_source(
            loaded.text,
            source_name=loaded.name,
            source_bytes=loaded.size_bytes,
            encoding=loaded.encoding,
        )

    def deobfuscate_source(
        self,
        source: str,
        source_name: str = "<memory>",
        source_bytes: int | None = None,
        encoding: str = "unicode",
    ) -> DeobfuscationResult:
        """Run iterative static transformations and capture every applied pass."""
        report = AnalysisReport(
            source_name=source_name,
            source_bytes=source_bytes if source_bytes is not None else len(source.encode("utf-8")),
            detected_encodings=encoding,
        )
        report.findings = self.detector.detect(source)
        current = source
        try:
            self.parser.validate(current)
        except Exception as exc:
            report.syntax_structure_valid = False
            report.warnings.append(f"Initial structural validation: {exc}")

        for layer in range(self.config.max_layers):
            before = current
            layer_events: list[TransformEvent] = []

            if self.config.normalize_literals:
                current, count = self.strings.normalize_literals(current)
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Normalized Lua string escape sequences", count)
                    )

            if self.config.fold_char_calls:
                current, count = self.strings.decode_char_calls(current)
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Folded constant string/UTF-8 construction calls", count)
                    )
                current, count = self.strings.decode_string_arrays(current)
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Resolved immutable local string arrays", count)
                    )

            if self.config.xor_keys:
                current, count = self.strings.xor_literal_payloads(
                    current,
                    bytes(self.config.xor_keys),
                    self.config.min_xor_printable_ratio,
                    "utf-8" if encoding == "utf-8-sig" else encoding,
                )
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Decoded printable XOR-encrypted string literals", count)
                    )

            if self.config.rolling_xor_key is not None:
                current, count = self.strings.rolling_xor_literal_payloads(
                    current,
                    self.config.rolling_xor_key,
                    self.config.rolling_xor_step,
                    self.config.min_xor_printable_ratio,
                    "utf-8" if encoding == "utf-8-sig" else encoding,
                )
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Decoded rolling-XOR string literals", count)
                    )

            if self.config.additive_key is not None:
                current, count = self.strings.additive_literal_payloads(
                    current,
                    self.config.additive_key,
                    self.config.additive_step,
                    self.config.min_xor_printable_ratio,
                    "utf-8" if encoding == "utf-8-sig" else encoding,
                )
                if count:
                    layer_events.append(
                        TransformEvent("strings", "Decoded additive-cipher string literals", count)
                    )

            if self.config.reconstruct_control_flow:
                current, events = self.flow.reconstruct(current)
                layer_events.extend(events)

            if self.config.rename_identifiers:
                current, events = self.cleaner.clean(current, rename=True)
                layer_events.extend(events)

            report.events.extend(layer_events)
            if current == before:
                break
            report.layers_processed = layer + 1

        try:
            self.parser.validate(current)
            report.syntax_structure_valid = True
        except Exception as exc:
            report.syntax_structure_valid = False
            report.warnings.append(f"Output structural validation: {exc}")

        final_findings = self.detector.detect(current)
        initial_names = {finding.name for finding in report.findings}
        added = [finding for finding in final_findings if finding.name not in initial_names]
        if added:
            report.findings.extend(added)
        return DeobfuscationResult(self.emitter.emit(current), report)
