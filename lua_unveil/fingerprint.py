"""Heuristic obfuscator and virtual-machine fingerprinting."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import Finding


class ObfuscatorDetector:
    """Rank likely protectors using explicit markers and structural evidence.

    Fingerprints are probabilistic. A marker can identify a family, but generally
    cannot prove the exact product version or configuration.
    """

    _SIGNATURES: tuple[tuple[str, tuple[str, ...], float, str], ...] = (
        (
            "Luraph-family",
            (r"LPH\$!!", r"LPH!", r"Luraph"),
            0.99,
            "Explicit LPH marker found; exact release is not inferred.",
        ),
        (
            "IronBrew-family",
            (r"IronBrew", r"Ironbrew", r"\bIB2\b"),
            0.96,
            "IronBrew-related marker found.",
        ),
        (
            "MoonVeil-family",
            (r"MoonVeil", r"Moon\s*Veil"),
            0.95,
            "MoonVeil-related marker found.",
        ),
        (
            "Prometheus-family",
            (r"Prometheus\s*Obfuscator", r"--\s*Prometheus", r"PROMETHEUS_OBF"),
            0.92,
            "Prometheus-related marker found.",
        ),
        (
            "LuaObfuscator-family",
            (r"LuaObfuscator", r"__lua_obfuscator"),
            0.90,
            "LuaObfuscator-related marker found.",
        ),
    )

    def detect(self, source: str) -> list[Finding]:
        """Return ordered fingerprints and generic VM evidence."""
        findings: list[Finding] = []
        lowered = source.lower()
        for name, patterns, confidence, details in self._SIGNATURES:
            evidence = tuple(
                pattern
                for pattern in patterns
                if re.search(pattern, source, flags=re.IGNORECASE)
            )
            if evidence:
                findings.append(Finding(name, confidence, evidence, details))

        vm_evidence: list[str] = []
        if re.search(r"bit32\.(?:band|bxor|rshift|lshift)", source):
            vm_evidence.append("bit32 arithmetic helpers")
        if re.search(r"\b(?:pcall|coroutine\.wrap)\b", source):
            vm_evidence.append("protected/coroutine execution wrapper")
        if re.search(r"\b\w+\s*\[\s*\w+\s*\]", source) and re.search(
            r"\b(?:while|repeat)\b", source
        ):
            vm_evidence.append("indexed state/dispatch loop")
        if re.search(r"\b(?:LOADK|GETTABUP|SETTABUP|NEWTABLE)\b", source):
            vm_evidence.append("bytecode-like opcode names")
        if len(re.findall(r"\b(?:if|elseif)\b", source)) > 100:
            vm_evidence.append("high-density conditional dispatch")

        if len(vm_evidence) >= 2:
            findings.append(
                Finding(
                    "Custom virtual machine (probable)",
                    min(0.94, 0.58 + 0.08 * len(vm_evidence)),
                    tuple(vm_evidence),
                    "Evidence indicates VM dispatch; automatic instruction decoding requires a VM-specific profile.",
                )
            )
        if not findings:
            findings.append(
                Finding(
                    "Unknown / no recognized signature",
                    0.30,
                    (),
                    "No supported explicit fingerprint was found.",
                )
            )
        return sorted(findings, key=lambda item: item.confidence, reverse=True)
