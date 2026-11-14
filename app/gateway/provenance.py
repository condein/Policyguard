"""Provenance labels and injection scanning.

The single most useful idea in this project: *where did the text come from?*
User instructions are trusted.  Anything the agent reads (PDF, web result,
tool output) is untrusted data and must never be treated as an instruction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.gateway.rules import COMPILED_INJECTION, EMAIL_RE, FILE_TOKEN_RE, URL_RE

TRUSTED_SOURCES = {"user", "user_task", "task", "human", "instruction"}
UNTRUSTED_SOURCES = {"document", "pdf", "web", "web_search", "tool", "tool_output", "email", "file"}


@dataclass
class ContextItem:
    source: str
    content: str
    trust: str = "untrusted"

    @property
    def is_trusted(self) -> bool:
        return self.trust == "trusted"


def normalize_context(items: Iterable[Any] | None) -> list[ContextItem]:
    """Accept strings or dicts and return labelled context items."""
    result: list[ContextItem] = []
    for item in items or []:
        if isinstance(item, ContextItem):
            result.append(item)
            continue
        if isinstance(item, str):
            result.append(ContextItem(source="document", content=item, trust="untrusted"))
            continue
        if isinstance(item, dict):
            source = str(item.get("source") or "document").lower()
            trust = str(item.get("trust") or ("trusted" if source in TRUSTED_SOURCES else "untrusted")).lower()
            result.append(ContextItem(source=source, content=str(item.get("content") or ""), trust=trust))
    return result


def trust_labels(items: Iterable[ContextItem]) -> dict:
    labels = {"user_task": "trusted", "untrusted_sources": [], "trusted_sources": []}
    for item in items:
        bucket = "trusted_sources" if item.is_trusted else "untrusted_sources"
        if item.source not in labels[bucket]:
            labels[bucket].append(item.source)
    return labels


@dataclass
class InjectionReport:
    score: int = 0
    flags: list[dict] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    has_dangerous_instruction: bool = False

    @property
    def detected(self) -> bool:
        return bool(self.flags)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "detected": self.detected,
            "flags": self.flags,
            "emails": sorted(set(self.emails)),
            "urls": sorted(set(self.urls)),
            "has_dangerous_instruction": self.has_dangerous_instruction,
        }


DANGEROUS_VERBS_RE = re.compile(r"\b(email|mail|send|forward|upload|post|exfiltrate|delete|remove|export|share)\b", re.I)


def scan_text(text: str) -> InjectionReport:
    report = InjectionReport()
    if not text:
        return report

    seen: set[str] = set()
    for code, pattern, weight, label in COMPILED_INJECTION:
        matches = pattern.findall(text)
        if not matches:
            continue
        if code in seen:
            continue
        seen.add(code)
        excerpt = matches[0] if isinstance(matches[0], str) else str(matches[0])
        report.flags.append({
            "code": code,
            "label": label,
            "weight": weight,
            "excerpt": excerpt[:160],
        })

    report.score = min(100, sum(flag["weight"] for flag in report.flags))
    report.emails = EMAIL_RE.findall(text)
    report.urls = URL_RE.findall(text)
    report.files = FILE_TOKEN_RE.findall(text)
    report.has_dangerous_instruction = bool(DANGEROUS_VERBS_RE.search(text))
    return report


def scan_untrusted(items: Iterable[ContextItem]) -> InjectionReport:
    """Scan only the untrusted portions of the context."""
    combined = "\n".join(item.content for item in items if not item.is_trusted)
    return scan_text(combined)


def untrusted_text(items: Iterable[ContextItem]) -> str:
    return "\n".join(item.content for item in items if not item.is_trusted)


def argument_provenance(arguments: dict, trusted_text: str, untrusted: str) -> list[dict]:
    """Find argument values that only appear in untrusted content.

    Addresses, URLs and file tokens copied out of a document into a tool call
    are the classic data-exfiltration signature, so they are tracked exactly.
    """
    hits: list[dict] = []
    untrusted_lower = untrusted.lower()
    trusted_lower = trusted_text.lower()
    for field_name, value in (arguments or {}).items():
        if not isinstance(value, str):
            continue
        candidates: list[tuple[str, str]] = []
        candidates += [("email", address) for address in EMAIL_RE.findall(value)]
        candidates += [("url", url) for url in URL_RE.findall(value)]
        candidates += [("file", token) for token in FILE_TOKEN_RE.findall(value)]
        for kind, token in candidates:
            needle = token.lower()
            if needle in untrusted_lower and needle not in trusted_lower:
                hit = {"field": field_name, "kind": kind, "value": token}
                if hit not in hits:
                    hits.append(hit)
    return hits
