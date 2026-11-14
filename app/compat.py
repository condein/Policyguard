"""Small compatibility shim.

``langchain-core`` imports ``uuid_utils.compat.uuid7`` at module load.  On
locked-down Windows machines an Application Control policy can block the
compiled ``_uuid_utils`` extension, which would make LangGraph unimportable.

This module provides the same two-function surface in pure Python, but only
when the real package cannot be imported.  Nothing else changes.
"""

from __future__ import annotations

import os
import sys
import time
import types
import uuid

_APPLIED = False


def _uuid7(timestamp: int | None = None, nanos: int | None = None) -> uuid.UUID:
    """RFC 9562 version-7 UUID (time ordered, random tail)."""
    if timestamp is None:
        unix_ms = time.time_ns() // 1_000_000
    else:
        unix_ms = int(timestamp) * 1000 + int(nanos or 0) // 1_000_000
    randomness = int.from_bytes(os.urandom(10), "big")

    value = (unix_ms & 0xFFFFFFFFFFFF) << 80  # 48-bit unix ms
    value |= 0x7 << 76  # version 7
    value |= ((randomness >> 68) & 0x0FFF) << 64  # 12 random bits
    value |= 0b10 << 62  # RFC variant
    value |= randomness & 0x3FFFFFFFFFFFFFFF  # 62 random bits
    return uuid.UUID(int=value)


def ensure_uuid7() -> bool:
    """Install the fallback if the native uuid_utils cannot be imported.

    Returns True when the shim was installed.
    """
    global _APPLIED
    if _APPLIED:
        return "uuid_utils" in sys.modules and getattr(sys.modules["uuid_utils"], "__pg_shim__", False)

    try:
        from uuid_utils.compat import uuid7  # noqa: F401

        return False
    except Exception:
        pass

    package = types.ModuleType("uuid_utils")
    package.__path__ = []  # mark as a package
    package.__pg_shim__ = True  # type: ignore[attr-defined]

    compat = types.ModuleType("uuid_utils.compat")
    compat.uuid7 = _uuid7  # type: ignore[attr-defined]
    compat.UUID = uuid.UUID  # type: ignore[attr-defined]

    package.compat = compat  # type: ignore[attr-defined]
    sys.modules["uuid_utils"] = package
    sys.modules["uuid_utils.compat"] = compat
    _APPLIED = True
    return True
