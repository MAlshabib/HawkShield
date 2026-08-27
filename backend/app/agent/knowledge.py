"""Markdown section index over the attack knowledge base.

``backend/app/rag/knowledge/attacks.md`` is a flat document whose ``##`` headings
are the attack class names the detector writes to ``predicted_label``.  The RAG
path pastes the whole file into a system prompt; the agent instead looks up the
one section it needs, so the model reads a few hundred words rather than several
thousand, and so a question about a class the file does not cover fails loudly
instead of being answered from the model's own memory.

Lookups are normalised the same way ``config.front_key`` normalises a class name
(lower-case, punctuation dropped), plus a small alias table for the words people
actually type -- "deauthentication", "key reinstallation", "fake access point".

The file is read once per resolved path and cached, exactly as ``packet_qa``
caches it, and is resolved relative to this package rather than the CWD.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from backend.app.config import ATTACK_CLASSES, front_key

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_KNOWLEDGE_FILE",
    "ALIASES",
    "clear_cache",
    "covered_classes",
    "knowledge_path",
    "missing_classes",
    "normalise_class",
    "section_for",
    "sections",
]

#: ``backend/app/agent/knowledge.py`` -> ``backend/app`` -> ``rag/knowledge``.
DEFAULT_KNOWLEDGE_FILE: Path = (
    Path(__file__).resolve().parent.parent / "rag" / "knowledge" / "attacks.md"
)

#: Everything before the gloss in a ``##`` heading.  ``## SSDP (Simple Service
#: Discovery Protocol) - Reflection`` and ``## (Re)Assoc - Association Floods``
#: both reduce to the bare class name.
_HEADING_SPLIT_RE = re.compile(r"\s+[–—(:-]|\s+[-–—]\s+")

#: What users type -> the class key.  Only unambiguous wordings; the model is
#: perfectly capable of mapping the rest itself.
ALIASES: Dict[str, str] = {
    "deauthentication": "deauth",
    "deauthentication flood": "deauth",
    "deauth flood": "deauth",
    "disassociation": "disas",
    "disassociation flood": "disas",
    "disassoc": "disas",
    "association flood": "reassoc",
    "reassociation": "reassoc",
    "reassociation flood": "reassoc",
    "re assoc": "reassoc",
    "evil twin": "evil_twin",
    "eviltwin": "evil_twin",
    "fake access point": "evil_twin",
    "ssid impersonation": "evil_twin",
    "rogue ap": "rogueap",
    "rogue access point": "rogueap",
    "unauthorised ap": "rogueap",
    "unauthorized ap": "rogueap",
    "key reinstallation": "krack",
    "key reinstallation attack": "krack",
    "krack attack": "krack",
    "kr00k attack": "kr00k",
    "krook": "kr00k",
    "cve 2019 15126": "kr00k",
    "cve201915126": "kr00k",
    "all zero tk": "kr00k",
    "amplification": "ssdp",
    "reflection": "ssdp",
    "upnp": "ssdp",
}

_cache: Dict[str, Dict[str, str]] = {}


def knowledge_path() -> Path:
    """Knowledge-base location: env override, else the packaged file."""
    override = os.getenv("ATTACKS_FILE") or os.getenv("RAG_KNOWLEDGE_FILE")
    if override:
        return Path(override).expanduser()
    return DEFAULT_KNOWLEDGE_FILE


def clear_cache() -> None:
    """Forget the parsed file.  Used by tests and after editing the markdown."""
    _cache.clear()


def _normalise_key(text: str) -> str:
    """``"(Re)Assoc"`` -> ``"reassoc"``; the same rule ``config.front_key`` uses."""
    return front_key(str(text))


def _heading_to_key(heading: str) -> str:
    """``"SSDP (Simple Service Discovery Protocol) - Reflection"`` -> ``"ssdp"``."""
    name = _HEADING_SPLIT_RE.split(heading.strip(), maxsplit=1)[0]
    return _normalise_key(name)


def sections() -> Dict[str, str]:
    """``{class key: section markdown}`` for every ``##`` heading in the file.

    The section text includes its own heading, so a model handed one section
    still sees what it is reading about.
    """
    path = knowledge_path()
    cache_key = str(path)
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Knowledge base unreadable at %s: %s", path, exc)
        _cache[cache_key] = {}
        return _cache[cache_key]

    parsed: Dict[str, str] = {}
    current_key: Optional[str] = None
    buffer: List[str] = []

    def flush() -> None:
        if current_key and buffer:
            body = "\n".join(buffer).strip().strip("-").strip()
            if body:
                parsed[current_key] = body

    for line in text.splitlines():
        if line.startswith("## "):
            flush()
            current_key = _heading_to_key(line[3:])
            buffer = [line.strip()]
        elif current_key:
            buffer.append(line)
    flush()

    _cache[cache_key] = parsed
    logger.debug("Indexed %d knowledge sections from %s", len(parsed), path)
    return parsed


def normalise_class(name: str) -> Optional[str]:
    """Map anything the user might type onto a DB class label, or ``None``.

    Returns the *DB* spelling (``"(Re)Assoc"``, ``"Evil_Twin"``, ``"Kr00k"``),
    taken from ``config.ATTACK_CLASSES`` -- never a second hand-written list.
    """
    raw = str(name or "").strip()
    if not raw:
        return None

    by_key = {front_key(c): c for c in ATTACK_CLASSES}
    key = _normalise_key(raw)
    if key in by_key:
        return by_key[key]

    loose = re.sub(r"[^a-z0-9]+", " ", raw.lower()).strip()
    alias = ALIASES.get(loose) or ALIASES.get(loose.replace(" ", ""))
    if alias and alias in by_key:
        return by_key[alias]

    # Last resort: a class key contained in the phrase ("tell me about deauth").
    for k, cls in by_key.items():
        if re.search(rf"\b{re.escape(k)}\b", loose.replace(" ", "_")):
            return cls
    return None


def section_for(name: str) -> Optional[str]:
    """The knowledge-base section for a class, by any spelling.  ``None`` if absent."""
    cls = normalise_class(name)
    if cls is None:
        return None
    return sections().get(front_key(cls))


def covered_classes() -> List[str]:
    """Attack classes from the spec that the knowledge base documents."""
    have = sections()
    return [c for c in ATTACK_CLASSES if front_key(c) in have]


def missing_classes() -> List[str]:
    """Attack classes from the spec with no section in the knowledge base.

    Non-empty means the assistant will refuse conceptual questions about those
    classes; ``system_status`` reports it so the gap is visible rather than
    silently answered from the model's own memory.
    """
    have = sections()
    return [c for c in ATTACK_CLASSES if front_key(c) not in have]
