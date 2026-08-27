"""Tests for backend.app.agent.knowledge and the lazy OpenRouter client.

No network, no OPENROUTER_API_KEY, no PostgreSQL.

**Provenance.**  Several cases here are ported from the deleted
``test_rag.py``.  When ``packet_qa`` was removed, its knowledge-base tests were
the only place three behaviours were pinned -- the file is resolved relative to
the package rather than the CWD, it is cached after the first read, and a
missing file degrades to empty rather than raising.  ``agent/knowledge.py``
inherits all three and would have lost their coverage silently, which is exactly
the kind of hole a delete opens.  The same goes for the import-safety and
"no API key" cases that pinned ``RagUnavailable``; their ``SaqrUnavailable``
equivalents are at the bottom of this file.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.agent import knowledge  # noqa: E402
from backend.app.config import ATTACK_CLASSES, front_key  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Neutralise ambient configuration and the module cache."""
    for var in ("ATTACKS_FILE", "RAG_KNOWLEDGE_FILE"):
        monkeypatch.delenv(var, raising=False)
    knowledge.clear_cache()
    yield
    knowledge.clear_cache()


@pytest.fixture()
def scratch_dir() -> Iterator[Path]:
    """A throwaway directory (pytest's tmp_path GC is racy on Windows)."""
    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


# --------------------------------------------------------------------------- #
# File resolution — ported from test_rag.py                                    #
# --------------------------------------------------------------------------- #
def test_knowledge_file_loads_from_arbitrary_cwd(scratch_dir):
    """Resolved relative to the package, not the working directory.

    The detector is started by systemd with an unrelated CWD, so a relative
    lookup here would work in every test and fail on the Pi.
    """
    original_cwd = Path.cwd()
    os.chdir(scratch_dir)  # a directory containing nothing named attacks.*
    try:
        sections = knowledge.sections()
        path = knowledge.knowledge_path()
    finally:
        os.chdir(original_cwd)  # restore before the temp dir is removed

    assert path.is_absolute()
    assert "evil_twin" in sections
    assert "deauth" in sections


def test_knowledge_file_is_cached_after_first_read(scratch_dir, monkeypatch):
    kb = scratch_dir / "kb.md"
    kb.write_text("## Deauth\n\nonly in the file\n", encoding="utf-8")
    monkeypatch.setenv("ATTACKS_FILE", str(kb))

    first = knowledge.sections()
    assert "deauth" in first
    kb.unlink()  # the cache must survive the file disappearing
    assert knowledge.sections() == first


def test_missing_knowledge_file_returns_no_sections(scratch_dir, monkeypatch):
    """Degrades to empty rather than raising: a missing file must not 500 /ask."""
    monkeypatch.setenv("ATTACKS_FILE", str(scratch_dir / "nope.md"))
    assert knowledge.sections() == {}
    assert knowledge.section_for("Deauth") is None
    assert knowledge.missing_classes() == list(ATTACK_CLASSES)


def test_attacks_file_env_override_is_honoured(scratch_dir, monkeypatch):
    kb = scratch_dir / "custom.md"
    kb.write_text("## Deauth\n\ncustom text\n", encoding="utf-8")
    monkeypatch.setenv("ATTACKS_FILE", str(kb))
    assert knowledge.knowledge_path() == kb
    assert "custom text" in (knowledge.section_for("Deauth") or "")


def test_clear_cache_forces_a_reread(scratch_dir, monkeypatch):
    kb = scratch_dir / "kb.md"
    kb.write_text("## Deauth\n\nfirst\n", encoding="utf-8")
    monkeypatch.setenv("ATTACKS_FILE", str(kb))
    assert "first" in (knowledge.section_for("Deauth") or "")

    kb.write_text("## Deauth\n\nsecond\n", encoding="utf-8")
    knowledge.clear_cache()
    assert "second" in (knowledge.section_for("Deauth") or "")


# --------------------------------------------------------------------------- #
# The section index                                                            #
# --------------------------------------------------------------------------- #
def test_every_spec_class_has_a_section():
    """Iterates the spec, never a hand-written list.

    A second hand-maintained list is precisely how ``Disas`` and ``Kr00k`` went
    missing from this file in the first place.
    """
    assert knowledge.missing_classes() == []
    assert knowledge.covered_classes() == list(ATTACK_CLASSES)


@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_each_section_is_keyed_by_the_dashboard_key(attack_class):
    section = knowledge.sections()[front_key(attack_class)]
    assert section.startswith("## ")
    assert "Definition" in section and "Defenses" in section


def test_sections_include_their_own_heading():
    """A model handed one section must still see what it is reading about."""
    section = knowledge.section_for("Kr00k") or ""
    assert section.splitlines()[0].startswith("## Kr00k")


def test_the_notes_block_is_not_indexed_as_a_class():
    """The trailing RAG-notes block is `###`, so it must not become a section."""
    assert not any("notes" in key for key in knowledge.sections())


# --------------------------------------------------------------------------- #
# Class-name normalisation                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_every_db_label_normalises_to_itself(attack_class):
    assert knowledge.normalise_class(attack_class) == attack_class


@pytest.mark.parametrize(
    "spelling, expected",
    [
        ("deauth", "Deauth"),
        ("DEAUTH", "Deauth"),
        ("deauthentication", "Deauth"),
        ("disassociation flood", "Disas"),
        ("(re)assoc", "(Re)Assoc"),
        ("reassoc", "(Re)Assoc"),
        ("association flood", "(Re)Assoc"),
        ("evil twin", "Evil_Twin"),
        ("evil_twin", "Evil_Twin"),
        ("fake access point", "Evil_Twin"),
        ("rogue ap", "RogueAP"),
        ("rogueap", "RogueAP"),
        ("krack", "Krack"),
        ("key reinstallation", "Krack"),
        ("kr00k", "Kr00k"),
        ("CVE-2019-15126", "Kr00k"),
        ("ssdp", "SSDP"),
        ("amplification", "SSDP"),
    ],
)
def test_plain_language_names_normalise(spelling, expected):
    assert knowledge.normalise_class(spelling) == expected


@pytest.mark.parametrize("junk", ["", "   ", "ransomware", "phishing", "sql injection"])
def test_unknown_names_normalise_to_none(junk):
    assert knowledge.normalise_class(junk) is None


def test_normalise_class_returns_the_database_spelling():
    """Not a lower-cased key: the value goes straight into a WHERE clause."""
    assert knowledge.normalise_class("reassoc") == "(Re)Assoc"
    assert knowledge.normalise_class("evil twin") == "Evil_Twin"


# --------------------------------------------------------------------------- #
# Lazy client / typed unavailability — ported from test_rag.py                 #
# --------------------------------------------------------------------------- #
def test_import_without_api_key_succeeds():
    """Importing the agent stack with no credentials must not raise.

    Importing must never touch the network or the environment; the client is
    built on first use, so a missing key is a clean 503 rather than a boot
    failure that takes the whole API down with it.

    Run in a **subprocess**, deliberately, not via ``importlib.reload``.  A
    reload rebinds ``SaqrUnavailable`` to a brand-new class object while
    ``loop.py`` still holds the original, so every later ``except
    SaqrUnavailable`` in the suite stops matching -- which is exactly how this
    test broke three unrelated tests the first time it was written.
    """
    env = dict(os.environ)
    env.pop("OPENROUTER_API_KEY", None)
    env["PYTHONPATH"] = str(REPO_ROOT)
    result = subprocess.run(
        [
            sys.executable, "-c",
            "from backend.app.agent import llm, loop, tools, prompts, sqlguard, knowledge;"
            "assert issubclass(llm.SaqrUnavailable, RuntimeError);"
            "print('ok')",
        ],
        env=env, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_get_client_raises_saqr_unavailable_without_a_key(monkeypatch):
    from backend.app.agent import llm
    from backend.app.config import settings

    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "")
    llm.reset_client()
    with pytest.raises(llm.SaqrUnavailable) as excinfo:
        llm.get_client()
    # The message is load-bearing: /ask and /agent/ask both return it verbatim.
    assert "OPENROUTER_API_KEY" in str(excinfo.value)
    llm.reset_client()


def test_model_name_falls_back_to_gen_model(monkeypatch):
    """A .env written before the agent existed must keep working untouched."""
    from backend.app.agent import llm
    from backend.app.config import settings

    monkeypatch.setattr(settings, "SAQR_MODEL", "")
    monkeypatch.setattr(settings, "GEN_MODEL", "vendor/legacy-model")
    assert llm.model_name() == "vendor/legacy-model"

    monkeypatch.setattr(settings, "SAQR_MODEL", "vendor/new-model")
    assert llm.model_name() == "vendor/new-model"


def test_model_name_raises_when_nothing_is_configured(monkeypatch):
    from backend.app.agent import llm
    from backend.app.config import settings

    monkeypatch.setattr(settings, "SAQR_MODEL", "")
    monkeypatch.setattr(settings, "GEN_MODEL", "")
    with pytest.raises(llm.SaqrUnavailable):
        llm.model_name()
