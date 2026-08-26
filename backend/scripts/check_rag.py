#!/usr/bin/env python3
"""
Pre-flight check for the /ask assistant (OpenRouter).

Run this once before a demo, with a key set in .env:

    python backend/scripts/check_rag.py

It verifies, in order:
  1. a key is configured,
  2. the configured model exists on OpenRouter and reports its price,
  3. the model answers a knowledge-base question (DOCS mode),
  4. the model produces valid SQL against the real schema (SQL mode),
  5. that SQL runs against your database, if one is reachable.

Exit code 0 means /ask will work. Anything else prints what to fix.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.rag import packet_qa  # noqa: E402
from backend.app.rag.packet_qa import RagUnavailable  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}OK{RESET}    {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}FAIL{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}WARN{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"        {DIM}{msg}{RESET}")


def check_model_catalogue(model: str) -> bool:
    """Confirm the model id exists on OpenRouter (public endpoint, no key needed)."""
    try:
        with urllib.request.urlopen("https://openrouter.ai/api/v1/models", timeout=20) as r:
            data = json.load(r)["data"]
    except Exception as exc:
        warn(f"could not reach the OpenRouter catalogue: {exc}")
        info("Skipping the model-id check; the live calls below still tell you what matters.")
        return True

    entry = next((m for m in data if m["id"] == model), None)
    if entry is None:
        fail(f"model id not found on OpenRouter: {model}")
        near = [m["id"] for m in data if model.split("/")[0] in m["id"]][:6]
        if near:
            info("Similar ids: " + ", ".join(near))
        return False

    p = entry.get("pricing", {})
    price_in = float(p.get("prompt", 0)) * 1e6
    price_out = float(p.get("completion", 0)) * 1e6
    ok(f"model exists: {entry.get('name', model)}")
    info(f"context {entry.get('context_length', '?')} tokens, "
         f"${price_in:.3f} in / ${price_out:.3f} out per million")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the OpenRouter assistant works.")
    ap.add_argument("--skip-db", action="store_true",
                    help="only check the model, do not run the generated SQL")
    args = ap.parse_args()

    model = packet_qa._cfg("GEN_MODEL", packet_qa.DEFAULT_GEN_MODEL)
    base = packet_qa._cfg("OPENROUTER_BASE_URL", packet_qa.DEFAULT_BASE_URL)

    print(f"\n  HawkShield assistant check\n  model: {model}\n  api:   {base}\n")
    print("-- configuration " + "-" * 54)

    try:
        packet_qa._get_client()
        ok("OPENROUTER_API_KEY is set, client built")
    except RagUnavailable as exc:
        fail(str(exc))
        info("Get a key at https://openrouter.ai/keys, then put it in .env:")
        info("  OPENROUTER_API_KEY=sk-or-v1-...")
        return 2

    if not check_model_catalogue(model):
        info("Set a different GEN_MODEL in .env. Known-good: deepseek/deepseek-v4-flash,")
        info("z-ai/glm-5.3-flash, qwen/qwen3.7-flash")
        return 2

    print("\n-- knowledge base (DOCS mode) " + "-" * 41)
    r = packet_qa.packet_ask("What is an Evil Twin attack and how do I defend against it?")
    if r.get("error"):
        fail(f"call failed: {r['error']}")
        return 3
    if r.get("mode") != "DOCS":
        warn(f"expected mode DOCS, got {r.get('mode')} (not fatal, but the router misclassified)")
    answer = (r.get("answer") or "").strip()
    if len(answer) < 40:
        fail(f"answer looks empty or truncated: {answer!r}")
        return 3
    ok(f"answered in {r.get('mode')} mode")
    info(answer[:220].replace("\n", " ") + ("..." if len(answer) > 220 else ""))

    print("\n-- text-to-SQL (SQL mode) " + "-" * 45)
    question = "How many Deauth attacks were detected in the last 24 hours?"
    if args.skip_db:
        try:
            routed = packet_qa._route_and_generate(question)
        except Exception as exc:
            fail(f"generation failed: {exc}")
            return 4
        if routed["mode"] != "SQL" or not routed["sql"]:
            fail(f"expected SQL mode, got {routed['mode']}")
            return 4
        ok("generated SQL (not executed, --skip-db)")
        info(routed["sql"])
        print(f"\n  {GREEN}Assistant is ready.{RESET}\n")
        return 0

    r = packet_qa.packet_ask(question)
    if r.get("error"):
        fail(f"call failed: {r['error']}")
        info("If this is a database error, the model is fine but your DB is unreachable.")
        info("Re-run with --skip-db to check the model on its own.")
        return 4
    if r.get("mode") != "SQL":
        warn(f"expected SQL mode, got {r.get('mode')}")
        info(f"answer: {(r.get('answer') or '')[:160]}")
        info("The model misrouted this question. Try a different GEN_MODEL.")
        return 4
    ok("generated and executed SQL against the live database")
    info(f"sql:    {r.get('sql')}")
    info(f"answer: {(r.get('answer') or '')[:220]}")

    print(f"\n  {GREEN}Assistant is ready. POST /ask will work.{RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
