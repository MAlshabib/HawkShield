"""Tests for tools/inject_attack.py — the over-the-air self-test.

These run on ANY OS with no radio and no root. The safety gates and argument
parsing are exactly what is testable off a Pi, and that is the point: the
transmit and DB-verify paths are guarded and never exercised here.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Keep the tool import-safe without real service config, same as test_api.
os.environ.setdefault("OPENROUTER_API_KEY", "")

from tools import inject_attack as ia  # noqa: E402
from backend.detector.attack_sim import SIM_CLASSES, ATTACK_SPECS  # noqa: E402


# --- module / --help ---------------------------------------------------------
def test_module_imports_on_any_os():
    # Importing must not require Linux, root, a radio, or a DB.
    assert hasattr(ia, "main")
    assert hasattr(ia, "build_and_retarget")
    assert ia.MAX_COUNT == 1000
    assert ia.MAX_RATE == 100.0


def test_help_works(capsys):
    with pytest.raises(SystemExit) as exc:
        ia.parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--target-bssid" in out
    assert "--i-own-this-network" in out


def test_help_via_subprocess():
    # A real `--help` invocation of the file must exit 0 on this box.
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    proc = subprocess.run(
        [sys.executable, "-m", "tools.inject_attack", "--help"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), env=env,
    )
    assert proc.returncode == 0
    assert "over-the-air self-test" in proc.stdout


# --- safety gate: ownership + explicit BSSID ---------------------------------
def _args(**overrides):
    base = dict(
        iface="wlan1mon",
        target_bssid="de:ad:be:ef:00:01",
        attack="deauth",
        count=10,
        rate=10.0,
        verify=None,
        verify_timeout=20.0,
        i_own_this_network=True,
    )
    base.update(overrides)
    import argparse
    return argparse.Namespace(**base)


def test_gate_refuses_without_ownership_flag():
    with pytest.raises(SystemExit) as exc:
        ia.enforce_transmit_safety(_args(i_own_this_network=False))
    assert exc.value.code == 2


def test_gate_refuses_without_target_bssid():
    with pytest.raises(SystemExit) as exc:
        ia.enforce_transmit_safety(_args(target_bssid=None))
    assert exc.value.code == 2


def test_gate_refuses_broadcast_bssid():
    with pytest.raises(SystemExit):
        ia.enforce_transmit_safety(_args(target_bssid="ff:ff:ff:ff:ff:ff"))


def test_gate_refuses_malformed_bssid():
    with pytest.raises(SystemExit):
        ia.enforce_transmit_safety(_args(target_bssid="not-a-mac"))


def test_gate_passes_when_both_present():
    # Well-formed BSSID + ownership assertion => returns without raising.
    assert ia.enforce_transmit_safety(_args()) is None


def test_main_refuses_and_never_transmits(monkeypatch):
    # The transmit path must never be reached when the gate fails.
    sent = {"called": False}

    def _boom(*a, **k):
        sent["called"] = True

    monkeypatch.setattr(ia, "transmit", _boom)
    with pytest.raises(SystemExit) as exc:
        ia.main([
            "--iface", "wlan1mon",
            "--target-bssid", "de:ad:be:ef:00:01",
            "--attack", "deauth",
            # no --i-own-this-network
        ])
    assert exc.value.code == 2
    assert sent["called"] is False


# --- caps on --count / --rate ------------------------------------------------
def test_count_above_cap_rejected():
    with pytest.raises(SystemExit):
        ia.parse_args([
            "--iface", "wlan1mon", "--attack", "deauth",
            "--target-bssid", "de:ad:be:ef:00:01",
            "--count", str(ia.MAX_COUNT + 1),
        ])


def test_rate_above_cap_rejected():
    with pytest.raises(SystemExit):
        ia.parse_args([
            "--iface", "wlan1mon", "--attack", "deauth",
            "--target-bssid", "de:ad:be:ef:00:01",
            "--rate", str(ia.MAX_RATE + 1),
        ])


def test_count_zero_rejected():
    with pytest.raises(SystemExit):
        ia.parse_args([
            "--iface", "wlan1mon", "--attack", "deauth",
            "--target-bssid", "de:ad:be:ef:00:01", "--count", "0",
        ])


def test_count_and_rate_at_cap_accepted():
    args = ia.parse_args([
        "--iface", "wlan1mon", "--attack", "deauth",
        "--target-bssid", "de:ad:be:ef:00:01",
        "--count", str(ia.MAX_COUNT), "--rate", str(ia.MAX_RATE),
    ])
    assert args.count == ia.MAX_COUNT
    assert args.rate == ia.MAX_RATE


# --- frames come from attack_sim, build-only never send ----------------------
@pytest.mark.parametrize("attack", ["deauth", "disas", "reassoc",
                                    "rogueap", "evil_twin", "krack"])
def test_frames_built_for_each_attack(attack):
    classes = ia.resolve_classes(attack)
    assert len(classes) == 1
    frames = ia.build_and_retarget(classes, count=3, target_bssid="de:ad:be:ef:00:01")
    assert len(frames) == 3            # count per class
    for frame in frames:
        assert len(bytes(frame)) > 0   # a real, serialisable frame


def test_attack_all_builds_every_class():
    classes = ia.resolve_classes("all")
    assert classes == list(SIM_CLASSES)
    frames = ia.build_and_retarget(classes, count=2, target_bssid="de:ad:be:ef:00:01")
    assert len(frames) == 2 * len(SIM_CLASSES)


def test_retarget_sets_bssid_to_target():
    from scapy.layers.dot11 import Dot11

    target = "de:ad:be:ef:00:01"
    frames = ia.build_and_retarget(["Deauth"], count=1, target_bssid=target)
    dot11 = frames[0].getlayer(Dot11)
    # addr2/addr3 are the BSSID role in a deauth and must now be the target.
    assert dot11.addr3 == target
    assert dot11.addr2 == target


def test_frames_match_attack_sim_specs():
    # Guard against re-crafting: the classes we build are exactly attack_sim's.
    for attack in ["deauth", "disas", "reassoc", "rogueap", "evil_twin", "krack"]:
        (cls,) = ia.resolve_classes(attack)
        assert cls in ATTACK_SPECS


# --- verify report shape (dry: no radio, no DB) ------------------------------
def test_verify_report_pass():
    report = ia.format_verify_report(["Deauth"], ["Deauth", "Deauth"])
    assert "OVERALL: PASS" in report


def test_verify_report_partial_on_wrong_label():
    # Saw attacks but under a different class => the cross-hardware gap.
    report = ia.format_verify_report(["Deauth"], ["Disas", "Disas"])
    assert "OVERALL: PARTIAL" in report
    assert "2.7.1" in report


def test_verify_report_fail_on_nothing():
    report = ia.format_verify_report(["Deauth"], [])
    assert "OVERALL: FAIL" in report
