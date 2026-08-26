"""Monitor-mode capture loop.

Ported from the original ``Detector.run()``: monitor-mode switch via ``iw`` / ``ip
link``, channel pin, ``sniff(store=False)``, ENETDOWN recovery, heartbeat thread and
clean SIGTERM/SIGINT shutdown - with ``logging`` in place of ``print`` and the DB
write handed to :class:`backend.detector.sink.PacketSink`.

Root privileges (and a Linux box with ``iw``) are required for live capture; the
interface helpers all degrade to a warning when the tools are absent, so the module
imports fine on a laptop.
"""
from __future__ import annotations

import errno
import logging
import signal
import subprocess
import threading
import time
from typing import Any, Callable, Optional

from backend.detector._config import get_settings
from backend.detector.features import ExtractState, packet_to_row
from backend.detector.pipeline import TwoStagePipeline

logger = logging.getLogger(__name__)

__all__ = ["Detector", "iface_type", "set_monitor_mode", "pin_channel", "bring_iface_up"]

HEARTBEAT_SECONDS = 2.0
SNIFF_SLICE_SECONDS = 10


# ---------------------------------------------------------------------------
# Interface helpers (best effort; all failures are logged, never fatal)
# ---------------------------------------------------------------------------
def _run(cmd: list, check: bool = True) -> bool:
    try:
        subprocess.run(
            cmd, check=check,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return True
    except Exception as e:
        logger.warning("command failed: %s (%s)", " ".join(cmd), e)
        return False


def iface_type(iface: str) -> str:
    """``monitor`` / ``managed`` / ``unknown`` for a wireless interface."""
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"], stderr=subprocess.STDOUT, text=True
        )
        for line in out.splitlines():
            line = line.strip().lower()
            if line.startswith("type "):
                return line.split()[1]
    except Exception as e:
        logger.debug("iw dev %s info failed: %s", iface, e)
    return "unknown"


def bring_iface_up(iface: str) -> None:
    _run(["ip", "link", "set", iface, "up"])
    time.sleep(0.3)


def set_monitor_mode(iface: str) -> str:
    """Switch ``iface`` to monitor mode if it is not already.  Returns the new type."""
    current = iface_type(iface)
    if current == "monitor":
        return current
    logger.info("switching %s (%s) to monitor mode", iface, current)
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", iface, "set", "monitor", "none"])
    _run(["ip", "link", "set", iface, "up"])
    return iface_type(iface)


def pin_channel(iface: str, channel: int) -> None:
    if _run(["iw", "dev", iface, "set", "channel", str(channel)]):
        return
    if _run(["iwconfig", iface, "channel", str(channel)]):
        return
    logger.warning("could not pin %s to channel %s", iface, channel)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class Detector:
    """Capture -> features -> two-stage inference -> batched DB write."""

    def __init__(
        self,
        iface: Optional[str] = None,
        channel: Optional[int] = None,
        ssid: Optional[str] = None,
        pipeline: Optional[TwoStagePipeline] = None,
        sink: Any = None,
        dry_run: bool = False,
    ) -> None:
        s = get_settings()
        self.iface = iface or getattr(s, "CAPTURE_IFACE", "wlan1")
        self.channel = int(channel if channel is not None else getattr(s, "CAPTURE_CHANNEL", 6))
        raw_ssid = ssid if ssid is not None else getattr(s, "TARGET_SSID", "")
        self.ssid = (raw_ssid or "").strip() or None
        self.dry_run = bool(dry_run)

        self.pipeline = pipeline or TwoStagePipeline()

        if sink is None and not self.dry_run:
            from backend.detector.sink import PacketSink

            sink = PacketSink()
        self.sink = sink

        self.state = ExtractState()
        self.seen = 0
        self.saved = 0
        self.filtered = 0
        self._stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    # -- packet path -------------------------------------------------------
    def on_packet(self, pkt: Any) -> None:
        self.seen += 1
        try:
            row, raw = packet_to_row(pkt, self.iface, self.state)

            if self.ssid:                      # soft SSID filter, as in the original
                pkt_ssid = raw.get("ssid")
                if pkt_ssid is not None and pkt_ssid != self.ssid:
                    self.filtered += 1
                    return

            verdict = self.pipeline.predict(row)
            if not verdict.is_attack:
                return

            self.saved += 1
            logger.info(
                "ATTACK %s p1=%.3f p2=%.3f sa=%s bssid=%s",
                verdict.label, verdict.p1 or 0.0, verdict.p2 or 0.0,
                raw.get("sa"), raw.get("bssid"),
            )
            if self.sink is not None:
                self.sink.write(raw, row, verdict, self.iface)
        except Exception as e:
            logger.error("on_packet failed: %s", e, exc_info=logger.isEnabledFor(logging.DEBUG))

    # -- heartbeat ---------------------------------------------------------
    def _heartbeat(self) -> None:
        last = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last >= HEARTBEAT_SECONDS:
                last = now
                logger.info(
                    "status=LIVE seen=%d saved=%d filtered=%d iface=%s ch=%s",
                    self.seen, self.saved, self.filtered, self.iface, self.channel,
                )
                if self.sink is not None:
                    self.sink.maybe_flush()     # do not strand the tail of a burst
            self._stop.wait(0.2)

    # -- run / stop --------------------------------------------------------
    def prepare_interface(self) -> str:
        itype = set_monitor_mode(self.iface)
        pin_channel(self.iface, self.channel)
        bring_iface_up(self.iface)
        return itype

    def run(self, sniff_fn: Optional[Callable[..., Any]] = None) -> None:
        from scapy.config import conf
        from scapy.sendrecv import sniff as scapy_sniff

        sniff_fn = sniff_fn or scapy_sniff
        itype = self.prepare_interface()

        try:
            conf.sniff_promisc = True
            conf.monitor = 1
        except Exception as e:  # pragma: no cover - platform dependent
            logger.debug("could not set scapy conf: %s", e)

        logger.info(
            "sniffer armed: iface=%s type=%s channel=%s ssid=%r thr1=%.2f thr2=%.2f dry_run=%s",
            self.iface, itype, self.channel, self.ssid or "",
            self.pipeline.thr1, self.pipeline.thr2, self.dry_run,
        )

        self._hb_thread = threading.Thread(target=self._heartbeat, name="heartbeat", daemon=True)
        self._hb_thread.start()

        while not self._stop.is_set():
            try:
                sniff_fn(
                    iface=self.iface,
                    prn=self.on_packet,
                    store=False,
                    timeout=SNIFF_SLICE_SECONDS,
                    stop_filter=lambda _p: self._stop.is_set(),
                )
            except OSError as e:
                if getattr(e, "errno", None) == errno.ENETDOWN or "Network is down" in str(e):
                    logger.warning("interface went down; bringing %s up and retrying", self.iface)
                    bring_iface_up(self.iface)
                    pin_channel(self.iface, self.channel)
                    continue
                logger.error("sniffer OSError: %s", e)
                self._stop.wait(1.0)
            except KeyboardInterrupt:
                logger.info("interrupted; stopping")
                self.stop()
                break
            except Exception as e:
                logger.error("sniffer error: %s", e)
                self._stop.wait(1.0)

        self.shutdown()

    def stop(self, *_args: Any) -> None:
        """Signal-handler friendly: ``signal.signal(SIGTERM, det.stop)``."""
        self._stop.set()

    def shutdown(self) -> None:
        self._stop.set()
        if self._hb_thread is not None and self._hb_thread.is_alive():
            self._hb_thread.join(timeout=2.0)
        if self.sink is not None:
            self.sink.close()
        logger.info("detector stopped: seen=%d saved=%d filtered=%d",
                    self.seen, self.saved, self.filtered)

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.stop)
            except Exception as e:  # pragma: no cover - not always available
                logger.debug("could not install handler for %s: %s", sig, e)
