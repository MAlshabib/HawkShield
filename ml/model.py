#!/usr/bin/env python3
"""
HawkShield v2 model: a causal dilated temporal CNN over the 46-feature contract.

Design constraints, in priority order
-------------------------------------
1. **Causal.** The prediction for frame *t* uses frames <= *t* only. A detector
   that peeks at frame *t+1* validates beautifully and cannot be deployed. Every
   convolution is left-padded; every normalisation is per-timestep. There is a
   unit test (:func:`assert_causal`) that perturbs frame *t+1* and asserts the
   output at *t* is bit-identical. Run it after any architecture change.

2. **NaN is signal, not damage.** ``feature_spec`` emits NaN when a field is
   genuinely absent from the frame -- a data frame has no ``mgmt.reason_code``,
   and that absence is informative. v1 mean-imputed those to a training constant
   and then keyed on the constant. Here NaN is handled explicitly:

   * every feature is standardised with train-only mean/std, then clamped;
   * a NaN becomes a **learned per-feature scalar** (``missing``), so the network
     picks its own "absent" location in feature space rather than being told
     absent == average;
   * every feature that is ever NaN in training gets a **companion mask channel**
     (1.0 = the value was missing), so "absent" and "happens to equal the learned
     sentinel" are distinguishable.

   Nothing is imputed silently and nothing is imputed with a statistic.

3. **Small.** ~80k parameters at the default width; the whole point is a Pi.

Receptive field
---------------
6 blocks, kernel 3, dilations 1,2,4,8,16,32 -> RF = 1 + 2*(1+2+4+8+16+32) = 127
past frames. At the default window of 128 the last position sees full context.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence

import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detector.feature_spec import FEATURE_ORDER  # noqa: E402

DEFAULT_DILATIONS: List[int] = [1, 2, 4, 8, 16, 32]


# --------------------------------------------------------------------------- #
# Normalisation + missing-value handling                                       #
# --------------------------------------------------------------------------- #
class FeatureFront(nn.Module):
    """Standardise, clamp, replace NaN with a learned sentinel, append masks.

    Input  ``(B, F, T)`` raw features, NaN allowed.
    Output ``(B, F + M, T)`` where M = number of NaN-capable features.

    ``mean``/``std`` are buffers so they travel inside the checkpoint and the
    ONNX graph -- inference cannot use different constants than training did.
    """

    def __init__(self, mean: np.ndarray, std: np.ndarray, mask_idx: Sequence[int],
                 clamp: float = 8.0) -> None:
        super().__init__()
        f = len(mean)
        self.n_features = f
        self.clamp = float(clamp)
        self.register_buffer("mean", torch.as_tensor(np.asarray(mean, np.float32)).view(1, f, 1))
        self.register_buffer("std", torch.as_tensor(np.asarray(std, np.float32)).view(1, f, 1))
        self.register_buffer("mask_idx", torch.as_tensor(np.asarray(mask_idx, np.int64)))
        self.missing = nn.Parameter(torch.zeros(1, f, 1))
        self.n_masks = len(mask_idx)          # python bool, not a traced tensor read
        self.out_channels = f + self.n_masks

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        nanmask = torch.isnan(x)
        # NaN propagates through arithmetic, so neutralise before scaling.
        safe = torch.where(nanmask, torch.zeros_like(x), x)
        z = (safe - self.mean) / self.std
        z = torch.clamp(z, -self.clamp, self.clamp)
        z = torch.where(nanmask, self.missing.expand_as(z), z)
        if self.n_masks == 0:
            return z
        m = nanmask.index_select(1, self.mask_idx).to(z.dtype)
        return torch.cat([z, m], dim=1)


# Width follows the contract; a literal here would silently rot on the next
# spec change, which is the class of bug this project exists to avoid.
N_FEATURES = len(FEATURE_ORDER)


class ChannelNorm(nn.Module):
    """LayerNorm over the channel axis only -- never over time.

    ``BatchNorm1d`` and ``GroupNorm`` both average across the time axis, which
    means the statistics used to normalise frame *t* depend on frames *t+1..T*.
    That is future leakage hiding in a normalisation layer, and it is exactly the
    kind of bug the causality test exists to catch.
    """

    def __init__(self, channels: int, eps: float = 1e-5) -> None:
        super().__init__()
        self.weight = nn.Parameter(torch.ones(1, channels, 1))
        self.bias = nn.Parameter(torch.zeros(1, channels, 1))
        self.eps = eps

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        mu = x.mean(dim=1, keepdim=True)
        var = x.var(dim=1, keepdim=True, unbiased=False)
        return (x - mu) * torch.rsqrt(var + self.eps) * self.weight + self.bias


class CausalBlock(nn.Module):
    """Left-padded dilated conv -> ChannelNorm -> GELU -> 1x1 -> residual."""

    def __init__(self, channels: int, dilation: int, kernel: int = 3,
                 dropout: float = 0.05) -> None:
        super().__init__()
        self.pad = (kernel - 1) * dilation
        self.conv = nn.Conv1d(channels, channels, kernel, dilation=dilation)
        self.norm = ChannelNorm(channels)
        self.point = nn.Conv1d(channels, channels, 1)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = F.pad(x, (self.pad, 0))            # left only == causal
        h = self.conv(h)
        h = self.norm(h)
        h = F.gelu(h)
        h = self.point(h)
        h = self.drop(h)
        return x + h


class HawkShieldTCN(nn.Module):
    """Per-frame 9-class classifier. ``(B, 46, T) -> (B, 9, T)``."""

    def __init__(
        self,
        mean: np.ndarray,
        std: np.ndarray,
        mask_idx: Sequence[int],
        n_classes: int,
        channels: int = 56,
        dilations: Optional[Sequence[int]] = None,
        kernel: int = 3,
        dropout: float = 0.05,
    ) -> None:
        super().__init__()
        dilations = list(dilations or DEFAULT_DILATIONS)
        self.config: Dict[str, object] = {
            "channels": channels,
            "dilations": dilations,
            "kernel": kernel,
            "dropout": dropout,
            "n_classes": n_classes,
            "n_features": int(len(mean)),
            "mask_idx": [int(i) for i in mask_idx],
        }
        self.front = FeatureFront(mean, std, mask_idx)
        self.proj = nn.Conv1d(self.front.out_channels, channels, 1)
        self.blocks = nn.ModuleList(
            [CausalBlock(channels, d, kernel, dropout) for d in dilations]
        )
        self.norm = ChannelNorm(channels)
        self.head = nn.Conv1d(channels, n_classes, 1)
        self.kernel = kernel
        self.dilations = dilations

    @property
    def receptive_field(self) -> int:
        return 1 + sum((self.kernel - 1) * d for d in self.dilations)

    def n_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters())

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.proj(self.front(x))
        for blk in self.blocks:
            h = blk(h)
        return self.head(F.gelu(self.norm(h)))


# --------------------------------------------------------------------------- #
# Causality test                                                               #
# --------------------------------------------------------------------------- #
def assert_causal(model: nn.Module, n_features: int = N_FEATURES, window: int = 128,
                  t: int = 64, seed: int = 0, tol: float = 0.0) -> Dict[str, float]:
    """Perturb every frame after *t* and assert outputs at <= *t* do not move.

    Catches: right-padding, non-causal dilation, BatchNorm/GroupNorm over time,
    global pooling, bidirectional layers, and any accidental ``x.mean(-1)``.
    Returns the max deviation on both sides of the cut; the future side must be
    non-zero or the test itself is vacuous.
    """
    model.eval()
    g = torch.Generator().manual_seed(seed)
    x = torch.randn(2, n_features, window, generator=g)
    # sprinkle NaN so the missing-value path is exercised too
    nan_pos = torch.rand(x.shape, generator=g) < 0.1
    x = torch.where(nan_pos, torch.full_like(x, float("nan")), x)

    with torch.no_grad():
        base = model(x)
        x2 = x.clone()
        x2[:, :, t + 1:] = torch.randn(x2[:, :, t + 1:].shape, generator=g) * 5.0
        pert = model(x2)

    past = (base[:, :, : t + 1] - pert[:, :, : t + 1]).abs().max().item()
    future = (base[:, :, t + 1:] - pert[:, :, t + 1:]).abs().max().item()
    if not math.isfinite(past) or past > tol:
        raise AssertionError(
            f"CAUSALITY VIOLATION: perturbing frames > {t} changed outputs at <= {t} "
            f"by {past:.3e}. The model can see the future; it will validate high "
            f"and fail in the field."
        )
    if future <= 0.0:
        raise AssertionError(
            "causality probe is vacuous: perturbing the future changed nothing at "
            "all, so the model is ignoring its input."
        )
    return {"max_delta_past": past, "max_delta_future": future}


def build_from_checkpoint(ckpt: Dict[str, object]) -> HawkShieldTCN:
    cfg = ckpt["config"]
    norm = ckpt["norm"]
    model = HawkShieldTCN(
        mean=np.asarray(norm["mean"], np.float32),
        std=np.asarray(norm["std"], np.float32),
        mask_idx=cfg["mask_idx"],
        n_classes=int(cfg["n_classes"]),
        channels=int(cfg["channels"]),
        dilations=list(cfg["dilations"]),
        kernel=int(cfg["kernel"]),
        dropout=float(cfg["dropout"]),
    )
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model


if __name__ == "__main__":  # quick self-check: python ml/model.py
    m = HawkShieldTCN(np.zeros(N_FEATURES, np.float32), np.ones(N_FEATURES, np.float32),
                      list(range(18)), n_classes=9)
    print(f"parameters      : {m.n_parameters():,}")
    print(f"receptive field : {m.receptive_field} past frames")
    print(f"causality       : {assert_causal(m)}")
