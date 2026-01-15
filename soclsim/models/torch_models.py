from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

import torch
import torch.nn as nn


class LSTMSeqAutoencoder(nn.Module):
    """Sequence autoencoder over one-hot tokens.

    Input: (B, T, V). Reconstructs same shape.
    """

    def __init__(self, vocab_size: int, hidden: int = 64, latent: int = 32):
        super().__init__()
        self.vocab_size = vocab_size
        self.enc = nn.LSTM(input_size=vocab_size, hidden_size=hidden, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)
        self.dec = nn.LSTM(input_size=hidden, hidden_size=hidden, batch_first=True)
        self.out = nn.Linear(hidden, vocab_size)

    def forward(self, x: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        # mask: (B, T) float32 0/1
        h, _ = self.enc(x)
        # take last valid timestep per sequence
        lengths = mask.sum(dim=1).clamp(min=1).long()
        idx = (lengths - 1).view(-1, 1, 1).expand(-1, 1, h.size(-1))
        last = h.gather(1, idx).squeeze(1)  # (B, H)
        z = torch.tanh(self.to_latent(last))  # (B, L)
        h0 = torch.tanh(self.from_latent(z)).unsqueeze(1).repeat(1, x.size(1), 1)  # (B, T, H)
        y, _ = self.dec(h0)
        logits = self.out(y)
        return logits


class DenseAutoencoder(nn.Module):
    def __init__(self, dim: int, hidden: int = 64, bottleneck: int = 16):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(dim, hidden), nn.ReLU(), nn.Linear(hidden, bottleneck), nn.ReLU())
        self.dec = nn.Sequential(nn.Linear(bottleneck, hidden), nn.ReLU(), nn.Linear(hidden, dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.enc(x)
        return self.dec(z)


@dataclass(frozen=True)
class TorchArtifacts:
    seq_state_dict: Dict
    dense_state_dict: Dict
    vocab_size: int
    window_dim: int


def save_torch_artifacts(path: str, art: TorchArtifacts) -> None:
    torch.save(
        {
            "seq_state_dict": art.seq_state_dict,
            "dense_state_dict": art.dense_state_dict,
            "vocab_size": art.vocab_size,
            "window_dim": art.window_dim,
        },
        path,
    )


def load_torch_artifacts(path: str) -> TorchArtifacts:
    obj = torch.load(path, map_location="cpu")
    return TorchArtifacts(
        seq_state_dict=obj["seq_state_dict"],
        dense_state_dict=obj["dense_state_dict"],
        vocab_size=int(obj["vocab_size"]),
        window_dim=int(obj["window_dim"]),
    )


