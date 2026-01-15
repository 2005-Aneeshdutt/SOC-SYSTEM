from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm

from soclsim.models.torch_models import DenseAutoencoder, LSTMSeqAutoencoder, TorchArtifacts


@dataclass(frozen=True)
class TorchTrainConfig:
    epochs: int = 8
    batch_size: int = 64
    lr: float = 1e-3
    device: str = "cpu"


def train_dense_autoencoder(X: np.ndarray, cfg: TorchTrainConfig) -> Tuple[DenseAutoencoder, Dict[str, float]]:
    device = torch.device(cfg.device)
    dim = int(X.shape[1])
    model = DenseAutoencoder(dim=dim).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=cfg.lr)
    loss_fn = nn.MSELoss()

    ds = TensorDataset(torch.tensor(X, dtype=torch.float32))
    dl = DataLoader(ds, batch_size=cfg.batch_size, shuffle=True)

    for _ in tqdm(range(cfg.epochs), desc="train_dense_ae"):
        model.train()
        for (xb,) in dl:
            xb = xb.to(device)
            opt.zero_grad()
            recon = model(xb)
            loss = loss_fn(recon, xb)
            loss.backward()
            opt.step()
    return model, {"dim": float(dim)}


def train_seq_autoencoder(X: np.ndarray, mask: np.ndarray, cfg: TorchTrainConfig) -> LSTMSeqAutoencoder:
    device = torch.device(cfg.device)
    vocab = int(X.shape[2])
    model = LSTMSeqAutoencoder(vocab_size=vocab).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=cfg.lr)
    loss_fn = nn.BCEWithLogitsLoss(reduction="none")

    ds = TensorDataset(
        torch.tensor(X, dtype=torch.float32),
        torch.tensor(mask, dtype=torch.float32),
    )
    dl = DataLoader(ds, batch_size=cfg.batch_size, shuffle=True)

    for _ in tqdm(range(cfg.epochs), desc="train_seq_ae"):
        model.train()
        for xb, mb in dl:
            xb = xb.to(device)
            mb = mb.to(device)
            opt.zero_grad()
            logits = model(xb, mb)
            # mask out padded timesteps
            loss = loss_fn(logits, xb).mean(dim=2)  # (B, T)
            loss = (loss * mb).sum() / mb.sum().clamp(min=1.0)
            loss.backward()
            opt.step()
    return model


def build_torch_artifacts(
    seq_model: LSTMSeqAutoencoder,
    dense_model: DenseAutoencoder,
    vocab_size: int,
    window_dim: int,
) -> TorchArtifacts:
    return TorchArtifacts(
        seq_state_dict=seq_model.state_dict(),
        dense_state_dict=dense_model.state_dict(),
        vocab_size=int(vocab_size),
        window_dim=int(window_dim),
    )


