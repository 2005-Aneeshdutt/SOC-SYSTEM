from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np
import torch

from soclsim.models.isoforest import IsoForestArtifact, score_isoforest
from soclsim.models.torch_models import DenseAutoencoder, LSTMSeqAutoencoder, TorchArtifacts


@dataclass(frozen=True)
class Scores:
    iso: np.ndarray  # (N,)
    dense_ae: np.ndarray  # (N,)
    seq_ae: np.ndarray  # (B,)


def score_dense_ae(model: DenseAutoencoder, X: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        xb = torch.tensor(X, dtype=torch.float32)
        recon = model(xb).cpu().numpy()
    err = ((recon - X) ** 2).mean(axis=1).astype(np.float32)
    q1, q9 = np.quantile(err, 0.1), np.quantile(err, 0.9)
    denom = float(max(1e-6, q9 - q1))
    s = (err - q1) / denom
    return np.clip(s, 0.0, 1.0)


def score_seq_ae(model: LSTMSeqAutoencoder, X: np.ndarray, mask: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        xb = torch.tensor(X, dtype=torch.float32)
        mb = torch.tensor(mask, dtype=torch.float32)
        logits = model(xb, mb)
        probs = torch.sigmoid(logits).cpu().numpy()
    # Reconstruction error averaged over valid tokens
    err = ((probs - X) ** 2).mean(axis=2)  # (B, T)
    denom = np.maximum(mask.sum(axis=1), 1.0)
    per_seq = (err * mask).sum(axis=1) / denom
    per_seq = per_seq.astype(np.float32)
    q1, q9 = np.quantile(per_seq, 0.1), np.quantile(per_seq, 0.9)
    denom2 = float(max(1e-6, q9 - q1))
    s = (per_seq - q1) / denom2
    return np.clip(s, 0.0, 1.0)


def load_torch_models(art: TorchArtifacts) -> Tuple[LSTMSeqAutoencoder, DenseAutoencoder]:
    seq = LSTMSeqAutoencoder(vocab_size=art.vocab_size)
    seq.load_state_dict(art.seq_state_dict)
    dense = DenseAutoencoder(dim=art.window_dim)
    dense.load_state_dict(art.dense_state_dict)
    return seq, dense


def explain_top_features(
    x: np.ndarray, 
    feature_names: List[str], 
    k: int = 5,
    feature_stats: Dict[str, Dict[str, float]] | None = None
) -> List[Dict]:
    """Explain top contributing features with real percentiles and z-scores.
    
    If feature_stats is provided, uses training data statistics for realistic attribution.
    Otherwise falls back to local z-score within the vector.
    """
    v = x.astype(np.float32)
    out = []
    
    if feature_stats:
        # Use training data statistics for realistic attribution
        z_scores = []
        percentiles = []
        for i, name in enumerate(feature_names):
            if name in feature_stats:
                stats = feature_stats[name]
                mu, sd = stats["mean"], stats["std"]
                val = float(v[int(i)])
                z = abs((val - mu) / sd) if sd > 0 else 0.0
                z_scores.append(z)
                
                # Compute percentile
                pct = 50.0  # default
                if val <= stats["p5"]:
                    pct = 5.0
                elif val <= stats["p25"]:
                    pct = 15.0
                elif val <= stats["p50"]:
                    pct = 37.5
                elif val <= stats["p75"]:
                    pct = 62.5
                elif val <= stats["p95"]:
                    pct = 85.0
                elif val <= stats["p99"]:
                    pct = 97.0
                else:
                    pct = 99.5
                percentiles.append(pct)
            else:
                z_scores.append(0.0)
                percentiles.append(50.0)
        
        # Sort by z-score
        idx = np.argsort(-np.array(z_scores))[:k]
        for i in idx:
            name = feature_names[int(i)]
            val = float(v[int(i)])
            z = z_scores[int(i)]
            pct = percentiles[int(i)]
            out.append({
                "feature": name,
                "value": val,
                "z_score": round(z, 2),
                "percentile": round(pct, 1),
                "attribution": round(z, 2),  # Keep for backward compat
            })
    else:
        # Fallback: local z-score within vector
        mu, sd = float(v.mean()), float(v.std() + 1e-6)
        z = np.abs((v - mu) / sd)
        idx = np.argsort(-z)[:k]
        for i in idx:
            out.append({
                "feature": feature_names[int(i)],
                "value": float(v[int(i)]),
                "z_score": round(float(z[int(i)]), 2),
                "percentile": 50.0,  # Unknown without stats
                "attribution": round(float(z[int(i)]), 2),
            })
    
    return out


