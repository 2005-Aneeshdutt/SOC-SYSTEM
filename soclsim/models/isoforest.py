from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass(frozen=True)
class IsoForestArtifact:
    model: IsolationForest
    feature_names: List[str]


def train_isoforest(X: np.ndarray, feature_names: List[str]) -> IsoForestArtifact:
    # Contamination left to auto by default; for SOC-style anomaly scoring this works well.
    model = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination="auto",
        random_state=7,
        n_jobs=-1,
    )
    model.fit(X)
    return IsoForestArtifact(model=model, feature_names=feature_names)


def score_isoforest(art: IsoForestArtifact, X: np.ndarray) -> np.ndarray:
    # sklearn: higher is less anomalous; invert and scale to [0, 1]
    raw = -art.model.score_samples(X)  # higher => more anomalous
    raw = raw.astype(np.float32)
    # robust scaling
    q1, q9 = np.quantile(raw, 0.1), np.quantile(raw, 0.9)
    denom = float(max(1e-6, q9 - q1))
    s = (raw - q1) / denom
    return np.clip(s, 0.0, 1.0)


def save_isoforest(path: str, art: IsoForestArtifact) -> None:
    joblib.dump({"model": art.model, "feature_names": art.feature_names}, path)


def load_isoforest(path: str) -> IsoForestArtifact:
    obj = joblib.load(path)
    return IsoForestArtifact(model=obj["model"], feature_names=list(obj["feature_names"]))


