from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from soclsim.models.isoforest import IsoForestArtifact, load_isoforest
from soclsim.models.torch_models import TorchArtifacts, load_torch_artifacts


@dataclass(frozen=True)
class Artifacts:
    iso: IsoForestArtifact
    torch: TorchArtifacts
    feature_names: List[str]
    token_map: Dict[str, int]
    feature_stats: Dict[str, Dict[str, float]]  # feature_name -> {mean, std, p5, p25, p50, p75, p95, p99}


def load_artifacts(art_dir: str | Path) -> Artifacts:
    d = Path(art_dir)
    meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
    iso = load_isoforest(str(d / "isoforest.joblib"))
    torch_art = load_torch_artifacts(str(d / "torch.pt"))
    feature_stats = meta.get("feature_stats", {})
    return Artifacts(
        iso=iso,
        torch=torch_art,
        feature_names=list(meta["feature_names"]),
        token_map={k: int(v) for k, v in meta["token_map"].items()},
        feature_stats=feature_stats,
    )


