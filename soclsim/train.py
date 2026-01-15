from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

from soclsim.features.sequences import build_token_map, sessions_to_sequences
from soclsim.features.windows import windowize
from soclsim.io.ndjson import read_ndjson
from soclsim.logs.parsers import parse_any
from soclsim.logs.sessionize import Session, sessionize
from soclsim.config import SETTINGS
from soclsim.models.isoforest import save_isoforest, train_isoforest
from soclsim.models.scoring import load_torch_models
from soclsim.models.torch_models import TorchArtifacts, save_torch_artifacts
from soclsim.models.train_torch import TorchTrainConfig, build_torch_artifacts, train_dense_autoencoder, train_seq_autoencoder


def _load_and_normalize(raw_dir: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for source, fname in [("auth", "auth.ndjson"), ("network", "network.ndjson"), ("process", "process.ndjson")]:
        p = raw_dir / fname
        if not p.exists():
            continue
        for raw in read_ndjson(p):
            ne = parse_any(source, raw)
            events.append(
                {
                    "ts": ne.ts,
                    "source": ne.source,
                    "event_type": ne.event_type,
                    "user": ne.user,
                    "ip": ne.ip,
                    "host": ne.host,
                    "fields": ne.fields,
                    "event_id": ne.event_id,
                }
            )
    events.sort(key=lambda e: e["ts"])
    return events


def _sessions_to_dicts(sessions: List[Session]) -> List[Dict[str, Any]]:
    return [
        {
            "session_id": s.session_id,
            "user": s.user,
            "ip": s.ip,
            "start_ts": s.start_ts,
            "end_ts": s.end_ts,
            "events": s.events,
        }
        for s in sessions
    ]


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train SOC log intelligence models.")
    p.add_argument("--raw", required=True, help="Raw NDJSON directory, e.g. data/raw")
    p.add_argument("--artifacts", required=True, help="Artifacts output directory")
    p.add_argument("--epochs", type=int, default=8)
    args = p.parse_args(argv)

    raw_dir = Path(args.raw)
    art_dir = Path(args.artifacts)
    art_dir.mkdir(parents=True, exist_ok=True)

    events = _load_and_normalize(raw_dir)
    if not events:
        raise SystemExit(f"No events found in {raw_dir}")

    sessions = sessionize(events)
    sess_dicts = _sessions_to_dicts(sessions)

    # Window features for classical + dense AE
    windows = windowize(events)
    Xw = np.stack([w.x for w in windows], axis=0)
    feature_names = windows[0].feature_names

    # Train Isolation Forest
    iso = train_isoforest(Xw, feature_names)
    save_isoforest(str(art_dir / "isoforest.joblib"), iso)

    # Train Torch models (dense AE + seq AE)
    cfg = TorchTrainConfig(epochs=int(args.epochs))
    dense_model, _ = train_dense_autoencoder(Xw, cfg)

    token_map = build_token_map(sess_dicts, min_count=2)
    seq_batch = sessions_to_sequences(sess_dicts, token_map)
    if seq_batch.x.shape[0] > 0:
        seq_model = train_seq_autoencoder(seq_batch.x, seq_batch.mask, cfg)
    else:
        # degenerate fallback if dataset too small
        from soclsim.models.torch_models import LSTMSeqAutoencoder

        seq_model = LSTMSeqAutoencoder(vocab_size=len(token_map))

    torch_art = build_torch_artifacts(seq_model, dense_model, vocab_size=len(token_map), window_dim=int(Xw.shape[1]))
    save_torch_artifacts(str(art_dir / "torch.pt"), torch_art)

    # Compute feature statistics for attribution
    feature_stats = {}
    for i, name in enumerate(feature_names):
        values = Xw[:, i]
        feature_stats[name] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values) + 1e-6),
            "p5": float(np.percentile(values, 5)),
            "p25": float(np.percentile(values, 25)),
            "p50": float(np.percentile(values, 50)),
            "p75": float(np.percentile(values, 75)),
            "p95": float(np.percentile(values, 95)),
            "p99": float(np.percentile(values, 99)),
        }
    
    # Save metadata needed at inference time
    meta = {
        "feature_names": feature_names,
        "token_map": token_map,
        "feature_stats": feature_stats,
        "settings": {
            "window_minutes": SETTINGS.window_minutes,
            "session_gap_minutes": SETTINGS.session_gap_minutes,
            "max_sequence_len": SETTINGS.max_sequence_len,
        },
    }
    (art_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"Trained models on events={len(events)} windows={len(windows)} sessions={len(sessions)}")
    print(f"Artifacts written to {art_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


