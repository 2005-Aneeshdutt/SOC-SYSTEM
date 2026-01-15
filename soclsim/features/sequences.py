from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from soclsim.config import SETTINGS


@dataclass(frozen=True)
class SequenceBatch:
    keys: List[Tuple[Optional[str], Optional[str], str]]  # (user, ip, session_id)
    x: np.ndarray  # (B, T, D)
    mask: np.ndarray  # (B, T) 1 for valid tokens
    token_map: Dict[str, int]


def _event_token(e: Dict) -> str:
    src = e.get("source", "unknown")
    et = e.get("event_type", "event")
    if src == "process":
        cmd = ((e.get("fields") or {}).get("command")) or ""
        # Normalize a few high-signal command families
        cmd_s = str(cmd)
        if "curl " in cmd_s or "wget " in cmd_s:
            return "process:download"
        if "useradd" in cmd_s or "chpasswd" in cmd_s:
            return "process:account_create"
        if "ssh " in cmd_s:
            return "process:ssh"
    if src == "network":
        f = e.get("fields") or {}
        port = int(f.get("dst_port") or 0)
        if port in {4444, 8081, 1337, 9001}:
            return "network:rare_port"
    return f"{src}:{et}"


def build_token_map(sessions: List[Dict], min_count: int = 2) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for s in sessions:
        for e in s.get("events", []):
            t = _event_token(e)
            counts[t] = counts.get(t, 0) + 1
    token_map = {"<PAD>": 0, "<UNK>": 1}
    for tok, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if c >= min_count and tok not in token_map:
            token_map[tok] = len(token_map)
    return token_map


def sessions_to_sequences(sessions: List[Dict], token_map: Dict[str, int]) -> SequenceBatch:
    T = SETTINGS.max_sequence_len
    keys: List[Tuple[Optional[str], Optional[str], str]] = []
    seqs: List[List[int]] = []
    for s in sessions:
        tokens = []
        for e in s.get("events", []):
            tok = _event_token(e)
            tokens.append(token_map.get(tok, token_map["<UNK>"]))
        if not tokens:
            continue
        tokens = tokens[-T:]
        keys.append((s.get("user"), s.get("ip"), s.get("session_id", "sess_unknown")))
        seqs.append(tokens)

    if not seqs:
        x = np.zeros((0, T, 1), dtype=np.float32)
        mask = np.zeros((0, T), dtype=np.float32)
        return SequenceBatch(keys=[], x=x, mask=mask, token_map=token_map)

    V = len(token_map)
    B = len(seqs)
    x = np.zeros((B, T, V), dtype=np.float32)
    mask = np.zeros((B, T), dtype=np.float32)
    for i, seq in enumerate(seqs):
        for j, tok in enumerate(seq):
            x[i, j, tok] = 1.0
            mask[i, j] = 1.0
    return SequenceBatch(keys=keys, x=x, mask=mask, token_map=token_map)


