from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, Iterator, List


def read_ndjson(path: str | Path) -> Iterator[Dict]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def write_ndjson(path: str | Path, items: Iterable[Dict]) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with p.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it))
            f.write("\n")
            n += 1
    return n


