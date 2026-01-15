from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import requests

from soclsim.io.ndjson import read_ndjson


def post_batch(base_url: str, source: str, events: List[Dict]) -> Dict:
    r = requests.post(f"{base_url}/ingest/logs", json={"source": source, "events": events}, timeout=30)
    r.raise_for_status()
    return r.json()


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ingest NDJSON datasets into the API in batches.")
    p.add_argument("--api", default="http://127.0.0.1:8000", help="API base URL")
    p.add_argument("--raw", required=True, help="Raw directory containing auth.ndjson/network.ndjson/process.ndjson")
    p.add_argument("--batch", type=int, default=500, help="Batch size")
    args = p.parse_args(argv)

    raw = Path(args.raw)
    for source, fname in [("auth", "auth.ndjson"), ("network", "network.ndjson"), ("process", "process.ndjson")]:
        path = raw / fname
        if not path.exists():
            print(f"Skip missing: {path}")
            continue

        buf: List[Dict] = []
        total = 0
        for e in read_ndjson(path):
            buf.append(e)
            if len(buf) >= args.batch:
                res = post_batch(args.api, source, buf)
                total += len(buf)
                buf = []
                print(f"{source}: ingested={total} (last={res})")
        if buf:
            res = post_batch(args.api, source, buf)
            total += len(buf)
            print(f"{source}: ingested={total} (last={res})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


