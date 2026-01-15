from __future__ import annotations

import sys


def main() -> int:
    print(
        "soclsim package. Common commands:\n"
        "  python -m soclsim.generate --out data/raw --days 7 --seed 7\n"
        "  python -m soclsim.train --raw data/raw --artifacts artifacts --epochs 8\n"
        "  uvicorn soclsim.api.main:app --host 127.0.0.1 --port 8000\n"
        "  streamlit run soclsim/dashboard/app.py\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


