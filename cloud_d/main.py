"""Cloud-D Main Entrypoint.

Supports:
- Render production web service startup: python -m cloud_d.main --host 0.0.0.0 --port $PORT --no-browser
- Console execution and headless simulation
- Compatibility with all Render runtime commands
"""

from __future__ import annotations

import argparse
import os
import sys

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from run_server import app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run Cloud-D Enterprise Security.")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")))
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--console", action="store_true")
    args, _ = parser.parse_known_args(argv)

    print("=" * 70)
    print("   CLOUD-D: AUTONOMOUS THREAT DEFENSE & ENCRYPTED STORAGE PLATFORM")
    print("   PSG College of Technology — Nithish M (Roll No. 24X064)")
    print("=" * 70)
    print(f"[*] Binding Server: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
