"""Cloud-D Production WSGI & Development Server Runner.

Delivered for Cloud-D Enterprise Security (PSG College of Technology).
Nithish M (Roll No. 24X064).
"""

from __future__ import annotations

import os
import sys

# Ensure local directory is on python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_d.application import create_app

# Support persistent disk mounts on Render / Docker (/var/data, /data, etc.)
data_dir = os.environ.get("RENDER_DISK_PATH", os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__))))
os.makedirs(data_dir, exist_ok=True)
db_file = os.path.join(data_dir, "cloud_d_production.db")
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = create_app(db_path=db_file, static_dir=static_dir)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 70)
    print("   CLOUD-D: ENTERPRISE CLOUD STORAGE & MULTI-AGENT DEFENSE")
    print("   PSG College of Technology · Department of Applied Mathematics")
    print(f"   Server listening at: http://127.0.0.1:{port}")
    print("   Active Roadmap Features: Tasks 1 through 8 Loaded and Operational")
    print("=" * 70)
    app.run(host=host, port=port, debug=False)
