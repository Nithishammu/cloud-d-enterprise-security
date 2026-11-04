"""Cloud-D Production WSGI & Development Server Runner.

Delivered for Cloud-D Enterprise Security (PSG College of Technology).
Student Investigator: Nithish M (Roll No. 24X064).
Institution: Dept. of Applied Mathematics & Computational Sciences, PSG College of Technology.
"""

from __future__ import annotations

import os
import sys

# Ensure local directory is on python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from cloud_d.application import create_app

# Support persistent disk mounts on Render / Docker (/var/data, /data, etc.)
data_dir = os.environ.get("RENDER_DISK_PATH", os.environ.get("DATA_DIR", CURRENT_DIR))
os.makedirs(data_dir, exist_ok=True)
db_file = os.path.join(data_dir, "cloud_d_production.db")
static_dir = os.path.join(CURRENT_DIR, "static")

# Create Flask WSGI application instance
app = create_app(db_path=db_file, static_folder=static_dir)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 70)
    print("   CLOUD-D: AUTONOMOUS THREAT DEFENSE & ENCRYPTED STORAGE PLATFORM")
    print("   PSG College of Technology — Nithish M (Roll No. 24X064)")
    print("=" * 70)
    print(f"[*] Binding Server: http://{host}:{port}")
    print(f"[*] Persistent Database: {db_file}")
    print(f"[*] Static Assets: {static_dir}")
    print(f"[*] Credentials: username='nithish' | password='nithish123'")
    print("=" * 70)
    app.run(host=host, port=port, debug=False, threaded=True)
