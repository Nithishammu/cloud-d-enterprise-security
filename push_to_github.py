"""Cloud-D Enterprise Security - Automated GitHub Deployment Engine.

Deploys the complete codebase directly to:
    https://github.com/Nithishammu/cloud-d-enterprise-security.git (branch: main)

Supports:
- Direct GitHub Git Data REST API (zero Git CLI dependency)
- Automatic base64 binary encoding for .docx and assets
- Preservation of complete commit history on top of existing main branch
- Automatic webhook triggering on Render (https://cloud-d.onrender.com/)

Usage:
    python push_to_github.py [GITHUB_TOKEN]
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

# Ensure standard output can print utf-8 safely on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO_OWNER = "Nithishammu"
REPO_NAME = "cloud-d-enterprise-security"
BRANCH = "main"
COMMIT_MSG = "Deploy Cloud-D: Complete Production Release with Procfile, runtime.txt, lean requirements, strict login gating, and mobile app layer"
AUTHOR_NAME = "Nithish M"
AUTHOR_EMAIL = "nithish@psgtech.ac.in"


def github_request(
    endpoint: str,
    token: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}{endpoint}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None

    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "Cloud-D-Deployer/3.2.0")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()
            return json.loads(content.decode("utf-8")) if content else {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"GitHub API Error [{e.code}]: {error_body}") from e


def collect_deployable_files(base_dir: str) -> List[str]:
    files_to_deploy = []
    ignore_dirs = {".git", "__pycache__", ".pytest_cache", ".gemini", "venv", ".venv", "node_modules"}
    ignore_files = {".DS_Store", "cloud_d_production.db", "cloud_d_test.db", "desktop.ini"}

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f in ignore_files or f.endswith(".pyc"):
                continue
            rel_path = os.path.relpath(os.path.join(root, f), base_dir).replace("\\", "/")
            files_to_deploy.append(rel_path)

    return sorted(files_to_deploy)


def deploy_to_github(token: str) -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))

    print("=" * 70)
    print("   CLOUD-D: AUTONOMOUS GITHUB DEPLOYMENT PIPELINE")
    print(f"   Target: https://github.com/{REPO_OWNER}/{REPO_NAME} (branch: {BRANCH})")
    print("=" * 70)

    # 1. Verify token & get current head commit of main
    print("\n[1/5] Fetching remote branch reference...")
    ref_data = github_request(f"/git/ref/heads/{BRANCH}", token)
    parent_commit_sha = ref_data["object"]["sha"]
    print(f"  [+] Current {BRANCH} HEAD SHA: {parent_commit_sha}")

    # 2. Get base tree SHA from parent commit
    print("\n[2/5] Retrieving base tree structure...")
    commit_data = github_request(f"/git/commits/{parent_commit_sha}", token)
    base_tree_sha = commit_data["tree"]["sha"]
    print(f"  [+] Base Tree SHA: {base_tree_sha}")

    # 3. Create blobs for all active files
    files = collect_deployable_files(base_dir)
    print(f"\n[3/5] Packaging {len(files)} files into Git blobs...")
    tree_items = []

    for idx, rel_path in enumerate(files, 1):
        full_path = os.path.join(base_dir, rel_path.replace("/", os.sep))
        with open(full_path, "rb") as fp:
            content_bytes = fp.read()

        # Send as base64 blob to handle both text and binary files (like .docx)
        b64_content = base64.b64encode(content_bytes).decode("ascii")
        blob_res = github_request(
            "/git/blobs",
            token,
            method="POST",
            payload={"content": b64_content, "encoding": "base64"},
        )
        blob_sha = blob_res["sha"]
        tree_items.append({
            "path": rel_path,
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
        })
        print(f"  [{idx:02d}/{len(files):02d}] Staged: {rel_path} ({len(content_bytes):,} bytes)")

    # 4. Create new Git Tree
    print("\n[4/5] Creating Git tree object...")
    tree_res = github_request(
        "/git/trees",
        token,
        method="POST",
        payload={"base_tree": base_tree_sha, "tree": tree_items},
    )
    new_tree_sha = tree_res["sha"]
    print(f"  [+] New Tree SHA: {new_tree_sha}")

    # 5. Create Git Commit and update branch reference
    print("\n[5/5] Creating commit and updating main branch...")
    commit_res = github_request(
        "/git/commits",
        token,
        method="POST",
        payload={
            "message": COMMIT_MSG,
            "tree": new_tree_sha,
            "parents": [parent_commit_sha],
            "author": {
                "name": AUTHOR_NAME,
                "email": AUTHOR_EMAIL,
                "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        },
    )
    new_commit_sha = commit_res["sha"]
    print(f"  [+] New Commit SHA: {new_commit_sha}")

    update_res = github_request(
        f"/git/refs/heads/{BRANCH}",
        token,
        method="PATCH",
        payload={"sha": new_commit_sha, "force": False},
    )
    print(f"  [+] Branch {BRANCH} successfully updated to {new_commit_sha}")

    print("\n" + "=" * 70)
    print("SUCCESS: DEPLOYMENT COMPLETE!")
    print(f"   Commit URL: https://github.com/{REPO_OWNER}/{REPO_NAME}/commit/{new_commit_sha}")
    print("   Live Service: https://cloud-d.onrender.com/ (Render automated deploy triggered)")
    print("=" * 70)
    return new_commit_sha


def main():
    token = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GITHUB_TOKEN")
    if not token:
        token = input("Enter your GitHub Personal Access Token (PAT): ").strip()

    if not token:
        print("Error: A GitHub Personal Access Token is required to deploy.")
        sys.exit(1)

    try:
        deploy_to_github(token)
    except Exception as err:
        print(f"\n[-] Deployment failed: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
