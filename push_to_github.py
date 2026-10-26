"""One-Click GitHub Push Utility for Cloud-D.

Uses pure Python Dulwich and Certifi to push directly to GitHub without requiring Git installed.
Usage:
    python push_to_github.py [GITHUB_TOKEN]
"""

import os
import sys
import certifi

os.environ["SSL_CERT_FILE"] = certifi.where()

from dulwich import porcelain
from dulwich.repo import Repo

REPO_PATH = os.path.dirname(os.path.abspath(__file__))
REMOTE_URL = "https://github.com/Nithishammu/cloud-d-enterprise-security.git"

def main():
    token = sys.argv[1] if len(sys.argv) > 1 else None
    if not token:
        print("=" * 65)
        print("   CLOUD-D: PUSH TO GITHUB REPOSITORY (NO GIT REQUIRED)")
        print("=" * 65)
        print(f"Target Remote: {REMOTE_URL}")
        print("To push to GitHub, enter your GitHub Personal Access Token (PAT):")
        print("(Generate one at: https://github.com/settings/tokens with 'repo' scope)")
        print()
        token = input("Enter GitHub Token (or press Enter to cancel): ").strip()
        if not token:
            print("Push canceled.")
            return

    # Formulate authenticated remote URL
    # https://<token>@github.com/Nithishammu/cloud-d-enterprise-security.git
    auth_url = f"https://{token}@github.com/Nithishammu/cloud-d-enterprise-security.git"

    repo = Repo(REPO_PATH)
    print("Staging latest changes...")
    porcelain.add(repo, ".")

    try:
        commit_id = porcelain.commit(
            repo,
            message=b"Update Cloud-D: Google Drive replica, Recent layout, Handover Word doc, and Autonomous Threat Defense",
            author=b"Nithish M <nithish@psgtech.ac.in>",
        )
        print(f"Created local commit: {commit_id.decode() if isinstance(commit_id, bytes) else commit_id}")
    except Exception as e:
        print(f"Note: {e} (Working directory already clean)")

    print(f"Pushing refs/heads/main to {REMOTE_URL}...")
    try:
        porcelain.push(repo, auth_url, "refs/heads/main", force=True)
        print("SUCCESS! Project pushed to GitHub main branch successfully!")
        print("Render (https://cloud-d.onrender.com/) will automatically rebuild and deploy!")
    except Exception as err:
        print(f"Push failed: {err}")
        print("\nAlternative: If you have Git installed, simply run:")
        print("  git add .")
        print('  git commit -m "Update Cloud-D Deliverables"')
        print("  git push origin main")

if __name__ == "__main__":
    main()
