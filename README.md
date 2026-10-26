# Cloud-D: Autonomous Multi-Agent Threat Defense & Encrypted Cloud Storage

**Student Investigator**: Nithish M (Roll No. 24X064)  
**Department & Institution**: Department of Applied Mathematics & Computational Sciences, PSG College of Technology, Coimbatore  
**Live Deployed Service**: [https://cloud-d.onrender.com/](https://cloud-d.onrender.com/)  
**Repository**: [https://github.com/Nithishammu/cloud-d-enterprise-security.git](https://github.com/Nithishammu/cloud-d-enterprise-security.git) (Branch: `main`)  
**Documentation Revision Date**: October 26, 2026  

---

## 🚀 Overview

Cloud-D is an enterprise-grade cloud storage platform paired with an autonomous multi-agent threat defense network. It provides users with a realistic, responsive Google Drive-like cloud storage experience fortified by zero-knowledge AES-256-GCM authenticated encryption (AEAD), paired with an autonomous multi-agent defense simulation where AI sentinel agents continuously evaluate, detect, and neutralize simulated adversarial attacks across distributed cloud nodes in real time.

---

## 📦 Delivered & Implemented Capabilities (Tasks 1 through 8)

| Task / Feature | Implementation Details | Target Platform | Status |
| :--- | :--- | :--- | :--- |
| **Pure Minimax (No Pruning)** | 2-ply exhaustive search in `cloud_d/logic/search.py` evaluating complete game tree without pruning. | Backend | Delivered & Verified |
| **Expectimax Search** | Probability-weighted chance node search for SQL query injection sanitization under AST uncertainty. | Backend | Delivered & Verified |
| **Task 1: Automated Web-to-App Sync** | Dynamic service worker cache versioning (`CACHE_NAME`), hot-reloading hooks (`skipWaiting`, `clients.claim`), and `/api/version` endpoint. | Web & Mobile PWA | **Delivered & Verified** |
| **Task 2: Client-Side WebCrypto Key Derivation** | PBKDF2/AES-GCM in-browser encryption (`deriveKey`) before upload, ensuring zero-knowledge privacy on server shards. | Web & Mobile | **Delivered & Verified** |
| **Task 3: Native Mobile Push Notifications** | Web Push API / VAPID protocol, push subscription persistence, and automated Sentinel threat alerts to mobile devices. | iOS & Android PWA | **Delivered & Verified** |
| **Task 4: Biometric WebAuthn Authentication** | W3C WebAuthn credentials API for FaceID, TouchID, and Android Fingerprint passwordless sign-in. | Mobile & Web | **Delivered & Verified** |
| **Task 5: Multi-File Drag & Drop Reorganization** | HTML5 drag-and-drop & mobile touch reordering across Google Drive folders grid; atomic `/api/files/batch-move`. | Web UI & Mobile | **Delivered & Verified** |
| **Task 6: Expiring Encrypted Share Links** | `/share/<token>` portal with time-to-live (TTL) expiration, download quotas, PBKDF2 access passwords, and revocation. | Web & Mobile | **Delivered & Verified** |
| **Task 7: Real-Time Collaborative CRDT Editor** | Sequence CRDT (Conflict-free Replicated Data Type) engine for simultaneous multi-user document editing without overwrites. | Web & Mobile | **Delivered & Verified** |
| **Task 8: Continuous Red-Teaming AI Agent** | Reinforcement learning (Q-learning) agent generating evolving zero-day payloads (SQLi, Shard AAD tampering, Nonce reuse, Rate bursts). | Backend & UI | **Delivered & Verified** |
| **Hardware AEAD Integrity Proof** | In-browser verification dialog for 128-bit Galois tag, 96-bit nonce, and SHA-256 payload checksum. | Web UI | Delivered & Verified |
| **Visual Version Diff & Rollback** | Line-by-line unified diff (+ green, - red) and one-click rollback/promotion of historical revisions. | Web UI | Delivered & Verified |

---

## 🛠️ Quick Start & Running Locally

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Comprehensive Test Suite
```bash
python tests/test_all_features.py
```

### 3. Launch the Server
```bash
python run_server.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser or mobile emulator.
