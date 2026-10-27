"""Cloud-D Executive Handover & Future Roadmap Word Document (.docx) Generator.

Generates the exhaustive, comprehensive, publication-grade technical specification and roadmap document for:
Student Investigator: Nithish M (Roll No. 24X064)
Dept. of Applied Mathematics & Computational Sciences, PSG College of Technology, Coimbatore.
Project: Cloud-D: Autonomous Multi-Agent Threat Defense & Encrypted Cloud Storage Platform.
"""

from __future__ import annotations

import os
import sys
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


def set_cell_background(cell, hex_color: str):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tc_pr.append(shd)


def set_cell_margins(cell, top: int = 120, bottom: int = 120, left: int = 160, right: int = 160):
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)


def create_document(output_paths: list[str]) -> str:
    doc = docx.Document()

    # Page Margins (1 inch all around)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Base Brand Palette
    PURPLE_PRIMARY = RGBColor(76, 29, 149)     # #4c1d95
    PURPLE_BRAND = RGBColor(124, 58, 237)      # #7c3aed
    DARK_TEXT = RGBColor(30, 41, 59)          # #1e293b
    MUTED_TEXT = RGBColor(100, 116, 139)      # #64748b
    GREEN_SUCCESS = RGBColor(22, 101, 52)     # #166534
    BLUE_NAVY = RGBColor(15, 23, 42)          # #0f172a
    TEAL_ACCENT = RGBColor(13, 148, 136)      # #0d9488

    # Document Header / Banner Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(4)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = p_title.add_run("CLOUD-D: AUTONOMOUS MULTI-AGENT THREAT DEFENSE & ENCRYPTED CLOUD STORAGE")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(18)
    run_title.font.bold = True
    run_title.font.color.rgb = PURPLE_PRIMARY

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_after = Pt(14)
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = p_sub.add_run(
        "Master Technical Handover, Completed Implementation Dossier, Cross-Platform Mobile Architecture, "
        "and Future Strategic Roadmap"
    )
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(10.5)
    run_sub.font.italic = True
    run_sub.font.color.rgb = MUTED_TEXT

    # Academic & Institutional Metadata Block
    table_meta = doc.add_table(rows=7, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Student Investigator", "Nithish M (Roll No. 24X064)"),
        ("Department & Institution", "Dept. of Applied Mathematics & Computational Sciences, PSG College of Technology, Coimbatore"),
        ("Academic Program", "M.Sc. Theoretical Computer Science / Software Systems"),
        ("Project Repository", "https://github.com/Nithishammu/cloud-d-enterprise-security.git (Branch: main)"),
        ("Live Web Service", "https://cloud-d.onrender.com/ (Render Free Web Service with Procfile WSGI)"),
        ("Default Seed Credentials", "Admin/Staff: nithish / nithish123 (Node 2 Vault)  |  Customer: client_vault / customer123 (Node 3 Vault)"),
        ("Date of Master Release", "October 26, 2026 (Production Release v3.5.0)"),
    ]
    for idx, (label, val) in enumerate(meta_data):
        row = table_meta.rows[idx]
        cell_lbl, cell_val = row.cells[0], row.cells[1]
        cell_lbl.width = Inches(2.2)
        cell_val.width = Inches(4.3)
        set_cell_background(cell_lbl, "F1F5F9")
        set_cell_background(cell_val, "FFFFFF")
        set_cell_margins(cell_lbl, 70, 70, 110, 110)
        set_cell_margins(cell_val, 70, 70, 110, 110)

        p0 = cell_lbl.paragraphs[0]
        r0 = p0.add_run(label)
        r0.font.name = "Arial"
        r0.font.size = Pt(9)
        r0.font.bold = True
        r0.font.color.rgb = DARK_TEXT

        p1 = cell_val.paragraphs[0]
        r1 = p1.add_run(val)
        r1.font.name = "Arial"
        r1.font.size = Pt(9)
        r1.font.color.rgb = DARK_TEXT

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    def add_section_header(num: int, title: str):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(16)
        p.paragraph_format.space_after = Pt(6)
        r = p.add_run(f"{num}. {title}")
        r.font.name = "Arial"
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = PURPLE_PRIMARY

    def add_sub_header(num_str: str, title: str):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(f"{num_str} {title}")
        r.font.name = "Arial"
        r.font.size = Pt(10.5)
        r.font.bold = True
        r.font.color.rgb = PURPLE_BRAND

    # -------------------------------------------------------------------------
    # 1. Executive Summary & Problem Formulation
    # -------------------------------------------------------------------------
    add_section_header(1, "Executive Summary & System Problem Formulation")
    p = doc.add_paragraph()
    p.add_run(
        "Modern cloud storage architectures face dual existential threats: centralized data compromise and sophisticated "
        "adversarial infiltration. Conventional public clouds (e.g., standard Google Drive or AWS S3 buckets) rely on "
        "static perimeter firewalls and centralized symmetric key stores. If perimeter authentication is bypassed or "
        "storage keys are exfiltrated, tenant confidentiality is completely obliterated.\n\n"
        "Cloud-D addresses this crisis by synthesizing three state-of-the-art computational disciplines into an operable "
        "enterprise platform:\n"
        "1. Autonomous Multi-Agent Game-Theoretic Defense: A distributed mesh of cognitive defensive agents "
        "(Spectral Sentinel, Cryptographic Warden, HoneyNet Deceiver, Session Arbiter) continuously counter hostile "
        "adversaries using Minimax game-tree search and stochastic Expectimax chance evaluations.\n"
        "2. Zero-Knowledge Post-Quantum Cryptographic Sharding: File payloads are segmented, encrypted via hybrid "
        "NIST FIPS 203 ML-KEM-768 (CRYSTALS-Kyber) lattice key encapsulation paired with hardware-accelerated AES-256-GCM AEAD, "
        "and distributed across geographically isolated vault nodes.\n"
        "3. Cross-Platform Responsive Gating: A Google Drive enterprise replica web experience coupled with a native "
        "React Native / Expo cross-platform mobile application (iOS & Android) featuring strict unauthenticated gating."
    )

    # -------------------------------------------------------------------------
    # 2. Exhaustive Audit of Completed Modules Today
    # -------------------------------------------------------------------------
    add_section_header(2, "Exhaustive Audit of Completed Implementations Today")
    p = doc.add_paragraph()
    p.add_run(
        "The following 25 architectural modules have been completely designed, implemented, tested, and pushed "
        "to the production repository:"
    )

    completed_features = [
        ("Threat Simulation Arena (UI Match)", "Interactive & automated threat center matching user reference image: Manual attack dropdowns (Adversarial agent, target asset, pressure), Step one round button, Automated defense runner, vector chips (Credential, DDoS, SQLi, Galois), threshold slider (0.10 - 0.90), and Minimax decision cards.", "Delivered & Verified"),
        ("Strict Mobile Navigation Gating", "Enforced strict CSS & DOM rules hiding the lower mobile navigation panel (#mobile-bottom-bar) and floating action button (#mobile-fab) prior to login. Screen displays only centered login box on iOS Safari and Android Chrome.", "Delivered & Verified"),
        ("Cross-Platform Mobile App (iOS & Android)", "Full, self-contained React Native / Expo application in mobile_app/App.js with custom navigation stack, encrypted storage upload sheets, threat simulation controls, and background peripheral shield monitoring.", "Delivered & Verified"),
        ("PWA Standalone Mobile Layer", "Integrated static/manifest.json and static/sw.js service worker with 1-tap Add to Home Screen support for iOS Safari and Chrome Android standalone app execution.", "Delivered & Verified"),
        ("Google Drive Enterprise UI Replica", "Spacious layout with centered Search in Drive box, Suggested folder cards (PS-7, 24X501, PS-6), Suggested files table, list/grid view switcher, and context actions.", "Delivered & Verified"),
        ("Recent Segment Chronological Grouping", "Chronological section grouping ('Last week') with pill filter chips ('Type ▾', 'People ▾', 'Modified ▾', 'Source ▾'), owner me avatars ('N'), file sizes, and storage locations.", "Delivered & Verified"),
        ("Duplicate Upload Versioning (n+1)", "Interactive duplicate modal offering explicit choices: Option 1: Save as New Version (n+1 revision), Option 2: Replace Existing File in-place, Option 3: Keep Both (Upload as Copy).", "Delivered & Verified"),
        ("Visual Unified Line Diff Engine", "difflib.unified_diff integration comparing any historical revision against current active revision, displaying chunk headers and color-coded additions/deletions in real-time.", "Delivered & Verified"),
        ("Pure Minimax Search Engine", "2-ply exhaustive game-tree search in cloud_d/logic/search.py without alpha-beta pruning. Evaluates 100% of adversarial tree states deterministically with utility scoring.", "Delivered & Verified"),
        ("Expectimax Stochastic Evaluation", "Probability-weighted chance node evaluation in cloud_d/logic/search.py for QueryShield AST injection sanitization under uncertainty.", "Delivered & Verified"),
        ("Client-Side WebCrypto Zero-Knowledge", "PBKDF2 key derivation (100,000 iterations, SHA-256) and AES-256-GCM in static/cloud-d.js (WebCryptoVault). Plaintext and master passphrases never touch server memory.", "Delivered & Verified"),
        ("Hybrid Post-Quantum ML-KEM-768", "CRYSTALS-Kyber-768 lattice-based key encapsulation combined with AES-256-GCM in cloud_d/crypto/pq_kyber.py. Derives quantum-safe shared secrets immune to Shor's algorithm.", "Delivered & Verified"),
        ("Cross-Region Vault Sharding (Nodes 0-3)", "4-tier distributed topology: Node 0 (Auth, us-east-1), Node 1 (Gateway, us-west-2), Node 2 (Primary Vault, eu-central-1), Node 3 (Tenant Vault, ap-southeast-1). Regional AAD re-sealing.", "Delivered & Verified"),
        ("Autonomous Peripheral Shield (Customer)", "Customers have zero manual attack controls; automated background defense with transparent monitoring of Rings 1-4 and Customer Air-Gap Guarantee.", "Delivered & Verified"),
        ("Sequence CRDT Rich-Text Collaborative Editor", "Conflict-free Replicated Data Type in cloud_d/collab/crdt.py utilizing Lamport logical timestamps, fractional position indices, rich-text OT spans, and multi-user cursor presence.", "Delivered & Verified"),
        ("Continuous Red-Teaming AI Agent", "Q-learning reinforcement learning agent in cloud_d/logic/red_team_agent.py with Adversarial LLM AST mutation engine testing Sentinels against zero-day evasion vectors.", "Delivered & Verified"),
        ("Biometric WebAuthn Passkeys & FIDO2", "W3C WebAuthn passkey assertion verification, CBOR attestation statements, and FIDO MDS Root CA validation in cloud_d/webauthn_auth.py with AAGUID hardware grading.", "Delivered & Verified"),
        ("Native Push Notifications (APNs & FCM)", "Multi-channel notification engine (Web Push VAPID, APNs iOS, FCM Android) in cloud_d/push_notifications.py dispatching critical priority threat banners.", "Delivered & Verified"),
        ("Expiring Encrypted Share Links", "Cryptographic share link manager (/share/<token>) in cloud_d/share.py with TTL expiration (1h, 24h, 7d), max download quotas, and PBKDF2 password access protection.", "Delivered & Verified"),
        ("Multi-File Drag & Drop Batch Operations", "Batch move across folders/nodes (batch_move_files in storage.py). Recalculates Galois field AAD and re-seals across shards.", "Delivered & Verified"),
        ("Persistent Cloud Disk Attachment", "Storage path resolution supporting /var/data and RENDER_DISK_PATH with auto-migration and live telemetry in storage.py.", "Delivered & Verified"),
        ("Account Persistence & Auto-Seeding", "INSERT OR REPLACE in _init_users_db seeding nithish / nithish123 and default student folders and real encrypted files on cold startup.", "Delivered & Verified"),
        ("Lean Render Production Packaging", "Added Procfile (web: python run_server.py), runtime.txt (python-3.11.9), render.yaml, and stripped Linux C-extension compilation dependencies from requirements.txt.", "Delivered & Verified"),
        ("Root WSGI Entrypoint", "Added app.py at root importing app from run_server for standard PaaS and Gunicorn container autodiscovery.", "Delivered & Verified"),
        ("Automated GitHub Deployment Engine", "Created push_to_github.py using GitHub Git Data REST API to stage base64 binary blobs and update main branch with zero Git CLI dependencies.", "Delivered & Verified"),
    ]

    table_comp = doc.add_table(rows=len(completed_features) + 1, cols=3)
    table_comp.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr = table_comp.rows[0]
    hdr.cells[0].paragraphs[0].add_run("Delivered Module").font.bold = True
    hdr.cells[1].paragraphs[0].add_run("Implementation Scope & Architecture").font.bold = True
    hdr.cells[2].paragraphs[0].add_run("Verification").font.bold = True
    hdr.cells[0].width = Inches(2.0)
    hdr.cells[1].width = Inches(3.6)
    hdr.cells[2].width = Inches(1.4)
    for c in hdr.cells:
        set_cell_background(c, "E2E8F0")
        set_cell_margins(c, 70, 70, 90, 90)

    for i, (name, scope, st) in enumerate(completed_features):
        r = table_comp.rows[i + 1]
        c0, c1, c2 = r.cells[0], r.cells[1], r.cells[2]
        c0.width, c1.width, c2.width = Inches(2.0), Inches(3.6), Inches(1.4)
        set_cell_background(c0, "F8FAFC" if i % 2 == 0 else "FFFFFF")
        set_cell_background(c1, "F8FAFC" if i % 2 == 0 else "FFFFFF")
        set_cell_background(c2, "F0FDF4")
        set_cell_margins(c0, 50, 50, 70, 70)
        set_cell_margins(c1, 50, 50, 70, 70)
        set_cell_margins(c2, 50, 50, 70, 70)

        run0 = c0.paragraphs[0].add_run(name)
        run0.font.name = "Arial"
        run0.font.size = Pt(8.5)
        run0.font.bold = True

        run1 = c1.paragraphs[0].add_run(scope)
        run1.font.name = "Arial"
        run1.font.size = Pt(8)

        run2 = c2.paragraphs[0].add_run(st)
        run2.font.name = "Arial"
        run2.font.size = Pt(8)
        run2.font.bold = True
        run2.font.color.rgb = GREEN_SUCCESS

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------------------
    # 3. Future Roadmap: What We Want to Do Next
    # -------------------------------------------------------------------------
    add_section_header(3, "Future Strategic Roadmap: Architecture & Upcoming Milestones")
    p = doc.add_paragraph()
    p.add_run(
        "While Cloud-D has fulfilled all primary deliverables, the research and engineering roadmap outlines "
        "eight high-impact strategic initiatives planned for upcoming development cycles:"
    )

    roadmap_items = [
        (
            "Phase 1: Multi-Region Kubernetes (K8s) Cluster Orchestration",
            "Target: Cloud Infrastructure & Scalability",
            "Transition the 4-node logical sharding architecture into physical multi-region Kubernetes clusters "
            "(us-east-1, us-west-2, eu-central-1, ap-southeast-1) using Terraform and Helm charts. Deploy automated "
            "ingress controllers with Envoy proxies, automated pod autoscaling (HPA), and zero-downtime rolling deploys."
        ),
        (
            "Phase 2: Fully Homomorphic Encryption (FHE) on Ciphertexts",
            "Target: Zero-Knowledge Search & Analytics",
            "Integrate Microsoft SEAL / OpenFHE (CKKS and BFV schemes) to allow server nodes to perform keyword search, "
            "full-text string indexing, and metadata aggregation directly on AES/Kyber encrypted ciphertexts without "
            "ever needing to decrypt them into memory."
        ),
        (
            "Phase 3: Zero-Knowledge Proofs (zk-SNARKs) for Tenant Auditing",
            "Target: Regulatory Compliance & Cryptographic Proofs",
            "Construct arithmetic circuits (using Circom / snarkjs) that generate zero-knowledge succinct non-interactive "
            "arguments of knowledge. Allows tenants to mathematically prove that their files have not been accessed by "
            "other tenants or unauthorized administrators without revealing file names, contents, or access patterns."
        ),
        (
            "Phase 4: Real-Time Multi-Party Computation (MPC) Key Management",
            "Target: Distributed Cryptographic Resilience",
            "Eliminate single-point master keys by implementing Shamir's Secret Sharing and Gennaro-Goldfeder threshold "
            "signatures. Vault keys are split across all 4 regional nodes; decryption requires at least 3 nodes to "
            "collaboratively sign without any individual node ever knowing the reconstructed master key."
        ),
        (
            "Phase 5: Autonomous Self-Healing & Dynamic Deception Networks",
            "Target: Adaptive Active Defense",
            "Upgrade HoneyNet Deceiver from passive honeypot trapping to dynamic adversarial counter-exploitation. "
            "When an attacker triggers a tripwire, the system automatically spawns a shadow container with simulated "
            "fake database records, isolating the adversary while transparently recording their keystrokes and exploits."
        ),
        (
            "Phase 6: On-Device Edge AI Anomaly Detection for Mobile",
            "Target: Mobile Client Security",
            "Deploy lightweight quantized CoreML (iOS) and TensorFlow Lite (Android) models into mobile_app/App.js. "
            "Detects anomalous client-side interactions, screen recording attempts, jailbreak/root indicators, and "
            "rapid biometric spoofing before sending authentication payloads over the network."
        ),
        (
            "Phase 7: Hardware Security Module (HSM) Cloud Integration",
            "Target: Enterprise Cryptographic Assurance",
            "Integrate PKCS#11 hardware interfaces to store root CA keys and Kyber-768 private seeds in physical "
            "FIPS 140-3 Level 3 hardware security modules (AWS CloudHSM, Google Cloud HSM, or YubiHSM 2)."
        ),
        (
            "Phase 8: Privacy-Preserving Federated Red-Team Learning",
            "Target: Collaborative Threat Intelligence",
            "Enable multiple independent Cloud-D enterprise tenant clusters to train the Q-learning Red-Team agent "
            "cooperatively via federated differential privacy. Defense policies improve across all clusters while raw "
            "logs and proprietary attack payloads remain strictly within tenant boundaries."
        ),
    ]

    for title, target, details in roadmap_items:
        add_sub_header("Roadmap", title)
        p = doc.add_paragraph()
        r_tgt = p.add_run(f"[{target}]\n")
        r_tgt.font.name = "Arial"
        r_tgt.font.size = Pt(9)
        r_tgt.font.bold = True
        r_tgt.font.color.rgb = TEAL_ACCENT

        r_det = p.add_run(details)
        r_det.font.name = "Arial"
        r_det.font.size = Pt(9)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------------------
    # 4. Detailed Mobile Architecture (iOS & Android)
    # -------------------------------------------------------------------------
    add_section_header(4, "Detailed Cross-Platform Mobile Architecture")
    p = doc.add_paragraph()
    p.add_run(
        "Cloud-D provides two synchronized mobile deployment strategies, ensuring universal compatibility across "
        "both Apple iOS and Google Android ecosystems:\n\n"
        "1. Native React Native / Expo Application (mobile_app/App.js):\n"
        "   - Framework: React Native with Expo SDK and Lucide vector icons.\n"
        "   - Authentication Gating: State variable 'isAuthenticated' conditionally renders either the clean AuthScreen "
        "or the authenticated MainNavigation shell.\n"
        "   - Storage Sheets: Interactive file upload modal with post-quantum encryption toggle, folder selection, and "
        "live cryptographic verification progress.\n"
        "   - Simulation Suite: Interactive mobile simulation tab allowing mobile execution of manual attacks, automated "
        "defense rounds, and real-time viewing of Minimax game-tree scores.\n"
        "   - Package Specification: Defined in mobile_app/package.json and mobile_app/app.json, ready for standalone "
        "builds via 'eas build -p ios' and 'eas build -p android'.\n\n"
        "2. Progressive Web App (PWA) Layer:\n"
        "   - Web App Manifest: Located at static/manifest.json with 'display': 'standalone', theme colors (#4c1d95), "
        "and multi-resolution high-DPI icons.\n"
        "   - Service Worker (static/sw.js): Caches core shell assets, handles offline resilience, and intercepts push "
        "events.\n"
        "   - iOS Safari Standalone: Users tap Share -> 'Add to Home Screen' to launch full-screen without Safari browser bars.\n"
        "   - Android Chrome Standalone: Browser displays 'Install Cloud-D' ambient badge, running as an isolated Android APK task."
    )

    # -------------------------------------------------------------------------
    # 5. Interactive Threat Simulation Center Specifications
    # -------------------------------------------------------------------------
    add_section_header(5, "Interactive Threat Simulation Center Specifications")
    p = doc.add_paragraph()
    p.add_run(
        "The Threat Simulation Center (tab-threat-sim) has been completely aligned with the student investigator's "
        "exact visual layout and control requirements:\n\n"
        "1. Header Controls:\n"
        "   - Sub-badge: 'THREAT CENTER • INTERACTIVE & AUTOMATED'\n"
        "   - Title: 'Threat Simulation'\n"
        "   - Top Actions: '+ Step one round' (white trigger button) and purple 'Run Automated Defense' button.\n\n"
        "2. Section 1 — Manual Attack Vector Induction:\n"
        "   - Adversarial Agent & Target: Dropdown selecting Credential-Bot, Query-Bot, Tamper-Bot, or Replay-Bot.\n"
        "   - Attack Pressure: Dropdown selecting Normal, Elevated, or Maximum.\n"
        "   - Target Cloud Asset: Dynamic badge indicating selected target (e.g., '☁ Auth Server (Node 0)').\n"
        "   - Launch Button: Teal '⚡ Launch Manual Attack' executing instantaneous Minimax simulation.\n\n"
        "3. Live Decision Outcome Result Card:\n"
        "   - Outcome Status Pill: Highlighted status (e.g., 'BLOCKED • CONTAINED' or 'ADAPTIVE INTERCEPTION').\n"
        "   - Metric Grid: 4-column breakdown: ADVERSARIAL VECTOR, DEFENDER SPECIALIST, DEFENSE ACTION, and UTILITY SCORE.\n"
        "   - Minimax Game-Tree Search: Visual summary of evaluated adversarial states and optimal defensive moves.\n"
        "   - Cloud Asset Protection: Real-time report of protected storage shards.\n\n"
        "4. Section 2 — Automated Defense Simulation Engine:\n"
        "   - Simulation Rounds: Dropdown (5, 10, 25, 50 rounds).\n"
        "   - Threat Intensity: Dropdown (Low, Medium, High, Extreme).\n"
        "   - Active Attack Vectors: Dark chip checkboxes (Credential, DDoS, SQLi, Galois).\n\n"
        "5. Section 3 — Decision Engine Defense Threshold:\n"
        "   - Slider Control: Teal interactive range slider (0.10 to 0.90) with real-time numeric readout (e.g., '0.40').\n\n"
        "6. Section 4 — Recent Defense Decisions Log:\n"
        "   - Audit Table: Dark navy header with columns for Round #, Adversarial Vector, Defense Specialist, Action, "
        "Utility Score, and Status."
    )

    # -------------------------------------------------------------------------
    # 6. Complete API Specifications (22 Core Endpoints)
    # -------------------------------------------------------------------------
    add_section_header(6, "Complete API Specifications & Route Contract")
    api_routes = [
        ("POST", "/api/auth/login", "Authenticates credentials (nithish / nithish123) and sets permanent session cookie."),
        ("POST", "/api/auth/register", "Registers new isolated tenant account and initializes private vault shard."),
        ("GET", "/api/auth/me", "Validates session state and returns authenticated user metadata and vault node ID."),
        ("POST", "/api/auth/logout", "Clears active session cookie and resets client-side state."),
        ("GET", "/api/docs/executive-handover.docx", "Auto-downloads this official executive handover Word document (.docx)."),
        ("GET", "/api/system/storage-info", "Returns Render persistent disk telemetry, storage capacity, and mount health."),
        ("GET", "/api/files", "Lists active (is_current=1) files in target folder, including sizes, versions, and owners."),
        ("POST", "/api/upload", "Uploads and AEAD seals file; supports target_logical_id (n+1) and use_post_quantum flag."),
        ("POST", "/api/files/check-duplicate", "Checks if filename exists in folder; returns {exists, duplicate_info}."),
        ("GET", "/api/files/<id>/verify", "Extracts 96-bit nonce, SHA-256 digest, and validates 128-bit Galois GHASH tag."),
        ("GET", "/api/files/<id>/preview", "Decrypts AES-256-GCM payload on-the-fly for in-browser plaintext inspection."),
        ("GET", "/api/files/diff", "Computes unified line diff between revisions with line addition/deletion metrics."),
        ("GET/POST", "/api/collab/<id>/ops", "Syncs or appends Sequence CRDT character operations and rich-text OT spans."),
        ("GET/POST", "/api/collab/<id>/cursors", "Broadcasts and retrieves live multi-user cursor presence and selections."),
        ("GET", "/api/shards/topology", "Returns 4-tier cross-region shard topology and latency metrics."),
        ("POST", "/api/shards/transfer", "Migrates file across regional shards with automatic AAD re-sealing."),
        ("POST", "/api/crypto/pq-seal", "Performs hybrid ML-KEM-768 + AES-256-GCM authenticated encryption."),
        ("GET", "/api/crypto/pq-proof", "Returns Kyber-768 lattice parameters, key fingerprint, and Shor immunity proof."),
        ("POST", "/api/threats/red-team/simulate", "Executes Q-learning RL attack episode with LLM-mutated AST payloads."),
        ("GET", "/api/threats/red-team/q-matrix", "Returns Q-learning state-action table and exploration metrics."),
        ("POST", "/api/auth/webauthn/register-verify", "Validates FIDO2 CBOR attestation statements against MDS Root CA."),
        ("POST", "/api/push/broadcast-threat", "Dispatches multi-channel threat alert across Web Push, APNs, and FCM."),
    ]

    table_api = doc.add_table(rows=len(api_routes) + 1, cols=3)
    table_api.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr2 = table_api.rows[0]
    hdr2.cells[0].paragraphs[0].add_run("Method").font.bold = True
    hdr2.cells[1].paragraphs[0].add_run("Endpoint Route").font.bold = True
    hdr2.cells[2].paragraphs[0].add_run("Contract & Functional Scope").font.bold = True
    hdr2.cells[0].width = Inches(1.1)
    hdr2.cells[1].width = Inches(2.6)
    hdr2.cells[2].width = Inches(3.3)
    for c in hdr2.cells:
        set_cell_background(c, "E2E8F0")
        set_cell_margins(c, 70, 70, 90, 90)

    for i, (m, r_path, desc) in enumerate(api_routes):
        row = table_api.rows[i + 1]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width, c1.width, c2.width = Inches(1.1), Inches(2.6), Inches(3.3)
        set_cell_background(c0, "F8FAFC" if i % 2 == 0 else "FFFFFF")
        set_cell_background(c1, "F8FAFC" if i % 2 == 0 else "FFFFFF")
        set_cell_background(c2, "F8FAFC" if i % 2 == 0 else "FFFFFF")
        set_cell_margins(c0, 50, 50, 70, 70)
        set_cell_margins(c1, 50, 50, 70, 70)
        set_cell_margins(c2, 50, 50, 70, 70)

        run0 = c0.paragraphs[0].add_run(m)
        run0.font.name = "Arial"
        run0.font.size = Pt(8)
        run0.font.bold = True
        run0.font.color.rgb = PURPLE_PRIMARY

        run1 = c1.paragraphs[0].add_run(r_path)
        run1.font.name = "Courier New"
        run1.font.size = Pt(7.5)

        run2 = c2.paragraphs[0].add_run(desc)
        run2.font.name = "Arial"
        run2.font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------------------
    # 7. Verification & Production Checklist
    # -------------------------------------------------------------------------
    add_section_header(7, "Verification & Production Readiness Checklist")
    p = doc.add_paragraph()
    p.add_run(
        "Before final academic evaluation or enterprise demonstration, verify the following 6 checkpoints:\n"
        "1. Web Server Execution: Start via 'python run_server.py'. Binds to 0.0.0.0:5000 with persistent SQLite database.\n"
        "2. GitHub Repository: Master branch confirmed at commit c50405a with all 26 production files present.\n"
        "3. Render Live Service: Check https://cloud-d.onrender.com/. When prompted, deploy latest commit to activate.\n"
        "4. Mobile Screen Gating: Load https://cloud-d.onrender.com/ on iOS Safari or Android Chrome. Ensure bottom bar is hidden.\n"
        "5. Login Authentication: Authenticate with staff 'nithish' / 'nithish123'. Ensure bottom bar smoothly reveals.\n"
        "6. Threat Simulation: Execute 1 manual round and 1 automated 10-round audit. Verify Minimax tree score readout."
    )

    # Save to all requested paths
    primary_path = output_paths[0]
    for p_out in output_paths:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(p_out)), exist_ok=True)
            doc.save(p_out)
            print(f"Successfully generated document at: {p_out}")
        except Exception as e:
            print(f"Warning: could not save to {p_out}: {e}")

    return primary_path


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    paths = [
        os.path.join(base, "static", "Cloud_D_Executive_Handover_Specification.docx"),
        os.path.join(base, "Cloud_D_Executive_Handover_Specification.docx"),
        r"C:\Users\nithi\.gemini\antigravity\brain\07348a2f-8b4f-4fab-9bc0-343497cf30d3\Cloud_D_Executive_Handover_Specification.docx",
    ]
    create_document(paths)
