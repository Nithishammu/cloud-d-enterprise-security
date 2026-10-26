# Cloud-D Mobile Application (iOS & Android)

A complete, fully functional cross-platform mobile application for **Cloud-D: Autonomous Multi-Agent Threat Defense & Encrypted Cloud Storage**.

---

## 🌟 Key Capabilities Implemented

1. **Strict Authentication Gating**:
   - Until authentication is completed, **ONLY the login/registration screen is visible**.
   - The lower navigation panel (bottom bar) is **strictly unmounted and hidden**.
   - User Registration supports selecting between **Customer (Node 3 Isolated Vault)** and **Staff (Node 2 Primary Vault)**.
   - Quick one-tap autofill buttons for testing:
     - **Staff**: `nithish` / `nithish123`
     - **Customer**: `client_vault` / `customer123`

2. **User-Friendly Encrypted Cloud Storage**:
   - Browse files stored across distributed geographic shards.
   - Suggested folder shortcuts (`PS-7`, `24X501`, `PS-6`, `Documents`, `Audits`).
   - Floating Action Button (`+`) to upload new documents with AES-256-GCM AEAD encryption.
   - Optional Post-Quantum Hybrid encryption toggle (ML-KEM-768 / Kyber-768).

3. **Interactive & Automated Threat Simulation Center**:
   - **For Staff**:
     - **Top Actions**: `+ Step one round` and `Run Automated Defense`.
     - **Manual Induction**: Adversarial agent dropdown (`Credential-Bot`, `Query-Bot`, `Tamper-Bot`, `Replay-Bot`), Attack Pressure (`Normal`, `Elevated`, `Maximum`), dynamic target badge (`☁ Auth Server (Node 0)`, etc.), and `⚡ Launch Manual Attack`.
     - **Live Decision Card**: `BLOCKED • CONTAINED` status pill, 4-column metric grid (`ADVERSARIAL VECTOR`, `DEFENDER SPECIALIST`, `DEFENSE ACTION`, `UTILITY SCORE`), Minimax 2-ply game-tree analysis text box, and Cloud Protection Status footer.
     - **Decision Engine Threshold**: Quick selector buttons for utility threshold (`0.20`, `0.40`, `0.60`, `0.80`).
     - **Recent Threat Decisions Table**: Live logging of attack rounds and mitigation actions.
   - **For Customers**:
     - **Autonomous Peripheral Shield Monitor**: Real-time status of the 4 Peripheral Rings (Ingress Edge, QueryShield AST Filter, AuthWall Tenant Barrier, and Customer Vault `💎 100% SEALED`).
     - **Customer Air-Gap Guarantee**: Visual confirmation that customer data remains cryptographically sealed during red-team exercises.

4. **Lower Navigation Panel (Bottom Bar)**:
   - Mounts and becomes visible **strictly after sign-in**.
   - Tabs: 📁 `Files`, ⚡ `Simulation`, 🛡️ `Security`, 👤 `Profile`.
   - Logging out unmounts the lower panel and returns immediately to the login screen.

---

## 🚀 How to Run on iOS and Android

### Prerequisites
- Node.js (v18 or higher) installed on your machine.
- Expo CLI or Expo Go app on your physical iPhone / Android device.

### Running with Expo (Instant):

```bash
# 1. Navigate to the mobile app directory
cd mobile_app

# 2. Install dependencies
npm install

# 3. Start the Expo development server
npx expo start
```

- **On iOS**: Scan the QR code with your iPhone Camera to open the app in **Expo Go**, or press `i` in the terminal to launch the iOS Simulator (macOS / Xcode required).
- **On Android**: Scan the QR code with the **Expo Go** app on your Android phone, or press `a` in the terminal to launch the Android Emulator.
- **On Web**: Press `w` to view the mobile app directly in your desktop browser.

---

## 📦 Building Standalone Native Binaries (.ipa / .apk)

To build production-ready native binaries for the Apple App Store or Google Play Store:

```bash
# Install EAS CLI
npm install -g eas-cli

# Login to your Expo account
eas login

# Build APK for Android
eas build -p android --profile preview

# Build for iOS (Simulator or TestFlight)
eas build -p ios --profile preview
```
