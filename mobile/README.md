# Cloud-D mobile client

This Flutter app is a separate iOS/Android interface for the same Cloud-D account and API used by the website. It does not keep a second copy of cloud files or reports on the phone. Sign-in, folders, file versions, starred/trash state, simulation runs, and reports are read from and written to the configured Cloud-D server.

## Run on a simulator

Install Flutter and the platform tools, then run from this directory:

```sh
flutter pub get
flutter run
```

The starting server URL is `https://cloud-d.onrender.com`, the same API used by the website. Change **Cloud-D server** on the sign-in screen to use another host. For local development, an Android emulator can use `http://10.0.2.2:8765`, an iOS simulator can use `http://127.0.0.1:8765`, and a physical phone can use the computer's LAN address. Both clients must use the same server to see the same files and reports.

## Shared data and sync

Cloud-D uses the Python service as the source of truth. The mobile app refreshes after edits, syncs every 12 seconds while open, and refreshes when it returns to the foreground. The website polls the same API every 6 seconds. The app stores the session cookie in iOS Keychain or Android encrypted preferences; file contents, folder state, and reports stay on the server.

For local testing on a physical phone, run the Python server on a LAN-reachable interface and configure the phone with the computer's LAN address. HTTP is only for local development; use HTTPS for a hosted server. Use a strong `CLOUD_D_STAFF_REGISTRATION_CODE` when binding beyond loopback.

The app implements login and account creation, customer/staff role routing, optional profile photos, folder creation, file upload/download, version history, duplicate update/replace choices, My Drive/Recent/Starred/Trash views, security overview, attacker selection with automatic defenders, simulation rounds/intensity/threshold, event stream, and saved report summaries.

## Current hosting caveat

The hosted Render service is active and shared by the website and this mobile client. Its Free plan uses temporary storage, so accounts, files, and encryption keys can be lost when the service restarts or is replaced. Shared access is working, but durable cross-device storage and reliable backups are not guaranteed until the backend uses persistent storage and a stable encryption key.
