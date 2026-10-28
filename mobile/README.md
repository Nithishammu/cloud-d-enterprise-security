# Cloud-D mobile client

This Flutter app is a separate iOS/Android interface for the same Cloud-D account and API used by the website. It does not keep a second copy of cloud files or reports on the phone. Sign-in, folders, file versions, starred/trash state, simulation runs, and reports are read from and written to the configured Cloud-D server.

## Run on a simulator

Install Flutter and the platform tools, then run from this directory:

```sh
flutter pub get
flutter run
```

The starting server URL is `http://10.0.2.2:8765` for an Android emulator and `http://127.0.0.1:8765` for an iOS simulator. Change **Cloud-D server** on the sign-in screen to use another host. On a physical phone, use a server address the phone can reach; both the mobile app and website must use the same address for changes to appear in both.

## Shared data and sync

Cloud-D uses the Python service as the source of truth. The mobile app refreshes after edits, syncs every 12 seconds while open, and refreshes when it returns to the foreground. The website polls the same API every 6 seconds. The app stores the session cookie in iOS Keychain or Android encrypted preferences; file contents, folder state, and reports stay on the server.

For local testing on a physical phone, run the Python server on a LAN-reachable interface and configure the phone with the computer's LAN address. HTTP is only for local development; use HTTPS for a hosted server. Use a strong `CLOUD_D_STAFF_REGISTRATION_CODE` when binding beyond loopback.

The app implements login and account creation, customer/staff role routing, optional profile photos, folder creation, file upload/download, version history, duplicate update/replace choices, My Drive/Recent/Starred/Trash views, security overview, attacker selection with automatic defenders, simulation rounds/intensity/threshold, event stream, and saved report summaries.

## Current hosting caveat

The existing Render URL returned a suspended-service page during development. Set the server URL to an active Cloud-D service before using the app across devices. Render's current Free web service plan cannot use persistent disks and loses local SQLite files when restarted or spun down. For durable shared SQLite storage, use a paid service with a persistent disk and a stable `CLOUD_D_ENCRYPTION_KEY`, or migrate the backend to a managed database before production use.
