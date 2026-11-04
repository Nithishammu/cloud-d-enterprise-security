# Cloud-D Mobile UI Prototype (iOS & Android)

This Expo project is a visual prototype, not the supported mobile client. Its file and simulation screens use local mock state and do not sync with the Cloud-D database. It does not provide an installable APK or IPA.

Use the Flutter app in `mobile/` for the connected client. It shares the website API and account data, and defaults to `https://cloud-d.onrender.com`. Existing emulator-local defaults are migrated to that shared server; a custom server address remains unchanged.

The shared Render Free service uses temporary storage. Website and Flutter data can sync while the service is running, but data is not durable across service replacement or restart.
