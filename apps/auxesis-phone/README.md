# Auxesis on iPhone — fixture shell

Open `AuxesisPhone.xcodeproj` in Xcode and run the AuxesisPhone scheme on iOS 17 or later. The checked-in Xcode project was generated with `xcodegen generate` from `project.yml`, keeping the local package dependency explicit. No generator is needed to build the project.

This is a UI-only sample: Connect advances to the fixture; no discovery, pairing, networking, persistence, notifications, or real sends exist. The sample Mac confirms actions after a short delay. The Away / Stopped example is available under Since you left. The simulator uses a successful authentication stub; devices use LocalAuthentication. Agent creation and renaming only change in-memory display state. The review is intentionally read-only, so its exact content is what the sample approval describes.

Tests use a controllable clock and fake authenticator. Snapshot tests attach eight screens in both appearances and one French screen to the test result; they render SwiftUI views without driving the Simulator UI.
