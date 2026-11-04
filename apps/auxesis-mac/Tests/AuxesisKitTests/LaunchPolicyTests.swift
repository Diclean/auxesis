// Whether the app may pull the focus to itself.
//
// The owner's own app comes to the front: that is what an app is for. A
// sandbox instance is a different thing: it runs on the owner's Mac while the
// owner works (a UI driver can drive it with the Accessibility API), and
// it must never take the focus away from whatever the owner is doing. So in
// a sandbox the app opens its window and works, without ever activating
// itself; the owner's own sandbox dev script brings the app forward itself.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class LaunchPolicyTests: XCTestCase {
    func testASandboxInstanceNeverActivatesItself() {
        XCTAssertFalse(LaunchPolicy.shouldActivate(env: ["AUXESIS_SANDBOX": "1"]))
        XCTAssertFalse(LaunchPolicy.shouldActivate(env: ["AUXESIS_SANDBOX": "1", "AUXESIS_MAC_BACKGROUND": "1"]))
    }

    func testTheOwnersAppIsUnchanged() {
        XCTAssertTrue(LaunchPolicy.shouldActivate(env: [:]))
        XCTAssertTrue(LaunchPolicy.shouldActivate(env: ["AUXESIS_SANDBOX": "0"]))
        XCTAssertTrue(LaunchPolicy.shouldActivate(env: ["HOME": "/Users/someone"]))
    }

    func testTheBackgroundSwitchStopsTheActivationOnItsOwn() {
        XCTAssertFalse(LaunchPolicy.shouldActivate(env: ["AUXESIS_MAC_BACKGROUND": "1"]))
    }

    // `open -g -j` launches the app hidden and inactive; no activation then.
    func testHiddenAndBackgroundLaunchesAreTold() {
        XCTAssertTrue(LaunchPolicy.launchedInBackground(isHidden: true, isActive: false, inBundle: true), "open -g -j")
        XCTAssertTrue(LaunchPolicy.launchedInBackground(isHidden: false, isActive: false, inBundle: true), "open -g")
        XCTAssertFalse(LaunchPolicy.launchedInBackground(isHidden: false, isActive: true, inBundle: true), "a double click")
        XCTAssertFalse(LaunchPolicy.launchedInBackground(isHidden: false, isActive: false, inBundle: false), "a bare binary is never active")
    }

    func testABackgroundLaunchNeverActivates() {
        XCTAssertFalse(LaunchPolicy.shouldActivateAtLaunch(env: [:], arguments: ["AuxesisMac"], inBackground: true))
    }

    func testTheBackgroundArgumentNeverActivates() {
        XCTAssertFalse(LaunchPolicy.shouldActivateAtLaunch(env: [:], arguments: ["AuxesisMac", "--background"], inBackground: false))
    }

    func testAnOrdinaryLaunchStillActivates() {
        XCTAssertTrue(LaunchPolicy.shouldActivateAtLaunch(env: [:], arguments: ["AuxesisMac"], inBackground: false))
    }

    func testTheSandboxStillNeverActivatesAtLaunch() {
        XCTAssertFalse(LaunchPolicy.shouldActivateAtLaunch(env: ["AUXESIS_SANDBOX": "1"], arguments: [], inBackground: false))
    }

    func testAClickOnTheDockIconStillActivates() {
        // The launch is held back, never a person's own request.
        XCTAssertTrue(LaunchPolicy.shouldActivate(env: [:]))
    }
}
