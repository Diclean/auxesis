import SwiftUI
import AuxesisShared

@main
struct AuxesisPhoneApp: App {
    @StateObject private var model = PhoneModel()
    var body: some Scene {
        WindowGroup { PhoneRoot(model: model) }
    }
}
