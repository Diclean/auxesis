import Foundation
import LocalAuthentication
import Combine

protocol DraftAuthenticating {
    func authenticate(reason: String) async -> Bool
}

struct DeviceAuthenticator: DraftAuthenticating {
    func authenticate(reason: String) async -> Bool {
        #if targetEnvironment(simulator)
        // The simulator has no enrolled biometric identity in the fixture.
        return true
        #else
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) ?? false
        #endif
    }
}

enum Screen: String, CaseIterable { case pair, chats, chat, review, waiting, away, team, newAgent }
enum RequestID: String, CaseIterable { case reminder, receipts, jonas }
enum Decision: Hashable { case send, allow, deny }
enum SendStatus: Equatable { case cancelling(until: Date), final, cancelled }
struct RecentSend: Equatable { let request: RequestID; var status: SendStatus }
struct SampleAgent: Identifiable { let id = UUID(); let name: String; let task: String; let template: String }

@MainActor
final class PhoneModel: ObservableObject {
    @Published var screen: Screen = .pair
    @Published var chiefName = "Aux"
    @Published var words = ["harbor", "violet", "seven", "cedar", "", ""]
    @Published var waiting: Set<RequestID> = [.reminder, .receipts, .jonas]
    @Published private(set) var pending: [RequestID: Decision] = [:]
    @Published private(set) var recent: RecentSend?
    @Published var selectedDraft: RequestID = .jonas
    @Published var reviewOrigin: Screen = .chat
    @Published var authFailed = false
    @Published var agents: [SampleAgent] = []
    let chiefID = "chief"
    let chiefAccess = ["mail", "calendar", "clients", "documents"]
    let chiefHistory = ["sample-step-1", "sample-step-2"]
    let authenticator: any DraftAuthenticating
    let now: () -> Date
    let autoConfirm: Bool

    init(authenticator: any DraftAuthenticating = DeviceAuthenticator(), now: @escaping () -> Date = Date.init, autoConfirm: Bool = true) {
        self.authenticator = authenticator
        self.now = now
        self.autoConfirm = autoConfirm
    }

    var displayName: String { chiefName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Aux" : chiefName.trimmingCharacters(in: .whitespacesAndNewlines) }
    var waitingCount: Int { waiting.intersection([.reminder, .receipts]).count }
    // The phone offers a single-use decision only.
    var receiptDecisions: [Decision] { [.allow, .deny] }

    func connect() { screen = .chats }
    func openDraft(_ request: RequestID) { reviewOrigin = screen; selectedDraft = request; authFailed = false; screen = .review }
    func send(reason: String) async {
        let request = selectedDraft
        guard pending[request] == nil, waiting.contains(request) else { return }
        guard await authenticator.authenticate(reason: reason) else { authFailed = true; return }
        guard screen == .review, selectedDraft == request, waiting.contains(request), pending[request] == nil else { return }
        authFailed = false
        submit(request, decision: .send)
        screen = .waiting
    }
    func submit(_ request: RequestID, decision: Decision) {
        guard waiting.contains(request), pending[request] == nil else { return }
        pending[request] = decision
        if autoConfirm {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 700_000_000)
                self?.macConfirmed(request)
            }
        }
    }
    /// The sample Mac, and only the sample Mac, removes an open request.
    func macConfirmed(_ request: RequestID) {
        guard let decision = pending.removeValue(forKey: request) else { return }
        waiting.remove(request)
        if decision == .send {
            recent = RecentSend(request: request, status: .cancelling(until: now().addingTimeInterval(10)))
        }
    }
    func remaining(at date: Date) -> Int {
        guard case let .cancelling(until) = recent?.status else { return 0 }
        return max(0, Int(ceil(until.timeIntervalSince(date))))
    }
    func updateTime(at date: Date) {
        guard case let .cancelling(until) = recent?.status, date >= until else { return }
        recent?.status = .final
    }
    func cancelSend(at date: Date) {
        guard case let .cancelling(until) = recent?.status else { return }
        guard date < until else { updateTime(at: date); return }
        recent?.status = .cancelled
    }
    func rename(_ name: String) { chiefName = name }
    func addAgent(name: String, task: String, template: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        agents.append(SampleAgent(name: trimmed, task: task, template: template))
        screen = .chats
    }
}
