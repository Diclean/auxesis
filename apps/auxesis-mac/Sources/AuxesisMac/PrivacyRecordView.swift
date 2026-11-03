import AuxesisKit
import SwiftUI

struct PrivacyRecordListView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @Binding var selection: String?
    @State private var agent = "All agents"
    @State private var day = ""

    private var receipts: [Receipt] { shell.store.receipts }
    private var visible: [Receipt] {
        PrivacyRecordListModel.filtered(receipts, agent: agent == "All agents" ? nil : agent,
                                        day: day.isEmpty ? nil : day)
    }

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Picker(copy(.colAgent), selection: $agent) {
                    Text("All agents").tag("All agents")
                    ForEach(PrivacyRecordListModel.agents(receipts), id: \.self) { Text($0).tag($0) }
                }
                .frame(maxWidth: 150)
                .accessibilityLabel(copy(.colAgent)).accessibilityIdentifier("privacy-record-agent-filter")
                TextField(L10n.ui(.privacyDayFilter, language), text: $day)
                    .textFieldStyle(.roundedBorder).frame(maxWidth: 150)
                    .accessibilityLabel(L10n.ui(.privacyDayFilter, language)).accessibilityIdentifier("privacy-record-day-filter")
            }.padding(.horizontal, 14).padding(.top, 12)
            List(selection: $selection) {
                Section("Run receipts · external hosts recorded") {
                    if visible.isEmpty {
                        Text(receipts.isEmpty ? "Request history is unavailable." : "No run receipts match these filters.")
                            .font(.meta).foregroundStyle(palette.ink2.color)
                    }
                    ForEach(visible) { receipt in
                        let host = receipt.hostsContacted.first ?? L10n.ui(.externalHostUnavailable, language)
                        let time = receipt.started ?? L10n.ui(.receiptTimeUnavailable, language)
                        Button { selection = receipt.runId } label: {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(host)
                                    .font(.ui).foregroundStyle(palette.ink.color)
                                Text("\(receipt.agent) · \(time)")
                                    .font(.meta).foregroundStyle(palette.ink2.color)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 3)
                        }
                        .buttonStyle(.plain).tag(receipt.runId)
                        .accessibilityLabel("\(receipt.agent) · \(time) · \(host)").accessibilityIdentifier("receipt-row-\(receipt.runId)")
                        .accessibilityAddTraits(selection == receipt.runId ? [.isSelected] : [])
                    }
                }
                Section(L10n.ui(.stayedOnMac, language)) {
                    Text("The receipts API does not record request-level local outcomes.")
                        .font(.meta).foregroundStyle(palette.ink2.color)
                }
            }
            .listStyle(.inset)
            .scrollContentBackground(.hidden)
            .background(palette.work.color)
            Text("A run receipt can list contacted hosts; it does not identify each provider request.")
                .font(.meta).foregroundStyle(palette.ink2.color).padding(.horizontal, 14).padding(.bottom, 10)
        }
        .background(palette.work.color)
        .onAppear { if selection == nil { selection = visible.first?.runId } }
        .onChange(of: shell.store.receipts) { _, _ in if selection == nil { selection = visible.first?.runId } }
    }
}

struct RequestInspectorView: View {
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    let receipt: Receipt?

    private var model: RequestInspectorModel? { receipt.map { RequestInspectorModel(receipt: $0) } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Run receipt").font(.title2.weight(.semibold)).foregroundStyle(palette.ink.color)
                Text("This record covers a whole run, not one request. Per-request detail is not recorded yet.")
                    .font(.meta).foregroundStyle(palette.ink2.color)
                if let receipt {
                    if receipt.receiptError {
                        Label("Record unavailable", systemImage: "questionmark.circle")
                            .font(.ui).foregroundStyle(palette.ink2.color)
                    }
                    if let model {
                        ForEach(model.visibleSections, id: \.rawValue) { section in
                            field(title(for: section), model.value(for: section))
                        }
                        Text(model.notKeptDisclosure(language: language))
                            .font(.meta).foregroundStyle(palette.ink2.color)
                    }
                } else {
                    Text("Select a run receipt to inspect the evidence it contains.")
                        .font(.ui).foregroundStyle(palette.ink2.color)
                }
            }
            .padding(.horizontal, 36).padding(.vertical, 28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(palette.work.color)
    }

    private func field(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.meta).foregroundStyle(palette.ink2.color)
            Text(value).font(.ui)
                .foregroundStyle(title == "What came back" ? palette.ink2.color : palette.ink.color)
                .textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func title(for section: RequestInspectorSection) -> String {
        switch section {
        case .sent: return "Run started"
        case .destination: return "Destination"
        case .agentAndSkill: return "Agent and skill"
        case .trigger: return "Trigger"
        case .replaced: return "Replaced"
        case .coverage: return "Coverage"
        case .exactRequest: return "Exactly what the provider received"
        case .restored: return "Restored, this Mac only"
        case .whatCameBack: return "What came back"
        case .retentionClaim: return "Provider retention claim"
        }
    }
}
