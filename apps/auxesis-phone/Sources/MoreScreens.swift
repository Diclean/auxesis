import SwiftUI

struct ReviewScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var isReminder: Bool { model.selectedDraft == .reminder }
    var body: some View {
        VStack(spacing: 0) {
            Capsule().fill(p.line).frame(width: 36, height: 5).padding(.top, 9).padding(.bottom, 10).accessibilityHidden(true)
            HStack {
                Button(c("cancel")) { model.screen = model.reviewOrigin }
                Spacer()
                Text(c(isReminder ? "reminder" : "replyTitle")).font(.headline).multilineTextAlignment(.center)
                Spacer()
            }.font(.subheadline).padding(.horizontal, 16)
            FixtureScroll {
                VStack(alignment: .leading, spacing: 10) {
                    Card(palette: p) {
                        Text(c(isReminder ? "reminderTo" : "to")).font(.caption).foregroundStyle(p.ink3)
                        p.line.frame(height: 1)
                        Text(c(isReminder ? "reminderBody" : "body")).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                    }
                    Fact(icon: "arrow.up.right", text: c("leaves"), palette: p, glyph: p.out)
                    Fact(icon: "checkmark.shield", text: c("stayed"), palette: p, glyph: p.local)
                    Fact(icon: "arrow.uturn.backward", text: c("cancelInfo"), palette: p)
                    if model.authFailed { Fact(icon: "lock", text: c("authFailed"), palette: p) }
                    HStack {
                        ActionButton(title: c("notNow"), palette: p) { model.screen = model.reviewOrigin }
                        Spacer()
                        ActionButton(title: c("send"), palette: p, primary: true, icon: "faceid") {
                            Task { await model.send(reason: c("authReason")) }
                        }
                    }.padding(.top, 8)
                    Text(c("faceInfo")).font(.caption2).foregroundStyle(p.ink3).frame(maxWidth: .infinity).multilineTextAlignment(.center)
                }.padding(16)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

struct WaitingScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var body: some View {
        FixtureScroll {
            VStack(alignment: .leading, spacing: 10) {
                Text(c("waiting")).font(.largeTitle.bold()).accessibilityAddTraits(.isHeader)
                Text(model.waitingCount == 2 ? c("waitingSub") : "\(model.waitingCount) · \(c("needs"))")
                    .font(.caption).foregroundStyle(p.ink3)
                if model.waiting.contains(.reminder) {
                    requestCard(.reminder, kind: .glance, name: "Mail", time: "08:13", title: "reminder", detail: "reminderSub")
                }
                if model.waiting.contains(.receipts) {
                    requestCard(.receipts, kind: .specs, name: "Documents", time: "08:05", title: "receipts", detail: "receiptsSub")
                }
                if model.waitingCount == 0 { Fact(icon: "checkmark.circle", text: c("emptyWaiting"), palette: p) }
                if let recent = model.recent {
                    SectionLabel(title: c("justAnswered"), palette: p).padding(.top, 5)
                    recentCard(recent)
                }
            }.padding(.horizontal, 14).padding(.top, 4).padding(.bottom, 20)
        }
    }
    private func requestCard(_ id: RequestID, kind: MascotKind, name: String, time: String, title: String, detail: String) -> some View {
        Card(palette: p) {
            HStack { Mascot(kind: kind, size: 18, palette: p); Text(name).font(.caption.bold()); Spacer(); Text(time).font(.caption2).foregroundStyle(p.ink3) }
            Text(c(title)).font(.subheadline.weight(.semibold))
            Text(c(detail)).font(.caption).foregroundStyle(p.ink3)
            if model.pending[id] != nil {
                Fact(icon: "hourglass", text: c("confirming"), palette: p)
            } else if id == .reminder {
                HStack {
                    ActionButton(title: c("review"), palette: p, primary: true) { model.openDraft(.reminder) }
                    ActionButton(title: c("notNow"), palette: p) { }
                }
            } else {
                HStack {
                    ForEach(model.receiptDecisions, id: \.self) { decision in
                        ActionButton(title: c(decision == .allow ? "allowOnce" : "deny"), palette: p, primary: decision == .allow) {
                            model.submit(id, decision: decision)
                        }
                    }
                }
            }
        }
    }
    private func recentCard(_ recent: RecentSend) -> some View {
        Card(palette: p) {
            HStack {
                Text(c(recent.request == .jonas ? "reply" : "reminder")).font(.subheadline.weight(.semibold))
                Spacer()
                switch recent.status {
                case .cancelling: Label(c("sending"), systemImage: "clock").font(.caption).foregroundStyle(p.ink3)
                case .final: Label(c("final"), systemImage: "checkmark.circle").font(.caption).foregroundStyle(p.ink3)
                case .cancelled: Label(c("cancelled"), systemImage: "arrow.uturn.backward").font(.caption).foregroundStyle(p.ink3)
                }
            }
            if case .cancelling = recent.status {
                TimelineView(.periodic(from: .now, by: 0.25)) { context in
                    let seconds = model.remaining(at: context.date)
                    HStack {
                        GeometryReader { proxy in
                            ZStack(alignment: .leading) {
                                Capsule().fill(p.line)
                                Capsule().fill(p.ink2).frame(width: proxy.size.width * CGFloat(seconds) / 10)
                            }
                        }.frame(height: 4).accessibilityHidden(true)
                        Text("\(seconds) s").font(.caption).foregroundStyle(p.ink3)
                        ActionButton(title: c("cancel"), palette: p) { model.cancelSend(at: context.date) }
                    }
                    .onAppear { model.updateTime(at: context.date) }
                    .onChange(of: seconds) { _, _ in model.updateTime(at: context.date) }
                }
            }
        }
    }
}

struct AwayScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var body: some View {
        FixtureScroll {
            VStack(alignment: .leading, spacing: 9) {
                Text("Auxesis").font(.largeTitle.bold()).accessibilityAddTraits(.isHeader).padding(.horizontal, 2)
                banner(icon: "wifi.slash", title: c("awayTitle"), detail: c("awayBody", model.displayName), stopped: false)
                banner(icon: "stop.fill", title: c("stopTitle"), detail: c("stopBody"), stopped: true)
                VStack(spacing: 10) {
                    Image(systemName: "lock").font(.largeTitle).foregroundStyle(p.ink3).accessibilityHidden(true)
                    Text(c("emptyTitle")).font(.headline).accessibilityAddTraits(.isHeader)
                    Text(c("emptyBody")).font(.subheadline).foregroundStyle(p.ink2).multilineTextAlignment(.center)
                }.frame(maxWidth: .infinity).padding(.horizontal, 15).padding(.vertical, 30)
                SectionLabel(title: c("lockScreen"), palette: p)
                Card(palette: p) {
                    HStack(alignment: .top, spacing: 10) {
                        Mascot(kind: .loop, size: 26, palette: p)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack { Text("Auxesis").bold(); Text(c("now")).foregroundStyle(p.ink3) }
                            Text(c("notification"))
                        }.font(.caption)
                    }
                }
            }.padding(14)
        }
    }
    private func banner(icon: String, title: String, detail: String, stopped: Bool) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(stopped ? p.bad : p.ink2).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(stopped ? p.bad : p.ink)
                Text(detail).font(.caption).foregroundStyle(p.ink2).fixedSize(horizontal: false, vertical: true)
            }
        }.frame(maxWidth: .infinity, alignment: .leading).padding(11)
            .background(stopped ? p.badBG : p.raise, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(stopped ? p.badBG : p.line))
            .accessibilityElement(children: .combine)
    }
}

struct TeamScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    @State private var draftName: String
    init(model: PhoneModel, p: PhonePalette, c: Copy) {
        self.model = model; self.p = p; self.c = c; _draftName = State(initialValue: model.displayName)
    }
    var previewName: String { draftName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Aux" : draftName }
    var body: some View {
        VStack(spacing: 0) {
            TopBar(title: c("yourTeam"), subtitle: nil, p: p, c: c) { model.screen = .chats }
            FixtureScroll {
                VStack(alignment: .leading, spacing: 10) {
                    Mascot(kind: .loop, size: 72, palette: p).frame(maxWidth: .infinity).padding(.top, 16)
                    SectionLabel(title: c("chiefName"), palette: p).padding(.top, 14)
                    HStack {
                        FixtureTextField(placeholder: c("chiefName"), text: $draftName).accessibilityLabel(c("chiefName"))
                        Text(c("default")).font(.caption).foregroundStyle(p.ink3)
                    }.padding(11).background(p.raise, in: RoundedRectangle(cornerRadius: 12))
                    Text(c("renameHint")).font(.caption).foregroundStyle(p.ink3)
                    SectionLabel(title: c("preview"), palette: p).padding(.top, 12)
                    Card(palette: p) {
                        HStack(spacing: 10) {
                            Mascot(kind: .loop, size: 30, palette: p)
                            VStack(alignment: .leading) {
                                HStack { Text(previewName).bold(); Text(c("chief")).foregroundStyle(p.ink3) }
                                Text(c("chiefSummary")).foregroundStyle(p.ink2)
                            }.font(.caption)
                        }
                    }
                    Card(palette: p) { Text(c("asked", previewName)).font(.caption).foregroundStyle(p.ink3) }
                    ActionButton(title: c("done"), palette: p, primary: true) { model.rename(draftName); model.screen = .chats }
                        .frame(maxWidth: .infinity).padding(.top, 8)
                }.padding(.horizontal, 16).padding(.bottom, 20)
            }.scrollDismissesKeyboard(.interactively)
        }
    }
}

struct NewAgentScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    @State private var name = "Ledger"
    @State private var task: String
    init(model: PhoneModel, p: PhonePalette, c: Copy) {
        self.model = model; self.p = p; self.c = c; _task = State(initialValue: c("whatValue"))
    }
    @State private var template = "blank"
    var templates: [String] { ["Mail", "calendar", "Clients", "Documents", "blank"] }
    var body: some View {
        VStack(spacing: 0) {
            Capsule().fill(p.line).frame(width: 36, height: 5).padding(.top, 9).padding(.bottom, 10).accessibilityHidden(true)
            HStack {
                Button(c("cancel")) { model.screen = .chats }
                Spacer(); Text(c("newAgent")).font(.headline); Spacer()
                Button(c("create")) { model.addAgent(name: name, task: task, template: template) }
                    .fontWeight(.semibold).disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }.font(.subheadline).padding(.horizontal, 16)
            FixtureScroll {
                VStack(alignment: .leading, spacing: 9) {
                    Mascot(kind: .sprout, size: 48, palette: p).frame(maxWidth: .infinity)
                    SectionLabel(title: c("startFrom"), palette: p)
                    FixtureScroll(axes: .horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(templates, id: \.self) { item in
                                Button { template = item } label: {
                                    Text(item == "blank" || item == "calendar" ? c(item) : item)
                                        .font(.caption).padding(.horizontal, 10).padding(.vertical, 8)
                                        .overlay(Capsule().stroke(template == item ? p.ink : p.line))
                                }.accessibilityAddTraits(template == item ? .isSelected : [])
                            }
                        }
                    }
                    SectionLabel(title: c("name"), palette: p).padding(.top, 3)
                    FixtureTextField(placeholder: c("name"), text: $name).padding(10).background(p.raise, in: RoundedRectangle(cornerRadius: 12)).accessibilityLabel(c("name"))
                    SectionLabel(title: c("what"), palette: p).padding(.top, 3)
                    FixtureTextField(placeholder: c("what"), text: $task, multiline: true).padding(10)
                        .background(p.raise, in: RoundedRectangle(cornerRadius: 12)).accessibilityLabel(c("what"))
                    SectionLabel(title: c("brain"), palette: p).padding(.top, 3)
                    Label(c("sameBrain", model.displayName), systemImage: "brain").font(.subheadline).padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading).background(p.raise, in: RoundedRectangle(cornerRadius: 12))
                    Fact(icon: "lock", text: c("access", model.displayName), palette: p).padding(.top, 4)
                    Fact(icon: "shield", text: c("agentPrivacy"), palette: p)
                }.padding(16)
            }.scrollDismissesKeyboard(.interactively)
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)

    }
}
