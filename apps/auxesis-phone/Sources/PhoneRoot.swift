import SwiftUI

struct PhoneRoot: View {
    @ObservedObject var model: PhoneModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.locale) private var locale
    private var p: PhonePalette { PhonePalette(scheme) }
    private var c: Copy { Copy(locale: locale) }

    var body: some View {
        ZStack(alignment: .bottom) {
            p.bg.ignoresSafeArea()
            mainContent
            if model.screen == .review || model.screen == .newAgent {
                p.ink.opacity(0.28).ignoresSafeArea().accessibilityHidden(true)
                sheetContent
                    .background(p.bg, in: UnevenRoundedRectangle(topLeadingRadius: 18, topTrailingRadius: 18))
                    .clipShape(UnevenRoundedRectangle(topLeadingRadius: 18, topTrailingRadius: 18))
                    .padding(.top, 55)
                    .accessibilityAddTraits(.isModal)
            }
        }
        .foregroundStyle(p.ink)
        .tint(p.ink)
    }

    @ViewBuilder private var mainContent: some View {
        switch model.screen {
        case .pair: PairScreen(model: model, p: p, c: c)
        case .chats, .newAgent: withTabs { ChatsScreen(model: model, p: p, c: c) }
        case .chat: ChatScreen(model: model, p: p, c: c)
        case .review:
            if model.reviewOrigin == .waiting { withTabs { WaitingScreen(model: model, p: p, c: c) } }
            else { ChatScreen(model: model, p: p, c: c) }
        case .waiting: withTabs { WaitingScreen(model: model, p: p, c: c) }
        case .away: withTabs { AwayScreen(model: model, p: p, c: c) }
        case .team: TeamScreen(model: model, p: p, c: c)
        }
    }
    private func withTabs<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: 0) {
            content().frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            Tabs(model: model, p: p, c: c)
        }
    }
    @ViewBuilder private var sheetContent: some View {
        if model.screen == .review { ReviewScreen(model: model, p: p, c: c) }
        else { NewAgentScreen(model: model, p: p, c: c) }
    }
}

struct Tabs: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            tab(.chats, "chats", "bubble.left")
            tab(.waiting, "waiting", "hourglass")
            tab(.away, "since", "clock")
        }
        .padding(.top, 8).padding(.bottom, 5)
        .background(p.bg).overlay(alignment: .top) { p.line.frame(height: 1) }
    }
    private func tab(_ screen: Screen, _ title: String, _ icon: String) -> some View {
        Button { model.screen = screen } label: {
            VStack(spacing: 4) {
                Image(systemName: icon).font(.body)
                Text(c(title)).font(.caption2).multilineTextAlignment(.center)
            }
            .fontWeight(model.screen == screen ? .semibold : .regular)
            .foregroundStyle(model.screen == screen ? p.ink : p.ink3)
            .frame(maxWidth: .infinity, minHeight: 44)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(c(title))
        .accessibilityAddTraits(model.screen == screen ? .isSelected : [])
    }
}

struct PairScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    let columns = Array(repeating: GridItem(.flexible(), spacing: 6), count: 3)
    var body: some View {
        FixtureScroll {
            VStack(spacing: 0) {
                Mascot(kind: .loop, size: 76, palette: p).padding(.top, 30)
                Text(c("pairTitle")).font(.title2.bold()).padding(.top, 14).accessibilityAddTraits(.isHeader)
                Text(c("pairBody")).font(.subheadline).foregroundStyle(p.ink3).multilineTextAlignment(.center).padding(.top, 6)
                HStack(spacing: 8) {
                    Label("Alex’s MacBook Pro", systemImage: "laptopcomputer")
                        .font(.caption).padding(7).overlay(Capsule().stroke(p.line))
                    Text(c("found")).font(.caption).foregroundStyle(p.ink3)
                }.padding(.top, 18)
                LazyVGrid(columns: columns, spacing: 6) {
                    ForEach(0..<6, id: \.self) { index in
                        FixtureTextField(placeholder: "…", text: $model.words[index])
                            .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .padding(9).background(p.raise, in: RoundedRectangle(cornerRadius: 9))
                            .overlay(RoundedRectangle(cornerRadius: 9).stroke(p.line))
                            .accessibilityLabel("\(c("word")) \(index + 1)")
                    }
                }.padding(.top, 14)
                Text(c("wordsTime")).font(.caption).foregroundStyle(p.ink3).padding(.top, 6)
                ActionButton(title: c("connect"), palette: p, primary: true) { model.connect() }
                    .frame(maxWidth: .infinity).padding(.top, 18)
                VStack(alignment: .leading, spacing: 9) {
                    Fact(icon: "checkmark.shield", text: c("pairDirect"), palette: p, glyph: p.local)
                    Fact(icon: "lock", text: c("pairPrivate"), palette: p)
                }.padding(.top, 20)
                Text(c("sample")).font(.caption2).foregroundStyle(p.ink3).padding(.top, 16)
            }.padding(.horizontal, 22).padding(.bottom, 20)
        }.scrollDismissesKeyboard(.interactively)
    }
}

struct ChatsScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var body: some View {
        FixtureScroll {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("Auxesis").font(.largeTitle.bold()).accessibilityAddTraits(.isHeader)
                    Spacer()
                    Button { model.screen = .team } label: { Image(systemName: "person.2").frame(width: 44, height: 44) }
                        .accessibilityLabel(c("yourTeam"))
                }.padding(.horizontal, 16)
                Label(c("connected"), systemImage: "laptopcomputer").font(.caption).foregroundStyle(p.ink3).padding(.horizontal, 16).padding(.bottom, 10)
                Button { model.screen = .chat } label: {
                    agentRow(name: model.displayName, role: c("chief"), summary: c("chiefSummary"), time: "08:13", kind: .loop)
                        .background(p.soft)
                }.buttonStyle(.plain)
                SectionLabel(title: c("team"), palette: p).padding(.horizontal, 16).padding(.top, 13).padding(.bottom, 4)
                agentRow(name: "Mail", role: c("mailRole"), summary: c("mailSummary"), time: "08:01", kind: .glance, needs: true)
                agentRow(name: c("calendar"), role: c("calendarRole"), summary: c("calendarSummary"), time: "08:00", kind: .hook)
                agentRow(name: "Clients", role: c("clientsRole"), summary: c("clientsSummary"), time: c("now"), kind: .twin)
                agentRow(name: "Documents", role: c("documentsRole"), summary: c("documentsSummary"), time: c("now"), kind: .specs)
                agentRow(name: "Ledger", role: c("ledgerRole"), summary: c("ledgerSummary"), time: c("fri"), kind: .sprout)
                ForEach(model.agents) { agent in
                    agentRow(name: agent.name, role: c("agentCreated"), summary: agent.task, time: c("now"), kind: .sprout)
                }
                Button { model.screen = .newAgent } label: {
                    HStack(spacing: 11) {
                        Image(systemName: "plus.circle").font(.title2).frame(width: 30)
                        Text(c("newAgent")).font(.subheadline.weight(.semibold))
                    }.frame(maxWidth: .infinity, minHeight: 48, alignment: .leading).padding(.horizontal, 16)
                }.buttonStyle(.plain)
            }
        }
    }
    private func agentRow(name: String, role: String, summary: String, time: String, kind: MascotKind, needs: Bool = false) -> some View {
        HStack(alignment: .center, spacing: 11) {
            Mascot(kind: kind, size: 30, palette: p)
            VStack(alignment: .leading, spacing: 2) {
                HStack { Text(name).font(.subheadline.weight(.semibold)); Text(role).font(.caption).foregroundStyle(p.ink3) }
                Text(summary).font(.caption).foregroundStyle(p.ink2).fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .trailing, spacing: 4) {
                Text(time).font(.caption2).foregroundStyle(p.ink3)
                if needs { NeedsBadge(text: c("needs"), palette: p) }
            }
        }.padding(.horizontal, 16).padding(.vertical, 9).frame(minHeight: 56)
            .accessibilityElement(children: .combine)
    }
}

struct TopBar: View {
    let title: String; let subtitle: String?; let p: PhonePalette; let c: Copy
    var mascot = false
    var back: () -> Void
    var body: some View {
        HStack(spacing: 9) {
            Button(action: back) { Image(systemName: "chevron.left").frame(width: 30, height: 44) }.accessibilityLabel(c("back"))
            if mascot { Mascot(kind: .loop, size: 30, palette: p) }
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.headline).accessibilityAddTraits(.isHeader)
                if let subtitle { Text(subtitle).font(.caption2).foregroundStyle(p.ink3) }
            }
            Spacer()
            if mascot { Label(c("private"), systemImage: "shield").font(.caption2).padding(7).overlay(Capsule().stroke(p.line)) }
        }.padding(.horizontal, 12).overlay(alignment: .bottom) { p.line.frame(height: 1) }
    }
}

struct ChatScreen: View {
    @ObservedObject var model: PhoneModel
    let p: PhonePalette; let c: Copy
    var body: some View {
        VStack(spacing: 0) {
            TopBar(title: model.displayName, subtitle: c("working"), p: p, c: c, mascot: true) { model.screen = .chats }
            FixtureScroll {
                VStack(alignment: .leading, spacing: 10) {
                    Text(c("today")).font(.caption2).foregroundStyle(p.ink3).frame(maxWidth: .infinity)
                    HStack { Spacer(); Text(c("question")).padding(11).foregroundStyle(p.onInk).background(p.ink, in: RoundedRectangle(cornerRadius: 18)) }
                    Text(c("answer")).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                    Card(palette: p) {
                        ViewThatFits {
                            HStack { Text(c("steps")).fontWeight(.semibold); Spacer(); Text(c("stepSummary")).foregroundStyle(p.ink3) }
                            VStack(alignment: .leading) { Text(c("steps")).fontWeight(.semibold); Text(c("stepSummary")).foregroundStyle(p.ink3) }
                        }.font(.caption)
                        step("step1", local: true); step("step2", local: true); step("step3", local: false)
                    }
                    if model.waiting.contains(.jonas) {
                        Card(palette: p) {
                            HStack(alignment: .top) {
                                HStack(spacing: 4) { Mascot(kind: .glance, size: 18, palette: p); Text("Mail").bold(); Text(c("drafted")).foregroundStyle(p.ink3) }
                                Spacer(minLength: 2)
                                NeedsBadge(text: c("needs"), palette: p)
                            }.font(.caption)
                            Text(c("draftTitle")).font(.subheadline.weight(.semibold))
                            Text(c("slots")).font(.caption).foregroundStyle(p.ink3)
                            if model.pending[.jonas] != nil { Fact(icon: "hourglass", text: c("confirming"), palette: p) }
                            else {
                                HStack { ActionButton(title: c("review"), palette: p, primary: true) { model.openDraft(.jonas) }
                                    ActionButton(title: c("notNow"), palette: p) { model.screen = .chats } }
                            }
                        }
                    }
                }.padding(14)
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack { Text(c("message", model.displayName)); Spacer(); Image(systemName: "arrow.up.circle.fill") }
                    .font(.subheadline).foregroundStyle(p.ink3).padding(10).background(p.raise, in: Capsule())
                    .accessibilityLabel(c("message", model.displayName))
                Fact(icon: "shield", text: c("hint", model.displayName), palette: p)
            }.padding(12).overlay(alignment: .top) { p.line.frame(height: 1) }
        }
    }
    private func step(_ key: String, local: Bool) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "checkmark").accessibilityHidden(true)
            Text(c(key)).frame(maxWidth: .infinity, alignment: .leading)
            Label(local ? c("mac") : c("left"), systemImage: local ? "checkmark.shield" : "arrow.up.right")
                .labelStyle(TinyGlyphStyle(color: local ? p.local : p.out))
        }.font(.caption).padding(.top, 5).overlay(alignment: .top) { p.line.frame(height: 1) }
    }
}

struct TinyGlyphStyle: LabelStyle {
    let color: Color
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 3) { configuration.icon.foregroundStyle(color); configuration.title }
    }
}
