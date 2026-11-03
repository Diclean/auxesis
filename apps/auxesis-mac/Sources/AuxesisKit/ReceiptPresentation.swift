// Run receipts, in plain words.
//
// The receipt read rides the existing `AuxdTransport` protocol (additive over
// the older surface): a service without `/v1/receipts` answers 404 and the
// snapshot degrades to an empty list instead of failing.
//
// Everything here is pure (no SwiftUI, no network), so `swift test` covers the
// French copy, the cost rules and the one-line summary without a window.
import Foundation

// MARK: - Status words

/// The status words the Activity list and the thread row show. `done_unverified`
/// keeps the word "terminé": the missing verification is said on the cost line,
/// never hidden behind a different status.
public enum ReceiptStatusCopy {
    public static func label(_ status: ReceiptStatus, _ language: Language) -> String {
        switch status {
        case .done, .doneUnverified:
            return L10n.t(.receiptStatusDone, language)
        case .pausedNeedsYou:
            return L10n.t(.receiptStatusPausedNeedsYou, language)
        case .stoppedBudget:
            return L10n.t(.receiptStatusInterrupted, language)
        case .failed:
            return L10n.t(.receiptStatusFailed, language)
        case .unknown:
            return L10n.t(.receiptStatusUnknown, language)
        }
    }

    /// A short colour hint for the row agent (not a user-visible word).
    public static func isProblem(_ status: ReceiptStatus) -> Bool {
        switch status {
        case .failed, .pausedNeedsYou, .stoppedBudget: return true
        case .done, .doneUnverified, .unknown: return false
        }
    }
}

// MARK: - Cost

/// How the cost of one receipt can honestly be told.
public enum ReceiptCostState: Equatable {
    /// A verified amount, in whole cents of the owner's AI service.
    case known(cents: UInt64)
    /// No amount was recorded and nothing says it failed: unknown, never "0".
    case unknown
    /// The service could not confirm the spend (`could_not_verify`).
    case unverified
    /// The receipt itself could not be written (`receipt_error`).
    case incomplete

    public static func of(_ receipt: Receipt) -> ReceiptCostState {
        if receipt.receiptError { return .incomplete }
        if receipt.status == .doneUnverified || !receipt.couldNotVerify.isEmpty {
            return .unverified
        }
        if receipt.costCents == 0, receipt.tokensIn == 0, receipt.tokensOut == 0 {
            return .unknown
        }
        return .known(cents: receipt.costCents)
    }
}

/// The one cost line. A displayed cost always names who is paid
/// (« (ton service) »); an unknown cost never invents a cent amount.
public enum ReceiptCostCopy {
    public static func label(_ state: ReceiptCostState, _ language: Language) -> String {
        switch state {
        case .known(let cents):
            let amount = "\(grouped(cents)) ¢"
            return L10n.f(.receiptCostKnown, language, amount)
        case .unknown:
            return L10n.t(.receiptCostUnknown, language)
        case .unverified:
            return L10n.t(.receiptCostUnverified, language)
        case .incomplete:
            return L10n.t(.receiptCostIncomplete, language)
        }
    }

    /// True only when a real amount is shown (tests pin "never cents when unknown").
    public static func showsCents(_ state: ReceiptCostState) -> Bool {
        if case .known = state { return true }
        return false
    }

    /// French thousands separators (thin space), plain digits elsewhere.
    static func grouped(_ value: UInt64) -> String {
        let formatter = NumberFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 0
        formatter.groupingSeparator = " "
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }
}

// MARK: - When

/// The date and time of a run, for the receipt row and the detail popover.
///
/// The service writes `started`/`finished` as `yyyy-MM-dd HH:mm:ss` on one
/// local clock. We read and render them in UTC so the wall time shown is the
/// one the run recorded (never a shifted hour). A missing or unparseable stamp
/// shows nothing — never a fabricated time.
public enum ReceiptTime {
    public static func label(_ receipt: Receipt, _ language: Language) -> String {
        guard let stamp = receipt.started ?? receipt.finished else { return "" }
        return label(fromStamp: stamp, language)
    }

    public static func label(fromStamp stamp: String, _ language: Language) -> String {
        guard let date = parse(stamp) else { return "" }
        let day = dayFormatter(language).string(from: date)
        let time = timeFormatter().string(from: date)
        return L10n.f(.receiptWhenAt, language, day, time)
    }

    static func parse(_ stamp: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.date(from: stamp)
    }

    static func dayFormatter(_ language: Language) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = language.dayMonthYearFormat
        return formatter
    }

    static func timeFormatter() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "HH:mm"
        return formatter
    }
}

// MARK: - One-line summary

/// The single line under a finished run:
/// « 12 s · 3 fichiers lus · 1 ¢ (ton service) ».
public enum ReceiptSummary {
    public static func line(_ receipt: Receipt, _ language: Language) -> String {
        var parts: [String] = []
        switch receipt.status {
        case .done, .doneUnverified:
            break
        case .pausedNeedsYou, .stoppedBudget, .failed, .unknown:
            parts.append(ReceiptStatusCopy.label(receipt.status, language))
        }
        if let seconds = durationSeconds(receipt) {
            parts.append(durationLabel(seconds, language))
        }
        if !receipt.filesTouched.isEmpty {
            parts.append(counted(
                receipt.filesTouched.count,
                one: L10n.t(.receiptFileReadOne, language),
                many: L10n.t(.receiptFileReadMany, language)
            ))
        }
        if !receipt.hostsContacted.isEmpty {
            parts.append(counted(
                receipt.hostsContacted.count,
                one: L10n.t(.receiptSiteVisitedOne, language),
                many: L10n.t(.receiptSiteVisitedMany, language)
            ))
        }
        if !receipt.messagesSent.isEmpty {
            parts.append(counted(
                receipt.messagesSent.count,
                one: L10n.t(.receiptMessageSentOne, language),
                many: L10n.t(.receiptMessageSentMany, language)
            ))
        }
        parts.append(ReceiptCostCopy.label(ReceiptCostState.of(receipt), language))
        return parts.joined(separator: " · ")
    }

    /// Whole seconds between `started` and `finished`, or `nil` when either is
    /// missing/unparseable (never a fabricated duration). Both stamps come from
    /// the same local clock, so the difference is zone-independent.
    public static func durationSeconds(_ receipt: Receipt) -> Int? {
        guard let started = receipt.started, let finished = receipt.finished else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        guard let start = formatter.date(from: started), let end = formatter.date(from: finished) else { return nil }
        let seconds = Int(end.timeIntervalSince(start).rounded())
        return seconds >= 0 ? seconds : nil
    }

    static func durationLabel(_ seconds: Int, _ language: Language) -> String {
        if seconds < 60 { return "\(seconds) s" }
        let minutes = seconds / 60
        let rest = seconds % 60
        return rest == 0 ? "\(minutes) min" : "\(minutes) min \(rest) s"
    }

    static func counted(_ count: Int, one: String, many: String) -> String {
        "\(count) \(count == 1 ? one : many)"
    }
}

// MARK: - Detail (popover)

/// The four sections of a receipt, as bullet lines.
public struct ReceiptDetail: Equatable {
    public let effects: [String]
    public let cost: [String]
    public let proof: [String]
    public let decisions: [String]

    public init(effects: [String], cost: [String], proof: [String], decisions: [String]) {
        self.effects = effects
        self.cost = cost
        self.proof = proof
        self.decisions = decisions
    }
}

public enum ReceiptDetailCopy {
    public static func detail(for receipt: Receipt, _ language: Language) -> ReceiptDetail {
        ReceiptDetail(
            effects: effects(receipt, language),
            cost: cost(receipt, language),
            proof: proof(receipt, language),
            decisions: decisions(receipt, language)
        )
    }

    // Effets
    static func effects(_ receipt: Receipt, _ language: Language) -> [String] {
        var lines: [String] = []
        if !receipt.filesTouched.isEmpty {
            let label = L10n.t(
                receipt.filesTouched.count == 1 ? .receiptFileReadTitleOne : .receiptFileReadTitleMany,
                language
            )
            lines.append("\(label) : \(list(receipt.filesTouched))")
        }
        if !receipt.hostsContacted.isEmpty {
            let label = L10n.t(
                receipt.hostsContacted.count == 1 ? .receiptSiteVisitedTitleOne : .receiptSiteVisitedTitleMany,
                language
            )
            lines.append("\(label) : \(list(receipt.hostsContacted))")
        }
        if !receipt.messagesSent.isEmpty {
            let label = L10n.t(
                receipt.messagesSent.count == 1 ? .receiptMessageSentTitleOne : .receiptMessageSentTitleMany,
                language
            )
            lines.append("\(label) : \(list(receipt.messagesSent))")
        }
        if !receipt.tools.isEmpty {
            let tools = receipt.tools
                .sorted { $0.key < $1.key }
                .map { "\(friendlyTool($0.key, language)) ×\($0.value)" }
            lines.append("\(L10n.t(.receiptToolsUsed, language)) : \(tools.joined(separator: ", "))")
        }
        if lines.isEmpty {
            lines.append(L10n.t(.receiptNoEffect, language))
        }
        return lines
    }

    // Coût
    static func cost(_ receipt: Receipt, _ language: Language) -> [String] {
        var lines = [ReceiptCostCopy.label(ReceiptCostState.of(receipt), language)]
        if receipt.tokensIn > 0 || receipt.tokensOut > 0 {
            lines.append(L10n.f(
                .receiptTextUnits,
                language,
                ReceiptCostCopy.grouped(receipt.tokensIn),
                ReceiptCostCopy.grouped(receipt.tokensOut)
            ))
        }
        lines.append(L10n.t(.receiptPayYourService, language))
        return lines
    }

    // Preuve
    static func proof(_ receipt: Receipt, _ language: Language) -> [String] {
        var lines: [String] = []
        if receipt.receiptError {
            lines.append(L10n.t(.receiptIncompleteNote, language))
        }
        for reason in receipt.couldNotVerify {
            lines.append(L10n.f(.receiptToVerify, language, reason))
        }
        if receipt.tainted {
            lines.append(L10n.t(.receiptUntrustedSource, language))
        }
        if lines.isEmpty {
            lines.append(L10n.t(.receiptNoReservation, language))
        }
        return lines
    }

    // Décisions
    static func decisions(_ receipt: Receipt, _ language: Language) -> [String] {
        var lines: [String] = []
        for tool in receipt.approvalsAsked {
            lines.append(L10n.f(.receiptApprovalAsked, language, friendlyTool(tool, language)))
        }
        for answer in receipt.approvalsAnswered {
            lines.append(L10n.f(.receiptYourAnswer, language, friendlyAnswer(answer, language)))
        }
        if receipt.status == .pausedNeedsYou, lines.isEmpty {
            lines.append(L10n.t(.receiptWaitingAnswer, language))
        }
        if lines.isEmpty {
            lines.append(L10n.t(.receiptNoApproval, language))
        }
        return lines
    }

    // MARK: Friendly labels (known tool ids map to plain words)

    public static func friendlyTool(_ raw: String, _ language: Language) -> String {
        knownToolLabel(raw, language) ?? unknownToolLabel(raw, language)
    }

    /// True only when `friendlyTool` would show a plain, known label. The card
    /// refuses "Always" for everything else: it cannot save a rule for a tool it
    /// does not know, and an unknown id must never look like a known one.
    public static func isKnownTool(_ raw: String) -> Bool {
        knownToolLabel(raw, .fr) != nil
    }

    /// True only for an id this build does not know **and** whose scalar count
    /// exceeds `ServerText.Limits.unknownTool`. The card then shows only the
    /// first 200 scalars plus `… (N caractères)`, so two distinct ids can render
    /// identically; such an ask may never be allowed, not even once. Known ids
    /// and unknown ids of `Limits.unknownTool` scalars or fewer are unaffected.
    public static func isUnknownToolOverLong(_ raw: String) -> Bool {
        !isKnownTool(raw) && raw.unicodeScalars.count > ServerText.Limits.unknownTool
    }

    /// True when `raw` belongs to the **command** category whatever its spelling:
    /// `shell`, `shell.exec`, `run_command`, `run`, `bash`, `exec`, in any case.
    /// "Always" must be refused for the whole class, not only for the raw names
    /// that happen to start with `shell`; the gate is driven by the label the
    /// card shows, so an alias can never slip past it.
    public static func isCommandTool(_ raw: String) -> Bool {
        guard let label = knownToolLabel(raw, .fr) else { return false }
        return label == commandLabel(.fr)
    }

    /// The plain label for the command category, whatever the raw spelling. The
    /// single source shared by `knownToolLabel` and `isCommandTool`, so the gate
    /// can never drift from what the card renders.
    private static func commandLabel(_ language: Language) -> String {
        L10n.t(.toolRunCommand, language)
    }

    /// The plain label for a tool id this build knows, or `nil` when it does not.
    /// The single source of truth for both `friendlyTool` and `isKnownTool`, so
    /// the label the card shows and the "Always" gate can never disagree.
    private static func knownToolLabel(_ raw: String, _ language: Language) -> String? {
        switch raw.lowercased() {
        case "read_file", "read", "readfile", "file_read", "read_text_file":
            return L10n.t(.toolReadFile, language)
        case "write_file", "write", "writefile", "file_write", "edit_file", "apply_patch":
            return L10n.t(.toolWriteFile, language)
        case "web_search", "search", "search_web", "browse", "browser":
            return L10n.t(.toolWebSearch, language)
        case "fetch", "web_fetch":
            return L10n.t(.toolReadPage, language)
        case "open_url":
            return L10n.t(.toolOpenLink, language)
        case "shell", "shell.exec", "run_command", "run", "bash", "exec":
            return commandLabel(language)
        case "mail.send", "send_email", "email", "send_mail", "mail":
            return L10n.t(.toolSendEmail, language)
        case "calendar", "calendar.create", "calendar_update", "create_event":
            return L10n.t(.toolCalendar, language)
        case "memory", "memory.write", "remember", "memory_write":
            return L10n.t(.toolMemory, language)
        default:
            return nil
        }
    }

    /// Label for a tool the app does not know by name. The generic phrase alone
    /// is not enough: two different unknown ids must never render identically on
    /// the approval card (a decision depends on telling them apart). So the id
    /// is spelled out inside the card's quote, with **every** scalar outside
    /// printable ASCII escaped (`\u{200B}`, an accent, a combining mark, a plain
    /// or non-breaking space) rather than shown raw — a width-less combining mark
    /// or an all-space id would otherwise make two distinct ids look the same.
    /// Known ids keep their plain label and never
    /// reach this path. The bound is in Unicode scalars; past
    /// `Limits.unknownTool` scalars the first ones are shown followed by
    /// `… (N caractères)`, N being the raw scalar count.
    public static func unknownToolLabel(_ raw: String, _ language: Language) -> String {
        let word = L10n.t(.toolUnknownWord, language)
        guard !raw.isEmpty else { return word }
        let limit = ServerText.Limits.unknownTool
        let total = raw.unicodeScalars.count
        var body = ServerText.escapedStrict(raw, maxLength: limit)
        if total > limit {
            let unit = L10n.t(.toolCharacters, language)
            body += " \(ServerText.truncationMarker) (\(total) \(unit))"
        }
        // The body is already escaped and bounded above, so `quoted` only adds
        // the local delimiters (and demotes any guillemets the id smuggled in).
        return "\(word) \(ServerText.quoted(body, maxLength: Int.max))"
    }

    public static func friendlyAnswer(_ raw: String, _ language: Language) -> String {
        switch raw.lowercased() {
        case "allow", "allowed", "allow_once", "once":
            return L10n.t(.answerAllowedOnce, language)
        case "allow_always", "allowed_always", "always":
            return L10n.t(.answerAlwaysAllowed, language)
        case "deny", "denied", "refuse", "refused":
            return L10n.t(.answerDenied, language)
        case "edit", "edited":
            return L10n.t(.answerEdited, language)
        case "expired", "timeout", "timed_out":
            return L10n.t(.answerExpired, language)
        default:
            return L10n.t(.answerRecorded, language)
        }
    }

    /// At most five items, then "…" — bounded, never a wall of text.
    static func list(_ items: [String]) -> String {
        let shown = items.prefix(5)
        let suffix = items.count > shown.count ? " …" : ""
        return shown.joined(separator: ", ") + suffix
    }
}
