// The Documents page (M5-4): the owner's receipts from `GET /v1/docs`, which
// client each belongs to, link or unlink one, and export a period. Only the
// fields the list route returns are shown: no file name, no text, no issuer.
import Foundation

/// One row of `GET /v1/docs`.
public struct DocumentRow: Decodable, Equatable, Identifiable {
    public struct Client: Decodable, Equatable {
        public let id: Int64
        public let name: String?
        public let archived: Bool
    }
    /// The first 12 hex characters of the content hash; the link route takes it as is.
    public let hash: String
    public let kind: String?
    public let issuedOn: String?
    public let number: String?
    /// `"120.00 EUR"`: amount and currency, as auxd wrote them.
    public let total: String?
    public let client: Client?
    /// `read`, `could not be read` or `waiting for reading`.
    public let status: String
    public var id: String { hash }
    public var isRead: Bool { status == "read" }
    /// Read, but no date, number or amount came out of it (a scan with no text).
    public var hasNoDetails: Bool { isRead && issuedOn == nil && number == nil && total == nil }

    enum CodingKeys: String, CodingKey { case hash, kind, number, total, client, status, issuedOn = "issued_on" }
}

/// What the page shows: all, the ones with no client, or one client's.
public enum DocumentsFilter: Hashable {
    case all, unlinked, client(Int64)

    var query: String {
        switch self {
        case .all: return ""
        case .unlinked: return "&unlinked=true"
        case .client(let id): return "&client=\(id)"
        }
    }
}

/// `POST /v1/docs/export?from=&to=&client=&out=`, dates as `yyyy-MM-dd`.
public struct DocumentsExport: Equatable {
    public let from: String
    public let to: String
    public let client: Int64?
    public let out: String

    public init(from: Date, to: Date, client: Int64?, out: URL, calendar: Calendar = .current) {
        let day = { (date: Date) in
            let parts = calendar.dateComponents([.year, .month, .day], from: date)
            return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
        }
        self.from = day(from)
        self.to = day(to)
        self.client = client
        self.out = out.path
    }

    public var queryItems: [URLQueryItem] {
        [URLQueryItem(name: "from", value: from), URLQueryItem(name: "to", value: to)]
            + (client.map { [URLQueryItem(name: "client", value: String($0))] } ?? [])
            + [URLQueryItem(name: "out", value: out)]
    }
}

public enum DocumentsExportResult: Equatable {
    case written(folder: String, rows: Int, missing: Int)
    case empty
}

public protocol DocumentsClient: AnyObject {
    func documents(_ filter: DocumentsFilter) async throws -> [DocumentRow]
    /// `client == nil` unlinks.
    func linkDocument(hash: String, client: Int64?) async throws
    func exportDocuments(_ request: DocumentsExport) async throws -> DocumentsExportResult
    func clients() async throws -> [ClientSummary]
}

/// Why a load or an action did not work, in the page's own words.
public enum DocumentsProblem: Equatable {
    case offline, notRead, gone, exportExists, exportRefused, failed

    public init(_ error: Error) {
        guard let error = error as? AuxdError else { self = .failed; return }
        switch (error, error.apiErrorCode) {
        case (.transport, _): self = .offline
        case (.http(409, _), "docs_link_refused"): self = .notRead
        case (.http(404, _), "docs_link_refused"): self = .gone
        case (_, "docs_export_exists"): self = .exportExists
        case (_, "docs_export_refused"): self = .exportRefused
        default: self = .failed
        }
    }

    public var key: UIKey {
        switch self {
        case .offline: return .docsErrOffline
        case .notRead: return .docsErrNotRead
        case .gone: return .docsErrGone
        case .exportExists: return .docsErrExists
        case .exportRefused: return .docsErrRefused
        case .failed: return .docsErrFailed
        }
    }
}

@MainActor public final class DocumentsPageModel: ObservableObject {
    public enum Load: Equatable { case loading, loaded([DocumentRow]), failed(DocumentsProblem) }

    @Published public private(set) var load: Load = .loading
    @Published public private(set) var clients: [ClientSummary] = []
    @Published public var filter: DocumentsFilter = .all { didSet { if filter != oldValue { Task { await reload() } } } }
    /// The row whose link is being written.
    @Published public private(set) var linking: String?
    /// The last failed link or export, shown in red under the toolbar.
    @Published public private(set) var problem: DocumentsProblem?
    @Published public private(set) var exporting = false
    @Published public private(set) var exported: DocumentsExportResult?
    @Published public private(set) var selected: DocumentRow?

    private let client: DocumentsClient

    public init(client: DocumentsClient) {
        self.client = client
    }

    /// Newest first by date; an undated row keeps auxd's order after the dated ones.
    public static func sorted(_ rows: [DocumentRow]) -> [DocumentRow] {
        rows.enumerated().sorted { a, b in
            switch (a.element.issuedOn, b.element.issuedOn) {
            case let (x?, y?) where x != y: return x > y
            case (nil, _?): return false
            case (_?, nil): return true
            default: return a.offset < b.offset
            }
        }.map(\.element)
    }

    public func reload() async {
        let asked = filter
        do {
            let rows = try await client.documents(asked)
            guard asked == filter else { return }
            let sorted = Self.sorted(rows)
            if let selected, !sorted.contains(where: { $0.hash == selected.hash }) { self.selected = nil }
            load = .loaded(sorted)
        } catch {
            guard asked == filter else { return }
            load = .failed(DocumentsProblem(error))
        }
        // The picker only; a failed read leaves the last list.
        if let list = try? await client.clients() { clients = list }
    }

    public func select(_ row: DocumentRow) { selected = row }

    public func link(_ row: DocumentRow, to party: Int64?) async {
        guard linking == nil, row.client?.id != party else { return }
        linking = row.hash
        defer { linking = nil }
        do {
            try await client.linkDocument(hash: row.hash, client: party)
            problem = nil
        } catch {
            problem = DocumentsProblem(error)
        }
        await reload()
    }

    public func export(from: Date, to: Date, client party: Int64?, into folder: URL) async {
        guard !exporting else { return }
        exporting = true
        defer { exporting = false }
        do {
            exported = try await client.exportDocuments(DocumentsExport(from: min(from, to), to: max(from, to), client: party, out: folder))
            problem = nil
        } catch {
            exported = nil
            problem = DocumentsProblem(error)
        }
    }

    // MARK: Copy

    /// `"2025-09-12"` → `Sep 12, 2025` / `12 sept. 2025`; unparseable stays as
    /// written. An unread row has no date yet: empty, not a dash.
    public static func dateText(_ row: DocumentRow, language: Language) -> String {
        guard let raw = row.issuedOn else { return row.isRead && !row.hasNoDetails ? "—" : "" }
        let parse = DateFormatter()
        parse.locale = Locale(identifier: "en_US_POSIX")
        parse.timeZone = TimeZone(identifier: "UTC")
        parse.dateFormat = "yyyy-MM-dd"
        guard let date = parse.date(from: raw) else { return raw }
        return dayText(date, language: language, timeZone: TimeZone(identifier: "UTC")!)
    }

    /// One day in the page's style, for the table and the export fields alike.
    public static func dayText(_ date: Date, language: Language, timeZone: TimeZone = .current) -> String {
        let show = DateFormatter()
        show.locale = Locale(identifier: language.localeIdentifier)
        show.timeZone = timeZone
        show.dateFormat = language.dayMonthYearFormat
        return show.string(from: date)
    }

    /// `"1240.00 EUR"` → `€1,240.00` / `1 240,00 €`. A code Foundation does not
    /// know keeps the grouped number plus the code as written; no code, the
    /// number alone; anything unparseable stays as auxd wrote it.
    public static func amountText(_ row: DocumentRow, language: Language) -> String {
        guard let raw = row.total else { return row.isRead && !row.hasNoDetails ? "—" : "" }
        let parts = raw.split(separator: " ", maxSplits: 1).map(String.init)
        guard let first = parts.first, first.allSatisfy({ $0.isNumber || $0 == "." || $0 == "-" }),
              let value = Decimal(string: first, locale: Locale(identifier: "en_US_POSIX")) else { return raw }
        let code = parts.count > 1 ? parts[1] : nil
        let formatter = NumberFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        if let code, Locale.commonISOCurrencyCodes.contains(code) {
            formatter.numberStyle = .currency
            formatter.currencyCode = code
            if let text = formatter.string(from: value as NSDecimalNumber) { return text }
        }
        formatter.numberStyle = .decimal
        formatter.minimumFractionDigits = 2
        formatter.maximumFractionDigits = 2
        let number = formatter.string(from: value as NSDecimalNumber) ?? first
        return [number, code].compactMap { $0 }.joined(separator: " ")
    }

    /// "Invoice FAC-2025-0042"; an unread row says "Not read yet", a read one
    /// with nothing in it says so instead of a bare "Document".
    public static func documentText(_ row: DocumentRow, language: Language) -> String {
        switch row.status {
        case "read": break
        case "could not be read": return L10n.ui(.docsUnreadable, language)
        default: return L10n.ui(.docsWaiting, language)
        }
        if row.hasNoDetails, row.kind != "invoice", row.kind != "receipt" { return L10n.ui(.docsNoDetails, language) }
        let kind = L10n.ui(row.kind == "invoice" ? .docsKindInvoice : row.kind == "receipt" ? .docsKindReceipt : .docsKindOther, language)
        return [kind, row.number].compactMap { $0 }.joined(separator: " ")
    }

    public static func clientText(_ row: DocumentRow, language: Language) -> String {
        guard let client = row.client else { return L10n.ui(.docsNoClient, language) }
        let name = client.name ?? "#\(client.id)"
        return client.archived ? L10n.uf(.docsArchived, language, name) : name
    }

    public func exportedText(language: Language) -> String? {
        switch exported {
        case nil: return nil
        case .empty?: return L10n.ui(.docsExportEmpty, language)
        case .written(_, let rows, _)?:
            return rows == 1 ? L10n.ui(.docsExportedOne, language) : L10n.uf(.docsExportedMany, language, rows)
        }
    }
}
