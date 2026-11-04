// Clients import: the request body and the answer's decoding, the
// presenter's helpers, and the import sheet's model (preview → confirm → reload)
// against the in-memory fixture daemon. Fictional files and people only.
import Foundation
import Testing
@testable import AuxesisKit

extension ClientImportModel.Phase {
    var isPreviewed: Bool { if case .previewed = self { return true } else { return false } }
    var isImported: Bool { if case .imported = self { return true } else { return false } }
    var isFailed: Bool { if case .failed = self { return true } else { return false } }
}

@objcMembers @MainActor final class ContactsImportWireTests: XCTestCase {
    func testTheRequestIsSnakeCaseAndOmitsAnAbsentTagOrCountry() throws {
        let body = try JSONEncoder().encode(
            ContactsImportRequest(path: "/tmp/exemple-contacts.vcf", dryRun: true, tag: "client", country: nil))
        let object = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        XCTAssertEqual(object?["path"] as? String, "/tmp/exemple-contacts.vcf")
        XCTAssertEqual(object?["dry_run"] as? Bool, true)
        XCTAssertEqual(object?["tag"] as? String, "client")
        XCTAssertNil(object?["country"])
        XCTAssertNil(object?["dryRun"])
    }

    func testTheNoneTagSendsNoTagAndTheCountryIsSent() throws {
        XCTAssertNil(ContactsImportTag.none.wire)
        XCTAssertEqual(ContactsImportTag.partner.wire, "partner")
        let body = try JSONEncoder().encode(
            ContactsImportRequest(path: "/tmp/exemple.csv", dryRun: false, tag: ContactsImportTag.none.wire, country: "FR"))
        let object = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        XCTAssertNil(object?["tag"])
        XCTAssertEqual(object?["country"] as? String, "FR")
        XCTAssertEqual(object?["dry_run"] as? Bool, false)
    }

    func testAPreviewDecodesTheDaemonShape() throws {
        let json = """
        {"dry_run":true,"format":"csv",
         "mapped_columns":[{"column":"Full name","as":"name"},{"column":"Work E-mail","as":"email"}],
         "unmapped_columns":["Notes"],"contacts":2,"emails":2,"phones":1,
         "parties_created":1,"parties_updated":1,"parties_refused":0,
         "skipped":{"no_name_or_contact":0,"repeated_in_file":1,"phone_needs_country":1,"phone_invalid":0,
                    "refused_charset":0,"undecodable_fields":0,"over_size_cap":0}}
        """
        let answer = try JSONDecoder().decode(ContactsImportAnswer.self, from: Data(json.utf8))
        XCTAssertTrue(answer.dryRun)
        XCTAssertEqual(answer.format, "csv")
        XCTAssertEqual(answer.mappedColumns.map(\.role), ["name", "email"])
        XCTAssertEqual(answer.mappedColumns.first?.column, "Full name")
        XCTAssertEqual(answer.unmappedColumns, ["Notes"])
        XCTAssertEqual(answer.partiesCreated, 1)
        XCTAssertEqual(answer.skipped.phoneNeedsCountry, 1)
        XCTAssertEqual(answer.skipped.repeatedInFile, 1)
    }

    func testAnImportAnswerWithoutTheColumnsStillDecodes() throws {
        let json = #"{"dry_run":false,"contacts":3,"emails":3,"phones":0,"parties_created":3,"parties_updated":0,"parties_refused":0,"skipped":{}}"#
        let answer = try JSONDecoder().decode(ContactsImportAnswer.self, from: Data(json.utf8))
        XCTAssertFalse(answer.dryRun)
        XCTAssertNil(answer.format)
        XCTAssertEqual(answer.mappedColumns, [])
        XCTAssertEqual(answer.skipped, ContactsImportSkipped())
        XCTAssertEqual(answer.contacts, 3)
    }

    func testTheSkippedReasonsKeepOnlyTheNonZeroOnesInOrder() {
        let reasons = ContactsImportText.skippedReasons(ContactsImportSkipped(repeatedInFile: 3, phoneInvalid: 1))
        XCTAssertEqual(reasons.map { $0.0 }, [.importSkippedRepeated, .importSkippedInvalidPhone])
        XCTAssertEqual(reasons.map { $0.1 }, [3, 1])
    }

    func testTheCountryCodeIsTwoLettersUpperCased() {
        XCTAssertEqual(ContactsImportText.countryCode(" fr "), "FR")
        XCTAssertNil(ContactsImportText.countryCode("France"))
        XCTAssertNil(ContactsImportText.countryCode("F1"))
        XCTAssertNil(ContactsImportText.countryCode(""))
    }

    func testAFailureShowsTheDaemonsSentenceNotTheBody() {
        let body = #"{"error":{"code":"contacts_import_invalid","message":"path must be absolute"}}"#
        XCTAssertEqual(ContactsImportText.failure(AuxdError.http(status: 422, body: body), .en), "path must be absolute")
        XCTAssertEqual(ContactsImportText.failure(AuxdError.http(status: 500, body: "not json"), .en),
                       L10n.t(.importFailed, .en))
        XCTAssertEqual(ContactsImportText.failure(AuxdError.unauthorized, .fr), L10n.t(.importFailed, .fr))
    }

    func testTheFormatNamesAreProductNames() {
        XCTAssertEqual(ContactsImportText.format("vcard"), "vCard")
        XCTAssertEqual(ContactsImportText.format("csv"), "CSV")
        XCTAssertNil(ContactsImportText.format(nil))
    }
}

@objcMembers @MainActor final class ContactsImportSheetTests: XCTestCase {
    private let path = "/tmp/exemple-contacts.vcf"

    private func makeShell(_ daemon: FixtureDaemon) -> ShellModel {
        ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
    }

    private func loadedShell(_ daemon: FixtureDaemon) -> ShellModel {
        let shell = makeShell(daemon)
        shell.loadClients()
        _ = waitUntil { shell.clients.value != nil }
        return shell
    }

    func testPreviewThenImportReloadsTheList() {
        let daemon = FixtureDaemon()
        let shell = loadedShell(daemon)
        let before = shell.clients.value?.count ?? 0

        let model = shell.clientImport(path: path, language: .en)
        model.preview()
        XCTAssertTrue(waitUntil { model.phase == .previewed(daemon.contactsPreview) })
        XCTAssertEqual(daemon.contactsRequests.map(\.dryRun), [true])
        XCTAssertEqual(daemon.contactsRequests.first?.tag, "client")
        XCTAssertTrue(model.canImport, "a file that needs no country can be imported at once")

        model.confirm()
        XCTAssertTrue(waitUntil { model.phase.isImported })
        XCTAssertEqual(daemon.contactsRequests.map(\.dryRun), [true, false])
        XCTAssertEqual(daemon.contactsRequests.last?.path, path)
        XCTAssertNil(daemon.contactsRequests.last?.country)
        XCTAssertTrue(waitUntil { (shell.clients.value?.count ?? 0) == before + daemon.contactsPreview.partiesCreated })
    }

    func testAPhoneNeedingACountryWaitsForOneAndSendsItUpperCased() {
        let daemon = FixtureDaemon()
        daemon.contactsPreview = ContactsImportAnswer(
            dryRun: true, format: "csv", contacts: 4, emails: 4, phones: 4, partiesCreated: 4,
            skipped: ContactsImportSkipped(phoneNeedsCountry: 2)
        )
        let model = loadedShell(daemon).clientImport(path: path, language: .en)
        model.preview()
        XCTAssertTrue(waitUntil { model.phase.isPreviewed })
        XCTAssertFalse(model.canImport)

        model.country = "fr"
        XCTAssertEqual(model.countryCode, "FR")
        XCTAssertTrue(model.canImport)
        model.confirm()
        XCTAssertTrue(waitUntil { model.phase.isImported })
        XCTAssertEqual(daemon.contactsRequests.last?.country, "FR")
    }

    func testTheOwnersTagGoesOnTheImport() {
        let daemon = FixtureDaemon()
        let model = loadedShell(daemon).clientImport(path: path, language: .en)
        model.tag = .partner
        model.preview()
        XCTAssertTrue(waitUntil { model.phase.isPreviewed })
        model.confirm()
        XCTAssertTrue(waitUntil { model.phase.isImported })
        XCTAssertEqual(daemon.contactsRequests.map(\.tag), ["partner", "partner"])
    }

    func testARefusedImportKeepsThePreviewAndShowsTheDaemonsSentence() {
        let daemon = FixtureDaemon()
        let model = loadedShell(daemon).clientImport(path: path, language: .en)
        model.preview()
        XCTAssertTrue(waitUntil { model.phase.isPreviewed })

        daemon.contactsFailure = AuxdError.http(status: 422, body: #"{"error":{"code":"contacts_import_invalid","message":"tag must be \"client\", \"partner\" or null"}}"#)
        model.confirm()
        XCTAssertTrue(waitUntil { model.message != nil })
        XCTAssertEqual(model.message, #"tag must be "client", "partner" or null"#)
        XCTAssertTrue(model.phase.isPreviewed, "the preview stays, so the owner can try again")
        XCTAssertTrue(model.canImport)
    }

    func testAFailedDryRunSaysWhyAndOffersNoImport() {
        let daemon = FixtureDaemon()
        daemon.contactsFailure = AuxdError.http(status: 422, body: #"{"error":{"code":"contacts_import_invalid","message":"the file is not a vCard or CSV file"}}"#)
        let model = loadedShell(daemon).clientImport(path: path, language: .en)
        model.preview()
        XCTAssertTrue(waitUntil { model.phase.isFailed })
        XCTAssertEqual(model.message, "the file is not a vCard or CSV file")
        XCTAssertFalse(model.canImport)
        XCTAssertEqual(daemon.contactsRequests.map(\.dryRun), [true])
    }

    func testAFileWithNoReadableContactOffersNoImport() {
        let daemon = FixtureDaemon()
        daemon.contactsPreview = ContactsImportAnswer(dryRun: true, format: "vcard")
        let model = loadedShell(daemon).clientImport(path: path, language: .en)
        model.preview()
        XCTAssertTrue(waitUntil { model.phase.isPreviewed })
        XCTAssertFalse(model.canImport)
    }

    func testWithoutAContactsRouteTheSheetSaysSo() {
        let model = ClientImportModel(path: path, importer: nil, language: .en) {}
        model.preview()
        XCTAssertTrue(model.phase.isFailed)
        XCTAssertEqual(model.message, L10n.t(.importUnavailable, .en))
    }
}
