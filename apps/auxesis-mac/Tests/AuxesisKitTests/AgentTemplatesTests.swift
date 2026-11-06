// The "Add an agent" sheet's model: it lists the templates, keeps the ones
// that exist out of reach, creates the picked one and refreshes the list,
// and says `grant_exceeds_chief` in plain words (EN + FR).
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class AgentTemplatesTests: XCTestCase {
    final class FakeTemplates: AgentTemplateClient {
        var list: [AgentTemplate] = []
        var createError: Error?
        private(set) var created: [String] = []
        func agentTemplates() async throws -> [AgentTemplate] { list }
        func createAgent(template: String) async throws {
            if let createError { throw createError }
            created.append(template)
        }
    }

    private let mailGrants = AgentGrants(
        see: [.init(scope: "mail", via: "IMAP (local)", level: "read")],
        canDo: [.init(skill: "mail.read", level: "auto"), .init(skill: "mail.draft", level: "auto"),
                .init(skill: "mail.send", level: "ask"), .init(skill: "calendar.read", level: "off")],
        never: ["documents"], egressNote: "")

    private func fake(mailCreated: Bool = false) -> FakeTemplates {
        let fake = FakeTemplates()
        let none = AgentGrants(see: [], canDo: [], never: [], egressNote: "")
        fake.list = [AgentTemplate(id: "mail", name: "Mail", grants: mailGrants, created: mailCreated),
                     AgentTemplate(id: "calendar", name: "Calendar", grants: none, created: false)]
        return fake
    }

    func testTheTemplatesDecodeFromTheDaemonShape() throws {
        let json = #"{"templates":[{"id":"mail","name":"Mail","glyph":"envelope","grants":{"see":[{"scope":"mail","via":"IMAP (local)","level":"read"}],"do":[{"skill":"mail.send","level":"ask"}],"never":["documents"],"egress_note":"Mail reads the mailbox on this Mac."},"created":true}]}"#
        struct List: Decodable { let templates: [AgentTemplate] }
        let list = try JSONDecoder().decode(List.self, from: Data(json.utf8)).templates
        XCTAssertEqual(list.map(\.id), ["mail"])
        XCTAssertTrue(list[0].created)
        XCTAssertEqual(list[0].grants.canDo.map(\.skill), ["mail.send"])
    }

    func testTheSheetListsTheTemplatesWithWhatEachDoesInPlainWords() async {
        let model = AgentTemplatesModel(client: fake(), language: .en)
        await model.load()
        XCTAssertEqual(model.templates.map(\.id), ["mail", "calendar"])
        XCTAssertEqual(model.selected, "mail")
        XCTAssertEqual(AgentTemplatesModel.about(model.templates[0], .en), L10n.ui(.aboutMail, .en))
        XCTAssertEqual(AgentTemplatesModel.grantLines(mailGrants, .en),
                       ["Does on its own: read mail, draft replies", "Asks you first: send mail"],
                       "a switched-off grant is not listed")
        XCTAssertEqual(AgentTemplatesModel.grantLines(mailGrants, .fr),
                       ["Fait seul : lire les e-mails, rédiger des brouillons", "Vous demande d’abord : envoyer des e-mails"])
    }

    func testTheFreeTimesGrantHasAPlainLabel() {
        let grants = AgentGrants(see: [], canDo: [.init(skill: "calendar.freebusy", level: "auto")],
                                 never: [], egressNote: "")
        XCTAssertEqual(AgentTemplatesModel.grantLines(grants, .en), ["Does on its own: read free times only"])
        XCTAssertEqual(AgentTemplatesModel.grantLines(grants, .fr),
                       ["Fait seul : lire les disponibilités seulement"])
    }

    func testAnAgentThatExistsCannotBePicked() async {
        let client = fake(mailCreated: true)
        let model = AgentTemplatesModel(client: client, language: .en)
        await model.load()
        XCTAssertEqual(model.selected, "calendar", "the first free template is picked")
        model.selected = "mail"
        XCTAssertFalse(model.canConfirm)
        let created = await model.confirm()
        XCTAssertFalse(created)
        XCTAssertTrue(client.created.isEmpty, "nothing is sent for an agent that exists")
    }

    func testConfirmCreatesTheTemplateAndRefreshesTheList() async {
        let client = fake()
        var refreshed = 0
        let model = AgentTemplatesModel(client: client, language: .en) { refreshed += 1 }
        await model.load()
        let created = await model.confirm()
        XCTAssertTrue(created)
        XCTAssertEqual(client.created, ["mail"])
        XCTAssertEqual(refreshed, 1)
        XCTAssertNil(model.error)
    }

    func testAGrantPastTheChiefIsSaidPlainlyAndNothingRefreshes() async {
        let client = fake()
        client.createError = AuxdError.http(status: 409, body: #"{"error":{"code":"grant_exceeds_chief","message":"the agent would have access beyond the chief"}}"#)
        var refreshed = 0
        let model = AgentTemplatesModel(client: client, language: .fr) { refreshed += 1 }
        await model.load()
        let created = await model.confirm()
        XCTAssertFalse(created)
        XCTAssertEqual(refreshed, 0)
        XCTAssertEqual(model.error, "Cet agent aurait plus d’accès qu’Aux lui-même, il n’a donc pas été créé.")
        XCTAssertEqual(AgentTemplatesModel.message(client.createError!, .en),
                       "This agent would get more access than Aux itself, so it was not created.")
        let other = AuxdError.http(status: 400, body: #"{"error":{"code":"unknown_template","message":"there is no such agent template"}}"#)
        XCTAssertEqual(AgentTemplatesModel.message(other, .en), "there is no such agent template", "any other refusal: the server's words")
    }
}
