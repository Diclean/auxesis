// The approval card's guarantees: exactly one answer in flight, arming delay
// on destructive scopes, "Always" refused for tainted/unsandboxed/shell asks.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ApprovalTests: XCTestCase {
    private func startedStore(_ transport: FakeTransport, approvals: [Approval]) -> Store {
        transport.approvalsResult = .success(approvals)
        let store = Store(transport: transport, language: .fr)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.approvals.count == approvals.count })
        return store
    }

    func testProposalViewModelMapsContractSectionsAndActionAvailability() throws {
        let approval = Approval(
            id: "ap-proposal", auditId: 3, agent: "mail", threadId: "5", ts: 1,
            action: "e-mail", headline: "Send the invoice reminder",
            preview: "Hello Alex.", fullPreview: "Hello Alex.",
            detail: ["To: alex@example.test", "From: owner@example.test",
                     "Subject: Invoice reminder", "Times: 1"],
            why: "The invoice is overdue.", cleanNote: "arguments were sanitized",
            scopeTool: "mail.send", scopeRule: "Mail may read and prepare."
        )
        let proposal = ProposalViewModel(approval: approval)

        XCTAssertEqual(proposal.title, "Send the invoice reminder")
        XCTAssertEqual(proposal.agent, "mail")
        XCTAssertEqual(proposal.fields, [
            ProposalField(label: "To", value: "alex@example.test"),
            ProposalField(label: "From", value: "owner@example.test"),
            ProposalField(label: "Subject", value: "Invoice reminder"),
            ProposalField(label: "Times", value: "1"),
            ProposalField(label: "Why", value: "The invoice is overdue.")
        ])
        XCTAssertEqual(proposal.body, "Hello Alex.")
        XCTAssertEqual(proposal.whatWillHappen, "e-mail")
        XCTAssertNil(proposal.leftThisMac)
        XCTAssertNil(proposal.stayedHere, "sanitization metadata is not a local-stay record")
        XCTAssertEqual(proposal.boundaryLine,
                       "This approval covers exactly: e-mail · to alex@example.test · Invoice reminder and this text")
        XCTAssertEqual(proposal.grantLine, "Grant used: Mail may read and prepare. Sending is never part of a grant")
        XCTAssertTrue(proposal.actions.send && proposal.actions.edit && proposal.actions.notNow && proposal.actions.dontSend)

        for state in [ApprovalState.allowed(by: "you", always: false), .denied(by: "you"), .expired, .unknown("future")] {
            var resolved = approval
            resolved.state = state
            let resolvedProposal = ProposalViewModel(approval: resolved)
            XCTAssertFalse(resolvedProposal.actions.send || resolvedProposal.actions.edit || resolvedProposal.actions.notNow || resolvedProposal.actions.dontSend)
        }
    }

    func testProposalBoundaryUsesTheRecipientShownFromApprovalDetailFallback() {
        let approval = Approval(
            id: "ap-detail-to", auditId: 4, agent: "mail", threadId: "5", ts: 1,
            action: "e-mail", headline: "Send a note",
            fullPreview: "Hello.",
            detail: ["To: detail@example.test"], scopeTool: "mail.send", scopeRule: "ask"
        )

        let proposal = ProposalViewModel(approval: approval)

        XCTAssertEqual(proposal.fields.first(where: { $0.label == "To" })?.value, "detail@example.test")
        XCTAssertTrue(proposal.boundaryLine.contains("to detail@example.test"))
    }

    /// The card shows the text the action carries, in its own field, and the
    /// fields the daemon sent. A body that reads like a mail header is shown
    /// whole: the card never re-reads it as a draft.
    func testTheCardBodyIsShownWholeEvenWhenItReadsLikeAMailHeader() {
        let body = "To: attacker@example.test\nThe rest of the mail."
        let approval = Approval(
            id: "ap-header", auditId: 5, agent: "mail", threadId: "5", ts: 1,
            action: "run mail_send", headline: "Send mail to camille@example.test",
            preview: body, fullPreview: body,
            detail: ["To: camille@example.test", "Subject: Check in"],
            scopeTool: "mail.send", scopeRule: "ask"
        )

        let proposal = ProposalViewModel(approval: approval)

        XCTAssertEqual(proposal.body, body)
        XCTAssertEqual(proposal.fields.first(where: { $0.label == "To" })?.value, "camille@example.test")
        XCTAssertEqual(proposal.fields.first(where: { $0.label == "Subject" })?.value, "Check in")
    }

    /// APPROVAL-PREVIEW-1: the card shows the title and the body the daemon
    /// built, and the fields it sent. The arguments never reach the screen:
    /// the owner reads a mail, not a fill.
    /// An invite with no description still has something to show: its
    /// organizer and event fields are drawn, so a mirror folds it behind
    /// "Show draft" and Send waits.
    func testAnInviteWithNoBodyStillShowsEveryDetailLine() {
        let approval = Approval(
            id: "ap-invite", auditId: 10, agent: "calendar", threadId: "6", ts: 1,
            action: "run skill__invite", headline: "Send invite \u{201c}Board review\u{201d} to board@example.test",
            preview: nil, fullPreview: nil, editPreview: nil,
            detail: ["Organizer: your Google account (signed in)",
                     "Attendees (each gets an invite): board@example.test",
                     "start: 2026-10-27T14:00:00+02:00", "Subject: kept apart"],
            why: "asks", scopeTool: "skill__invite", scopeRule: "ask"
        )
        let card = ApprovalCard.make(approval, phase: .open)
        XCTAssertTrue(card.displayText.isEmpty)
        XCTAssertTrue(card.hasPreview, "detail lines count as something to show")
        XCTAssertEqual(card.otherDetail, [
            "Organizer: your Google account (signed in)",
            "Attendees (each gets an invite): board@example.test",
            "start: 2026-10-27T14:00:00+02:00",
        ])
    }

    func testTheCardShowsTheDaemonTitleAndBodyAndNeverTheArguments() throws {
        let body = "Hi Camille,\n\nFollowing up on the quote."
        let approval = Approval(
            id: "ap-skill", auditId: 9, agent: "mail", threadId: "5", ts: 1,
            action: "run skill__follow-up", headline: "Send follow-up to camille@example.test",
            preview: body, fullPreview: body, editPreview: "{\"calls\":[]}",
            detail: ["To: camille@example.test", "Subject: Re: our last exchange"],
            why: "asks", scopeTool: "skill__follow-up", scopeRule: "ask"
        )

        let proposal = ProposalViewModel(approval: approval)

        XCTAssertEqual(proposal.title, "Send follow-up to camille@example.test")
        XCTAssertEqual(proposal.body, body)
        XCTAssertEqual(proposal.fields.first { $0.label == "To" }?.value, "camille@example.test")
        XCTAssertEqual(proposal.fields.first { $0.label == "Subject" }?.value, "Re: our last exchange")
        // The card the view draws: the same title, and a body that is the
        // mail, not the arguments.
        let card = ApprovalCard.make(approval, phase: .open)
        XCTAssertEqual(card.title, "Send follow-up to camille@example.test")
        XCTAssertEqual(card.displayText, body, "the card shows the mail, not the arguments")
        // The edit form keeps the arguments as JSON: that is the owner's
        // editor, never the card.
        XCTAssertTrue(card.editableText.contains("\"calls\""))
        for text in [proposal.title, proposal.body] {
            XCTAssertFalse(text.contains("{\""))
            XCTAssertFalse(text.contains("skill_hash"))
        }
    }

    /// The read-only card shows the daemon's text; the edit payload is the
    /// editor's own text and never reaches the card.
    func testTheReadOnlyCardNeverShowsTheEditPayload() throws {
        let approval = Approval(
            id: "ap-readonly", auditId: 9, agent: "scout", threadId: "7", ts: 1,
            action: "run write_file", headline: "Write file",
            preview: "content: written", fullPreview: "content: written",
            editPreview: "{\"path\":\"out.txt\"}",
            scopeTool: "write_file", scopeRule: "ask"
        )

        let card = ApprovalCard.make(approval, phase: .open)

        XCTAssertEqual(card.displayText, "content: written")
        XCTAssertFalse(card.displayText.contains("out.txt"), "the card never shows the arguments")
        XCTAssertTrue(card.editableText.contains("out.txt"), "the editor holds the payload")
    }

    // MARK: Target isolation — two pending cards never cross

    func testResolvingOneCardLeavesTheOtherPendingAndKeepsEachOwnId() throws {
        let transport = FakeTransport()
        // ts: a is newer, so the snapshot sorts it first (newest-first).
        let a = Approval(
            id: "ap-a", auditId: 1, agent: "scout", threadId: "7", ts: 2,
            action: "write", headline: "WRITE A", why: "asks",
            // A known, non-command tool: main's `alwaysAllowed` gate refuses
            // "Always" for ids this build has no rule to save.
            scopeTool: "write_file", scopeRule: "ask"
        )
        let b = Approval(
            id: "ap-b", auditId: 2, agent: "mail", threadId: "5", ts: 1,
            action: "send", headline: "SEND B", why: "asks",
            scopeTool: "mail.send", scopeResource: "smtp.acme", scopeRule: "ask"
        )
        let store = startedStore(transport, approvals: [a, b])
        XCTAssertEqual(store.approvals.map(\.id), ["ap-a", "ap-b"])

        let cardA = try XCTUnwrapOptional(store.approvals.first { $0.id == "ap-a" })
        let cardB = try XCTUnwrapOptional(store.approvals.first { $0.id == "ap-b" })

        store.resolve(cardA, decision: .allowAlways, scope: cardA.alwaysScope)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls[0].id, "ap-a", "the id sent is the resolved card's id")
        XCTAssertEqual(transport.resolveScopes[0].scope, cardA.alwaysScope, "the scope belongs to the same card")
        XCTAssertTrue(store.approvals.first { $0.id == "ap-b" }?.state.isPending == true, "B is untouched")

        transport.resolveResult = .success(.denied(by: "you"))
        store.resolve(cardB, decision: .deny)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 2 })
        XCTAssertEqual(transport.resolveCalls[1].id, "ap-b", "each answer sends its own card's id")
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always", "deny"])
        store.stop()
    }

    func testAlwaysScopeIsBuiltFromThatCardOnly() throws {
        // Pure helper the view uses for the allow-always dialog: the scope
        // always pairs with the same card's id, never a neighbor's fields.
        let mail = Approval(
            id: "ap-mail", auditId: 1, agent: "mail", threadId: "5", ts: 1,
            action: "send", headline: "SEND", why: "asks",
            scopeTool: "mail.send", scopeResource: "smtp.acme", scopeRule: "ask"
        )
        let shell = Approval(
            id: "ap-shell", auditId: 2, agent: "scout", threadId: "7", ts: 2,
            action: "run", headline: "RUN", why: "asks",
            scopeTool: "fs.write", scopeRule: "ask"
        )
        XCTAssertEqual(mail.alwaysScope, ApprovalScope(tool: "mail.send", agent: "mail", resource: "smtp.acme"))
        XCTAssertEqual(shell.alwaysScope, ApprovalScope(tool: "fs.write", agent: "scout", resource: nil))
        XCTAssertNotEqual(mail.alwaysScope, shell.alwaysScope)

        let json = Data(#"""
        {"id":"ap-wire","audit_id":9,"agent":"mail","thread_id":"5","ts":1,
         "action":"send","headline":"SEND","scope_tool":"mail.send",
         "scope_resource":"smtp.acme","state":{"state":"pending"}}
        """#.utf8)
        let wire = try JSONDecoder().decode(Approval.self, from: json)
        XCTAssertEqual(
            wire.alwaysScope,
            ApprovalScope(tool: "mail.send", agent: "mail", resource: "smtp.acme"),
            "the wire-decoded card carries its own resource into its scope"
        )
    }

    // MARK: Ordering — snapshots and live arrivals agree on newest-first

    func testSnapshotOrderMatchesLiveArrivalsAcrossAReconnect() throws {
        let transport = FakeTransport()
        let oldest = Approval(id: "ap-old", auditId: 1, agent: "scout", threadId: "7", ts: 1000, action: "act", headline: "OLD", scopeTool: "tool")
        let middle = Approval(id: "ap-mid", auditId: 2, agent: "scout", threadId: "7", ts: 2000, action: "act", headline: "MID", scopeTool: "tool")
        let newest = Approval(id: "ap-new", auditId: 3, agent: "scout", threadId: "7", ts: 3000, action: "act", headline: "NEW", scopeTool: "tool")

        // The daemon lists oldest-first; the inbox is newest-first.
        transport.approvalsResult = .success([oldest, middle])
        let store = startedStore(transport, approvals: [oldest, middle])
        XCTAssertEqual(store.approvals.map(\.id), ["ap-mid", "ap-old"], "snapshot is shown newest-first")
        store.focusNext()
        XCTAssertEqual(store.focusedApprovalId, "ap-mid", "J/K starts at the newest ask")
        store.focusNext()
        XCTAssertEqual(store.focusedApprovalId, "ap-old")

        transport.emit(.approvalNew(newest))
        XCTAssertTrue(waitUntil { store.approvals.map(\.id) == ["ap-new", "ap-mid", "ap-old"] })

        // A reconnect re-fetches the snapshot; the order must not flip.
        transport.approvalsResult = .success([oldest, middle, newest])
        store.restart()
        XCTAssertTrue(waitUntil(timeout: 3) {
            store.syncCount >= 2 && store.phase == .live && store.approvals.count == 3
        })
        XCTAssertEqual(
            store.approvals.map(\.id), ["ap-new", "ap-mid", "ap-old"],
            "a reconnect must not flip oldest/newest and reshuffle J/K focus"
        )
        store.stop()
    }

    func testOnlyOneAnswerEverLeavesForOneApproval() throws {
        let transport = FakeTransport()
        let approval = try Fixtures.approvals()[0]
        let store = startedStore(transport, approvals: [approval])

        let gate = Gate()
        transport.beforeResolve = { await gate.wait() }
        let card = try XCTUnwrapOptional(store.approvals.first)

        store.resolve(card, decision: .allowOnce)
        store.resolve(card, decision: .allowOnce) // double-click
        store.resolve(card, decision: .deny)      // a different key racing the click
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_once"])
        XCTAssertFalse(store.canAct(card), "buttons must be disabled while sending")

        gate.open()
        XCTAssertTrue(waitUntil { store.approvals.first?.state == .allowed(by: "you", always: false) })

        store.resolve(try XCTUnwrapOptional(store.approvals.first), decision: .deny)
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertEqual(transport.resolveCalls.count, 1, "a resolved card never answers again")
        store.stop()
    }

    func testFailureReturnsTheCardToPendingAndAllowsARetry() throws {
        let transport = FakeTransport()
        let approval = try Fixtures.approvals()[0]
        let store = startedStore(transport, approvals: [approval])
        transport.resolveResult = .failure(AuxdError.http(status: 501, body: "editing an approval draft"))

        store.resolve(try XCTUnwrapOptional(store.approvals.first), decision: .edit, text: "hello")
        XCTAssertTrue(waitUntil { store.approvalErrors[approval.id] != nil && store.sendingApprovalIds.isEmpty })
        XCTAssertTrue(store.approvals[0].state.isPending)
        XCTAssertTrue(store.approvalErrors[approval.id]?.contains("modification") == true, "plain words for 501")

        transport.resolveResult = .success(.denied(by: "you"))
        store.resolve(try XCTUnwrapOptional(store.approvals.first), decision: .deny)
        XCTAssertTrue(waitUntil { store.approvals.first?.state == .denied(by: "you") })
        XCTAssertEqual(transport.resolveCalls.count, 2)
        store.stop()
    }

    func testAlwaysIsRefusedForTaintedUnsandboxedAndShellAsks() throws {
        let approvals = try Fixtures.approvals()
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: approvals)

        let shell = try XCTUnwrapOptional(store.approvals.first { $0.id == "ap-1-1" })
        XCTAssertFalse(store.alwaysAllowed(shell), "shell is never allow-listed")

        let email = try XCTUnwrapOptional(store.approvals.first { $0.id == "ap-2-1" })
        XCTAssertNotNil(email.taint)
        XCTAssertFalse(store.alwaysAllowed(email), "taint can never widen permissions")

        let unsandboxed = try XCTUnwrapOptional(store.approvals.first { $0.id == "ap-3-1" })
        XCTAssertTrue(unsandboxed.unsandboxed)
        XCTAssertFalse(store.alwaysAllowed(unsandboxed))

        // A clean, sandboxed, non-shell ask can be always-allowed.
        let clean = Approval(
            id: "ap-clean", auditId: 1, agent: "mail", threadId: "5", ts: 0,
            action: "send an email", headline: "MAIL.SEND", why: "asks",
            scopeTool: "mail.send", scopeRule: "ask"
        )
        XCTAssertTrue(store.alwaysAllowed(clean))
        store.stop()
    }

    /// Regression (PR #104, security review FAIL P2): a tool this build does not know by
    /// name has no rule to save, so "Toujours" must be unavailable. Allow once,
    /// Deny and Edit stay available.
    func testAlwaysIsUnavailableForAnUnknownTool() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])

        let unknown = Approval(
            id: "ap-unknown", auditId: 5, agent: "scout", threadId: "7", ts: 0,
            action: "act", headline: "H", why: "asks",
            scopeTool: "totally_new_tool_9000", scopeRule: "ask"
        )
        XCTAssertFalse(store.alwaysAllowed(unknown), "an unknown tool can never be always-allowed")
        XCTAssertTrue(store.canAllow(unknown), "Allow once stays available")
        XCTAssertTrue(store.canAct(unknown), "Deny and Edit stay available")

        // The same id with an invisible byte is unknown too — never mistaken for
        // the known tool it is trying to imitate.
        let spoofed = Approval(
            id: "ap-spoof-unknown", auditId: 6, agent: "scout", threadId: "7", ts: 0,
            action: "read", headline: "READ", scopeTool: "read\u{200B}_file"
        )
        XCTAssertFalse(store.alwaysAllowed(spoofed), "an id that only mimics a known tool is still unknown")

        // A clean, known, sandboxed ask keeps "Always".
        let known = Approval(
            id: "ap-known", auditId: 7, agent: "mail", threadId: "5", ts: 0,
            action: "send an email", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        XCTAssertTrue(store.alwaysAllowed(known))
        store.stop()
    }

    /// Regression (PR #104, security review R3 P2 A): an unknown id past the scalar bound
    /// is truncated, so two distinct ids render identically. "Allow once" is
    /// refused too, leaving Refuse and Modifier; known ids and unknown ids at or
    /// under the bound keep the current behaviour.
    func testOverLongUnknownToolRefusesAllowOnce() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])

        let head = String(repeating: "x", count: ServerText.Limits.unknownTool)
        let idA = head + "A"
        let idB = head + "B"
        XCTAssertEqual(idA.unicodeScalars.count, 201)
        XCTAssertEqual(
            ReceiptDetailCopy.friendlyTool(idA, .fr),
            ReceiptDetailCopy.friendlyTool(idB, .fr),
            "the pair is genuinely ambiguous once truncated"
        )

        for (id, name) in [(idA, "A"), (idB, "B")] {
            let ask = Approval(
                id: "ap-long-\(name)", auditId: 8, agent: "scout", threadId: "7", ts: 0,
                action: "act", headline: "H", why: "asks", scopeTool: id
            )
            XCTAssertTrue(store.unknownToolTooLong(ask), "\(name) is over the bound")
            XCTAssertFalse(store.alwaysAllowed(ask))
            XCTAssertFalse(store.canAllowOnce(ask), "Allow once is refused for an ambiguous id")
            XCTAssertTrue(store.canAct(ask), "Refuse and Modifier stay available")
        }

        // At the bound, and known ids, keep Allow once.
        let atBound = Approval(
            id: "ap-bound", auditId: 9, agent: "scout", threadId: "7", ts: 0,
            action: "act", headline: "H",
            scopeTool: String(repeating: "y", count: ServerText.Limits.unknownTool)
        )
        XCTAssertFalse(store.unknownToolTooLong(atBound))
        XCTAssertTrue(store.canAllowOnce(atBound))

        let known = Approval(
            id: "ap-known-long", auditId: 10, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        XCTAssertFalse(store.unknownToolTooLong(known))
        XCTAssertTrue(store.canAllowOnce(known))
        store.stop()
    }

    /// Regression (PR #104, security review R4 P2 A): the allow guards lived only in the
    /// views. A direct `store.resolve` must not be a way around them: an over-long
    /// unknown id with `allowOnce`, or any unknown id with `allowAlways`, sends
    /// nothing, leaves the ask pending and answerable, and shows the card's own
    /// explicit message. A legitimate answer still goes through.
    func testResolveRefusesTheGuardsThatOnlyLivedInTheView() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])

        let overLong = Approval(
            id: "ap-direct-long", auditId: 11, agent: "scout", threadId: "7", ts: 0,
            action: "act", headline: "H", why: "asks",
            scopeTool: String(repeating: "x", count: ServerText.Limits.unknownTool + 1)
        )
        let unknown = Approval(
            id: "ap-direct-unknown", auditId: 12, agent: "scout", threadId: "7", ts: 0,
            action: "act", headline: "H", why: "asks",
            scopeTool: "totally_new_tool_9000"
        )

        store.resolve(overLong, decision: .allowOnce)
        store.resolve(unknown, decision: .allowAlways)

        // Nothing may be created: give any (wrongly) spawned task a real chance
        // to run before asserting on an empty resolve log.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "a guarded decision never reaches the daemon")
        XCTAssertEqual(
            store.approvalErrors[overLong.id],
            L10n.t(.approvalAllowUnknownToolTooLong, store.language)
        )
        XCTAssertEqual(
            store.approvalErrors[unknown.id],
            L10n.t(.approvalAlwaysUnknownTool, store.language)
        )
        // A refusal is not a resolution: the ask stays pending and answerable.
        XCTAssertTrue(store.canAct(overLong))
        XCTAssertTrue(store.canAct(unknown))

        // The guards do not over-refuse: a known, clean ask can still be
        // always-allowed, and any pending ask can still be denied.
        let known = Approval(
            id: "ap-direct-known", auditId: 13, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        store.resolve(known, decision: .allowAlways)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])

        store.resolve(unknown, decision: .deny)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 2 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always", "deny"])
        store.stop()
    }

    /// Regression (PR #104, security review R5 P2): `Store.resolve` refused `.allowAlways`
    /// only for an unknown tool, while the card also refuses tainted,
    /// unsandboxed and shell asks. A direct call must not be a wider door than
    /// the button: the same `alwaysAllowed` gate applies, nothing is sent, the
    /// ask stays pending and answerable, and the card's own copy names the cause.
    func testResolveRefusesAllowAlwaysForEveryAlwaysAllowedReason() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: try Fixtures.approvals())

        let guarded: [(id: String, message: StringKey)] = [
            ("ap-1-1", .approvalAlwaysShell),
            ("ap-2-1", .approvalAlwaysTainted),
            ("ap-3-1", .approvalAlwaysUnsandboxed),
        ]
        for (id, message) in guarded {
            let card = try XCTUnwrapOptional(store.approvals.first { $0.id == id })
            XCTAssertFalse(store.alwaysAllowed(card))
            store.resolve(card, decision: .allowAlways)
            XCTAssertEqual(store.approvalErrors[id], L10n.t(message, store.language))
            XCTAssertTrue(store.canAct(card), "a refused widening never blocks the ask")
        }

        // Give any (wrongly) spawned task a real chance to run before asserting
        // that the guarded decisions never reached the daemon.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "a guard is not bypassable by a direct call")
        XCTAssertTrue(store.approvals.allSatisfy { $0.state.isPending }, "the asks stay pending")

        // The gate does not over-refuse: a known, clean tool still widens.
        let known = Approval(
            id: "ap-known-always", auditId: 14, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        store.resolve(known, decision: .allowAlways)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])
        store.stop()
    }

    /// Regression (PR #104, GLM r4 P3): the `.allowOnce` guard in `Store.resolve`
    /// must not depend on the id's rendering path. An unknown id of 201 scalars —
    /// here built from quote delimiters, the very characters that used to be
    /// demoted — is over `ServerText.Limits.unknownTool`, so a direct
    /// `resolve(.allowOnce)` sends nothing, leaves the ask pending, and shows the
    /// card's own message.
    func testResolveRefusesAllowOnceForAnOverLongUnknownIdWithDelimiters() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])
        let id = String(repeating: "x\u{00AB}y", count: 67) // 67 × 3 = 201 scalars
        XCTAssertEqual(id.unicodeScalars.count, ServerText.Limits.unknownTool + 1)
        let ask = Approval(
            id: "ap-direct-delim", auditId: 15, agent: "scout", threadId: "7", ts: 0,
            action: "act", headline: "H", why: "asks", scopeTool: id
        )
        XCTAssertTrue(store.unknownToolTooLong(ask))
        XCTAssertFalse(store.canAllowOnce(ask), "the card refuses Allow once for the ambiguous id")

        store.resolve(ask, decision: .allowOnce)

        // Give any (wrongly) spawned task a real chance to run before asserting
        // on an empty resolve log.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "the over-long unknown id never reaches the daemon")
        XCTAssertEqual(
            store.approvalErrors[ask.id],
            L10n.t(.approvalAllowUnknownToolTooLong, store.language)
        )
        XCTAssertTrue(store.canAct(ask), "a refused answer never blocks the ask")
        store.stop()
    }

    func testDestructiveScopesArmForOneSecond() throws {
        let transport = FakeTransport()
        let destructive = try Fixtures.approvals()[0]
        let store = startedStore(transport, approvals: [destructive])

        let card = try XCTUnwrapOptional(store.approvals.first)
        let now = Date()
        let fresh = Approval(
            id: card.id, auditId: card.auditId, agent: card.agent, threadId: card.threadId,
            ts: card.ts, action: card.action, headline: card.headline, preview: card.preview,
            why: card.why, scopeTool: card.scopeTool, scopeRule: card.scopeRule,
            destructive: true, state: .pending, receivedAt: now
        )
        XCTAssertLessThan(store.armingProgress(fresh, now: now), 1)
        XCTAssertFalse(store.canAllow(fresh, now: now), "a fresh destructive ask is not armed")
        XCTAssertEqual(store.armingProgress(fresh, now: now.addingTimeInterval(1.0)), 1)
        XCTAssertTrue(store.canAllow(fresh, now: now.addingTimeInterval(1.0)))

        let harmless = Approval(
            id: "ap-soft", auditId: 2, agent: "mail", threadId: "5", ts: 0,
            action: "reply", headline: "MAIL.SEND", why: "asks",
            scopeTool: "mail.send", scopeRule: "ask", destructive: false, state: .pending
        )
        XCTAssertTrue(store.canAllow(harmless, now: now), "non-destructive asks don't arm")
        store.stop()
    }

    func testJkFocusCyclesThroughPendingApprovals() throws {
        let transport = FakeTransport()
        let approvals = try Fixtures.approvals()
        let store = startedStore(transport, approvals: approvals)

        // Cycle through the inbox as it is shown (newest first).
        let ids = store.approvals.map(\.id)
        XCTAssertEqual(ids.count, 3)
        store.focus(ids[0])
        store.focusNext()
        XCTAssertEqual(store.focusedApprovalId, ids[1])
        store.focusNext()
        XCTAssertEqual(store.focusedApprovalId, ids[2])
        store.focusNext()
        XCTAssertEqual(store.focusedApprovalId, ids[0], "wraps")
        store.focusPrev()
        XCTAssertEqual(store.focusedApprovalId, ids[2], "wraps backwards")
        store.stop()
    }

    // MARK: F5 — a hidden shell name cannot escape the Always refusal

    func testZeroWidthShellNamesCannotEscapeTheAlwaysRefusal() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])
        let spoof = Approval(
            id: "ap-spoof", auditId: 3, agent: "scout", threadId: "7", ts: 0,
            action: "run", headline: "SHELL", scopeTool: "sh\u{200B}ell"
        )
        XCTAssertFalse(store.alwaysAllowed(spoof), "a zero-width-hidden shell is still a shell")
        let clean = Approval(
            id: "ap-clean-2", auditId: 4, agent: "scout", threadId: "7", ts: 0,
            action: "send", headline: "MAIL", scopeTool: "mail.send"
        )
        XCTAssertTrue(store.alwaysAllowed(clean))
        store.stop()
    }

    // MARK: F5 — the shell refusal is case-insensitive

    /// Regression (PR #104, GLM r3 P2): the shell refusal was matched
    /// case-sensitively, while the known-tool table lowercases. So `Shell`,
    /// `SHELL` and `SHELL.exec` were known tools that slipped past the refusal —
    /// `alwaysAllowed` returned true. The gate must lowercase too, and a direct
    /// `.allowAlways` must send nothing.
    func testShellRefusalIsCaseInsensitive() throws {
        let transport = FakeTransport()
        let asks = ["Shell", "SHELL", "SHELL.exec"].map { raw in
            Approval(
                id: "ap-case-\(raw)", auditId: 20, agent: "scout", threadId: "7", ts: 0,
                action: "run", headline: "SHELL", why: "asks", scopeTool: raw
            )
        }
        let store = startedStore(transport, approvals: asks)

        for ask in asks {
            XCTAssertFalse(store.alwaysAllowed(ask), "\(ask.scopeTool) is still a shell")
            store.resolve(ask, decision: .allowAlways)
            XCTAssertEqual(
                store.approvalErrors[ask.id],
                L10n.t(.approvalAlwaysShell, store.language),
                "\(ask.scopeTool) names the same refusal as the button"
            )
            XCTAssertTrue(store.canAct(ask), "a refused widening never blocks the ask")
        }

        // Give any (wrongly) spawned task a real chance to run before asserting
        // that no case variant reached the daemon.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "a shell ask never widens, whatever its case")
        XCTAssertTrue(store.approvals.allSatisfy { $0.state.isPending }, "the asks stay pending")

        // The gate does not over-refuse: a non-shell known tool still widens.
        let known = Approval(
            id: "ap-case-known", auditId: 21, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        store.resolve(known, decision: .allowAlways)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])
        store.stop()
    }

    // MARK: F5 — the whole command class refuses Always, whatever the alias

    /// Regression (PR #104, security review R5 P2 A): the known-tool table labels
    /// `run_command`, `run`, `bash` and `exec` "lancer une commande" like
    /// `shell`, but the Always gate only refused a `shell` prefix — so those
    /// aliases could be widened to a permanent rule. The refusal now follows the
    /// label the card shows, in any case, and a direct `.allowAlways` sends
    /// nothing while a non-command known tool still widens.
    func testAlwaysIsRefusedForEveryCommandAlias() throws {
        let transport = FakeTransport()
        let aliases = ["run_command", "run", "bash", "exec", "BASH", "shell.exec"]
        let asks = aliases.map { raw in
            Approval(
                id: "ap-cmd-\(raw)", auditId: 30, agent: "scout", threadId: "7", ts: 0,
                action: "run", headline: "SHELL", why: "asks", scopeTool: raw
            )
        }
        let store = startedStore(transport, approvals: asks)

        for ask in asks {
            XCTAssertEqual(
                ReceiptDetailCopy.friendlyTool(ask.scopeTool, .fr),
                "lancer une commande",
                "\(ask.scopeTool) must be labelled as a command"
            )
            XCTAssertFalse(store.alwaysAllowed(ask), "\(ask.scopeTool) is still a command")
            store.resolve(ask, decision: .allowAlways)
            XCTAssertEqual(
                store.approvalErrors[ask.id],
                L10n.t(.approvalAlwaysShell, store.language),
                "\(ask.scopeTool) names the same refusal as the button"
            )
            XCTAssertTrue(store.canAct(ask), "a refused widening never blocks the ask")
        }

        // Give any (wrongly) spawned task a real chance to run before asserting
        // that no alias reached the daemon.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "no command alias ever widens")
        XCTAssertTrue(store.approvals.allSatisfy { $0.state.isPending }, "the asks stay pending")

        // The gate does not over-refuse: known non-command tools keep "Always".
        for (index, raw) in ["read_file", "mail.send", "fetch", "open_url"].enumerated() {
            let known = Approval(
                id: "ap-cmd-known-\(index)", auditId: 31, agent: "mail", threadId: "5", ts: 0,
                action: "read", headline: "READ", scopeTool: raw
            )
            XCTAssertFalse(ReceiptDetailCopy.isCommandTool(raw), "\(raw) is not a command")
            XCTAssertTrue(store.alwaysAllowed(known), "\(raw) keeps Always")
        }

        let known = Approval(
            id: "ap-cmd-known", auditId: 31, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", scopeTool: "mail.send"
        )
        store.resolve(known, decision: .allowAlways)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])
        store.stop()
    }

    /// Regression (PR #104, security review R8 P2): the Always gate only inspected the
    /// approval, then forwarded the caller's `scope` unchecked. A direct
    /// `resolve(.allowAlways)` on a healthy `mail.send` ask with a scope naming
    /// another tool (`run`, or an unknown id) could save a permanent command
    /// rule. The scope must name the ask's own tool: otherwise nothing is sent,
    /// the ask stays pending, and the card's own copy explains it. A scope that
    /// matches still widens.
    func testResolveRefusesAllowAlwaysWithAScopeForAnotherTool() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])
        let ask = Approval(
            id: "ap-scope-mismatch", auditId: 40, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", why: "asks", scopeTool: "mail.send"
        )
        // The ask itself is always-allowable: only the supplied scope is wrong.
        XCTAssertTrue(store.alwaysAllowed(ask))

        store.resolve(ask, decision: .allowAlways, scope: ApprovalScope(tool: "run", agent: ask.agent))
        store.resolve(
            ask,
            decision: .allowAlways,
            scope: ApprovalScope(tool: "totally_new_tool_9000", agent: ask.agent)
        )

        // Give any (wrongly) spawned task a real chance to run before asserting
        // on an empty resolve log.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "a scope for another tool never reaches the daemon")
        XCTAssertEqual(
            store.approvalErrors[ask.id],
            L10n.t(.approvalAlwaysUnknownTool, store.language)
        )
        XCTAssertTrue(store.canAct(ask), "a refused widening never blocks the ask")
        XCTAssertTrue(ask.state.isPending, "a refusal is not a resolution")

        // The card's own scope — the ask's tool — still passes.
        var scope = ApprovalScope(tool: ask.scopeTool, agent: ask.agent)
        if let resource = ask.scopeResource {
            scope = ApprovalScope(tool: ask.scopeTool, agent: ask.agent, resource: resource)
        }
        store.resolve(ask, decision: .allowAlways, scope: scope)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 1 })
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])
        store.stop()
    }

    /// Regression (PR #104, security review R9 P2): `.allowAlways` forwarded the caller's
    /// `scope` as-is. With a nil scope the server chose the rule's perimeter;
    /// with a matching tool the caller could still pick another agent or resource.
    /// "Always" must always send the perimeter the card builds from the
    /// approval itself — its tool, its agent and its resource when it has one.
    func testResolveAlwaysSendsTheApprovalsOwnScopeNotTheCallers() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])

        // No caller scope: the sent perimeter is derived, never nil.
        let ask = Approval(
            id: "ap-derived-scope", auditId: 41, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", why: "asks",
            scopeTool: "mail.send", scopeResource: "mailbox:inbox"
        )
        XCTAssertTrue(store.alwaysAllowed(ask))
        store.resolve(ask, decision: .allowAlways)
        XCTAssertTrue(waitUntil { transport.resolveScopes.count == 1 })
        XCTAssertEqual(
            try XCTUnwrapOptional(transport.resolveScopes.first?.scope),
            ApprovalScope(tool: "mail.send", agent: "mail", resource: "mailbox:inbox")
        )

        // A caller scope with the right tool but another agent and resource is
        // ignored: the sent perimeter stays the approval's own.
        let other = Approval(
            id: "ap-derived-scope-2", auditId: 42, agent: "scout", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", why: "asks",
            scopeTool: "mail.send", scopeResource: "mailbox:archive"
        )
        XCTAssertTrue(store.alwaysAllowed(other))
        store.resolve(
            other,
            decision: .allowAlways,
            scope: ApprovalScope(tool: "mail.send", agent: "someone-else", resource: "mailbox:sent")
        )
        XCTAssertTrue(waitUntil { transport.resolveScopes.count == 2 })
        XCTAssertEqual(
            try XCTUnwrapOptional(transport.resolveScopes.last?.scope),
            ApprovalScope(tool: "mail.send", agent: "scout", resource: "mailbox:archive")
        )
        store.stop()
    }

    /// A caller scope naming another tool on `.allowAlways` still sends
    /// nothing: the derived perimeter must not paper over a widened request.
    func testResolveAlwaysWithAScopeForAnotherToolSendsNothing() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])
        let ask = Approval(
            id: "ap-scope-other", auditId: 43, agent: "mail", threadId: "5", ts: 0,
            action: "send", headline: "MAIL.SEND", why: "asks", scopeTool: "mail.send"
        )
        XCTAssertTrue(store.alwaysAllowed(ask))

        store.resolve(ask, decision: .allowAlways, scope: ApprovalScope(tool: "run", agent: ask.agent))

        // Give any (wrongly) spawned task a real chance to run before asserting
        // on an empty resolve log.
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.isEmpty {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertTrue(transport.resolveCalls.isEmpty, "a scope for another tool never reaches the daemon")
        XCTAssertEqual(
            store.approvalErrors[ask.id],
            L10n.t(.approvalAlwaysUnknownTool, store.language)
        )
        XCTAssertTrue(store.canAct(ask), "a refused widening never blocks the ask")
        store.stop()
    }

    /// The derivation never over-refuses: a safe, known tool still widens with
    /// its own derived perimeter.
    func testResolveAlwaysOnASafeKnownToolStillPasses() throws {
        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [])
        let ask = Approval(
            id: "ap-safe-known", auditId: 44, agent: "scout", threadId: "7", ts: 0,
            action: "read", headline: "READ", why: "reads", scopeTool: "read_file"
        )
        XCTAssertTrue(store.alwaysAllowed(ask))

        store.resolve(ask, decision: .allowAlways)

        XCTAssertTrue(waitUntil { transport.resolveScopes.count == 1 })
        XCTAssertEqual(
            try XCTUnwrapOptional(transport.resolveScopes.last?.scope),
            ApprovalScope(tool: "read_file", agent: "scout")
        )
        XCTAssertEqual(transport.resolveCalls.map(\.decision), ["allow_always"])
        store.stop()
    }

    func testUnknownWireStateIsNeverPendingOrAnswerable() throws {
        // Real wire shape (fixtures): the approval's `state` is an object.
        let json = Data(#"""
        {"id":"ap-x","audit_id":9,"agent":"scout","thread_id":"7","ts":1,
         "action":"act","headline":"H","scope_tool":"tool",
         "state":{"state":"superseded","by":"daemon"}}
        """#.utf8)
        let approval = try JSONDecoder().decode(Approval.self, from: json)
        XCTAssertEqual(approval.state, .unknown("superseded"))
        XCTAssertFalse(approval.state.isPending)

        let transport = FakeTransport()
        let store = startedStore(transport, approvals: [approval])
        XCTAssertTrue(store.pendingApprovals.isEmpty, "an unknown state must not appear as pending")
        XCTAssertFalse(store.canAct(store.approvals[0]), "no Approve/Deny/Decide")
        XCTAssertFalse(store.canAllow(store.approvals[0]))
        XCTAssertNil(store.focusedApprovalId, "focus never lands on an unknown state")
        store.focusNext()
        XCTAssertNil(store.focusedApprovalId)
        XCTAssertEqual(store.agents.first { $0.name == "scout" }?.waiting, 0, "not waiting: nothing to answer")

        store.resolve(store.approvals[0], decision: .allowOnce)
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertTrue(transport.resolveCalls.isEmpty, "an unknown state is never answered")
        store.stop()
    }

    // MARK: F4 — a failed answer re-fetches before any retry, never re-sends

    func testFailedResolveRefetchesTheDaemonStateBeforeAllowingAnything() throws {
        let transport = FakeTransport()
        let approval = try Fixtures.approvals()[0]
        let store = startedStore(transport, approvals: [approval])
        transport.resolveResult = .failure(AuxdError.transport("timeout after commit"))
        var resolved = approval
        resolved.state = .denied(by: "you")
        transport.approvalsResult = .success([resolved]) // the daemon actually resolved it

        store.resolve(try XCTUnwrapOptional(store.approvals.first), decision: .allowOnce)
        XCTAssertTrue(waitUntil { store.approvalErrors[approval.id] != nil })
        XCTAssertTrue(waitUntil { transport.approvalsCalls >= 2 }, "a failed answer must re-fetch")
        XCTAssertEqual(transport.resolveCalls.count, 1, "never re-send automatically")
        XCTAssertTrue(waitUntil { store.pendingApprovals.isEmpty })
        XCTAssertEqual(store.approvals.first?.state, .denied(by: "you"))
        store.stop()
    }

    func testFailedRefetchKeepsTheCardBlockedUntilAFreshSnapshot() throws {
        let transport = FakeTransport()
        let approval = try Fixtures.approvals()[0]
        let store = startedStore(transport, approvals: [approval])
        transport.approvalsResult = .failure(AuxdError.transport("refetch also down"))
        transport.resolveResult = .failure(AuxdError.transport("boom"))

        let card = try XCTUnwrapOptional(store.approvals.first)
        store.resolve(card, decision: .allowOnce)
        XCTAssertTrue(waitUntil { store.approvalErrors[approval.id] != nil })
        XCTAssertTrue(waitUntil { store.sendingApprovalIds.isEmpty }, "the failed call has settled")
        XCTAssertTrue(store.isAwaitingResync(card))
        XCTAssertFalse(store.canAct(card), "blocked while the daemon's state is unknown")
        XCTAssertFalse(store.canAllow(card, now: Date().addingTimeInterval(60)))

        // A click now is a no-op, not a second answer. Give the scheduler a
        // real chance to run any (wrongly) created task before asserting.
        store.resolve(card, decision: .deny)
        let settleDeadline = Date().addingTimeInterval(0.3)
        while Date() < settleDeadline, transport.resolveCalls.count == 1 {
            RunLoop.main.run(until: Date())
            usleep(1_000)
        }
        XCTAssertEqual(transport.resolveCalls.count, 1, "no second answer without a fresh state")

        // A fresh snapshot clears the block (daemon still reports it pending).
        transport.approvalsResult = .success([approval])
        store.restart()
        XCTAssertTrue(waitUntil(timeout: 3) {
            store.syncCount >= 2 && store.phase == .live && !store.isAwaitingResync(card)
        })
        XCTAssertTrue(store.canAct(try XCTUnwrapOptional(store.approvals.first)))
        transport.resolveResult = .success(.allowed(by: "you", always: false))
        store.resolve(try XCTUnwrapOptional(store.approvals.first), decision: .allowOnce)
        XCTAssertTrue(waitUntil { transport.resolveCalls.count == 2 })
        store.stop()
    }
}
