// WO-BUD-4: `/v1/usage` caps feed the per-agent bar, and a `429 budget_denied`
// names the agent and the cap instead of "the service refused".
import XCTest
@testable import AuxesisKit

@objcMembers final class BudgetUsageTests: XCTestCase {
    func testUsageDecodesPerAgentCapsAndToleratesMissingOnes() throws {
        let json = """
        {"day":"2026-11-04","total":{"tokens_in":250,"tokens_out":90,"usd_cents":2},
         "agents":[
           {"agent":"mail","totals":{"tokens_in":200,"tokens_out":80,"usd_cents":2},
            "caps":{"tokens_in":2000000,"tokens_out":400000,"usd_cents":500}},
           {"agent":"aux","totals":{"tokens_in":50,"tokens_out":10,"usd_cents":0},
            "caps":{"tokens_in":null,"tokens_out":null,"usd_cents":null}},
           {"agent":"scout","totals":{"tokens_in":0,"tokens_out":0,"usd_cents":0}}
         ]}
        """
        let day = try JSONDecoder().decode(UsageDay.self, from: Data(json.utf8))
        XCTAssertEqual(day.agents[0].caps?.tokensOut, 400_000)
        XCTAssertEqual(day.agents[1].caps, UsageCaps(), "null caps cap no direction")
        XCTAssertNil(day.agents[2].caps, "missing caps mean no bar")
    }

    func testBudgetRatioUsesTheTightestCappedDirection() {
        let caps = UsageCaps(tokensIn: 1_000, tokensOut: 100, usdCents: 10)
        let usage = UsageTotals(tokensIn: 250, tokensOut: 50, usdCents: 2)
        XCTAssertEqual(Mapper.budgetRatio(usage, caps: caps), 0.5, accuracy: 0.0001)
        XCTAssertFalse(Mapper.budgetHit(usage, caps: caps))
        let atCap = UsageTotals(tokensIn: 250, tokensOut: 100, usdCents: 2)
        XCTAssertEqual(Mapper.budgetRatio(atCap, caps: caps), 1)
        XCTAssertTrue(Mapper.budgetHit(atCap, caps: caps))
        XCTAssertEqual(Mapper.budgetRatio(usage, caps: nil), 0)
        XCTAssertFalse(Mapper.budgetHit(usage, caps: UsageCaps()))
        XCTAssertEqual(Mapper.budgetRatio(usage, caps: UsageCaps(tokensOut: 0)), 1)
        XCTAssertTrue(Mapper.budgetHit(usage, caps: UsageCaps(tokensOut: 0)))
    }

    func testTheAgentMappingFillsTheBudgetSlot() {
        let summary = AgentSummary(name: "mail", usageToday: UsageTotals(tokensIn: 50, tokensOut: 90, usdCents: 1))
        let mapped = Mapper.agent(from: summary, live: nil, budget: UsageCaps(tokensOut: 100))
        XCTAssertEqual(mapped.budgetUsed, 0.9, accuracy: 0.0001)
        XCTAssertFalse(mapped.budgetHit)
        XCTAssertEqual(Mapper.agent(from: summary, live: nil).budgetUsed, 0)
    }

    func testABudgetDenied429NamesTheAgentAndCapInBothLanguages() throws {
        let body = #"{"error":{"code":"budget_denied","message":"the agent's daily budget denied this turn","detail":"agent `mail` reached its daily tokens_out budget (400000/400000 on 2026-11-04)"}}"#
        let error = AuxdError.http(status: 429, body: body)
        let refusal = try XCTUnwrapOptional(error.budgetRefusal)
        XCTAssertEqual(refusal.cap, BudgetRefusal.Cap.tokensOut)
        XCTAssertEqual(refusal.spent, 400_000)
        let english = refusal.message(.en)
        XCTAssertTrue(english.contains("Mail") && english.contains("output-token cap"), english)
        XCTAssertTrue(english.contains("tokens_out") && english.contains("[budgets.agents.mail]"), english)
        let french = refusal.message(.fr)
        XCTAssertTrue(french.contains("Mail") && french.contains("tokens en sortie"), french)
        XCTAssertTrue(french.contains("[budgets.agents.mail]"), french)
    }
}
