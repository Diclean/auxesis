// The calendar card (UI-V5-RICH-2a): rows from the Calendar tool row and the
// owner's question, no card for anything else, EN and FR copy. Fictional data.
import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class CalendarCardTests: XCTestCase {
    private var paris: Calendar { var calendar = Calendar(identifier: .gregorian); calendar.timeZone = TimeZone(identifier: "Europe/Paris")!; return calendar }

    /// Thursday 29 Oct 2026, 10:00 in Paris (UTC+1 after the clock change).
    private let asked = ISO8601DateFormatter().date(from: "2026-10-29T09:00:00Z")!

    private let toolRow = """
    [{"id":"e1","title":"Call with Sample Studio","start":"2026-10-30T12:00:00Z","end":"2026-10-30T13:00:00Z","calendar":"Work","location":null,"attendees":[]},
     {"id":"e2","title":"Review the drafts","start":"2026-10-30T14:30:00Z","end":"2026-10-30T15:00:00Z","calendar":"Work","location":null,"attendees":[]},
     {"id":"e3","title":"Team lunch","start":"2026-10-29T11:00:00Z","end":"2026-10-29T12:00:00Z","calendar":"Work","location":null,"attendees":[]},
     {"id":"e4","title":"Holiday","start":"2026-10-30T23:00:00Z","end":"2026-11-01T00:00:00Z","all_day":true,"calendar":"Home","location":null,"attendees":[]}]
    """

    private func clock(_ date: Date) -> String { CalendarCardModel.format("EEE HH:mm", "en_GB", paris).string(from: date) }

    private func thread(question: String, tool: String, name: String = "apple_calendar_list_events") -> [ChatMessage] {
        let ms = Int64(asked.timeIntervalSince1970 * 1000)
        var row = ChatMessage(id: "3", threadKey: "calendar", author: .tool, ts: ms + 2000, blocks: [.text(tool)])
        row.toolName = name
        return [
            ChatMessage(id: "1", threadKey: "calendar", author: .you, ts: ms, blocks: [.text(question)]),
            ChatMessage(id: "2", threadKey: "calendar", author: .agent("calendar"), ts: ms + 1000, blocks: [.text("I'll check your calendar.")]),
            row,
            ChatMessage(id: "4", threadKey: "calendar", author: .agent("calendar"), ts: ms + 3000, blocks: [.text("You're free from 15:00 to 15:30.")]),
        ]
    }

    func testACalendarResultMakesACardWithTheRightRows() {
        guard let card = CalendarCard.make(toolText: toolRow, question: "What's free tomorrow afternoon?", now: asked, readAt: asked, calendar: paris) else { return XCTFail("no card") }
        XCTAssertEqual(card.title(.en), "Free time")
        let rows = card.rows.map { "\($0.kind) \(clock($0.start))-\(clock($0.end)) \($0.title)" }
        XCTAssertEqual(rows, ["free Fri 12:00-Fri 13:00 ", "event Fri 13:00-Fri 14:00 Call with Sample Studio", "free Fri 14:00-Fri 15:30 ",
                              "event Fri 15:30-Fri 16:00 Review the drafts", "free Fri 16:00-Fri 18:00 "])
        XCTAssertEqual(CalendarCardModel.time(card.rows[1], .en, calendar: paris), "13:00–14:00")
    }

    func testAnAllDayEventBlocksTheWholeDay() {
        guard let card = CalendarCard.make(toolText: toolRow, question: "what's free on Saturday?", now: asked, readAt: asked, calendar: paris) else { return XCTFail("no card") }
        XCTAssertEqual(card.rows.map(\.kind), [.allDay])
        XCTAssertEqual(card.rows.first?.title, "Holiday")
    }

    func testADayTheToolNeverReadIsNotCheckedNeverFree() {
        // Read on Tue 27 Oct: the copy covers Tue 27 to Tue 3 Nov, so Wed 4 Nov was never read.
        let readAt = asked.addingTimeInterval(-2 * 86_400)
        guard let card = CalendarCard.make(toolText: toolRow, question: "free tomorrow or Wednesday?", now: asked, readAt: readAt, calendar: paris) else { return XCTFail("no card") }
        let wednesday = card.rows.filter { clock($0.start).hasPrefix("Wed") }
        XCTAssertEqual(wednesday.map(\.kind), [.notChecked])
        XCTAssertEqual(wednesday.flatMap { row in [Language.en, .fr].map { CalendarCardModel.what(row, $0) } }, ["Not checked", "Non vérifié"])
    }

    func testACappedListShowsEventsOnlyAndSaysSo() {
        let one = #"{"title":"Slot","start":"2026-10-30T12:00:00Z","end":"2026-10-30T12:15:00Z","calendar":"Work"}"#
        let full = "[" + Array(repeating: one, count: 50).joined(separator: ",") + "]"
        guard let card = CalendarCard.make(toolText: full, question: "what's free tomorrow?", now: asked, readAt: asked, calendar: paris) else { return XCTFail("no card") }
        XCTAssertTrue(card.incomplete)
        XCTAssertFalse(card.rows.contains { $0.kind == .free })
        XCTAssertEqual([.en, .fr].map { L10n.ui(.calCardIncomplete, $0) }, ["List may be incomplete", "Liste peut-être incomplète"])
    }

    func testOnlyTheCalendarToolMakesACardAndOldReadsSayWhen() {
        XCTAssertNil(CalendarCard.attach(thread(question: "free tomorrow?", tool: toolRow, name: "mail_list"), calendar: paris).last?.calendarCard)
        XCTAssertNil(CalendarCard.attach(thread(question: "free tomorrow?", tool: toolRow, name: ""), calendar: paris).last?.calendarCard)
        guard let card = CalendarCard.attach(thread(question: "free tomorrow?", tool: toolRow), calendar: paris).last?.calendarCard
        else { return XCTFail("no card") }
        XCTAssertNil(card.asOf(now: card.readAt.addingTimeInterval(240)))
        XCTAssertEqual(card.asOf(now: card.readAt.addingTimeInterval(360)), card.readAt)
    }

    func testTheCardSitsOnTheReplyAfterTheToolRowInTheThread() {
        let items = ThreadTimeline.build(agent: "calendar", messages: thread(question: "what's free tomorrow afternoon?", tool: toolRow),
                                         delegations: [], approvals: [], calendar: paris)
        let replies = items.flatMap { item -> [ChatMessage] in guard case .group(let group) = item, group.voice != .owner else { return [] }
            return group.entries.compactMap { if case .message(let message) = $0 { return message } else { return nil } } }
        XCTAssertEqual(replies.map(\.id), ["4"])
        XCTAssertEqual(replies.first?.calendarCard?.rows.count, 5)
    }

    func testAMessageWithNoCalendarResultRendersAsToday() {
        let plain = Array(thread(question: "what's free tomorrow?", tool: toolRow).prefix(2))
        XCTAssertEqual(CalendarCard.attach(plain, calendar: paris), plain)
        // Another tool, no access, a stale copy, an empty list or no named day: no card, prose only.
        let note = "Calendar copy is 3 days old.\n" + toolRow
        for (question, tool) in [("what's free tomorrow?", #"[{"uid":"7","subject":"Invoice","from":"a@example.test"}]"#),
                                 ("what's free tomorrow?", "Access not granted."), ("what's free tomorrow?", note),
                                 ("what's free tomorrow?", "[]"), ("when am I free?", toolRow)] {
            XCTAssertNil(CalendarCard.attach(thread(question: question, tool: tool), calendar: paris).last?.calendarCard, "\(question) / \(tool.prefix(30))")
        }
    }

    func testNamedDaysAndWeeksPickTheRightDays() {
        let friday = CalendarCard.window("Qu'est-ce que j'ai vendredi matin ?", now: asked, calendar: paris)
        XCTAssertEqual(friday.map { $0.days.map(clock) + ["\($0.from)-\($0.to)"] }, ["Fri 00:00", "8-12"])
        XCTAssertNil(CalendarCard.window("free tomorrow after lunch?", now: asked, calendar: paris))
        XCTAssertEqual(CalendarCard.window("et après-demain ?", now: asked, calendar: paris)?.days.map(clock), ["Sat 00:00"])
        XCTAssertEqual(CalendarCard.window("libre demain après-midi ?", now: asked, calendar: paris)?.days.map(clock), ["Fri 00:00"])
        let unread = ["Is Friday next week free?", "vendredi prochain ?", "Friday 6th?", "free this week?", "lundi 2 novembre",
                      "demain en huit ?", "jeudi en huit", "Friday fortnight?", "Friday the eighth?", "le vendredi treizième ?",
                      "the day after Friday?", "free before Monday?",
                      "demain dans deux jours ?", "Friday in three days?"]
        XCTAssertEqual(unread.filter { CalendarCard.window($0, now: asked, calendar: paris) != nil }, [])
    }

    /// CAL-PARSE-ALLOWLIST-1: the card shows only when every word of the question is understood.
    func testOnlyQuestionsTheCardFullyUnderstandsMakeACard() {
        let understood = [
            ("What's on tomorrow?", ["Fri 00:00", "9-18"]),
            ("Qu'est-ce que j'ai demain matin ?", ["Fri 00:00", "8-12"]),
            ("Am I free Friday afternoon?", ["Fri 00:00", "12-18"]),
            ("Do I have the Dupont meeting on Tuesday?", ["Tue 00:00", "9-18"]),
        ]
        for (question, expected) in understood {
            guard let window = CalendarCard.window(question, now: asked, calendar: paris) else {
                return XCTFail("no card for \(question)")
            }
            XCTAssertEqual(window.days.map(clock) + ["\(window.from)-\(window.to)"], expected, question)
        }
    }

    /// A word the card does not know means no card: a wrong day is worse than no card.
    func testAQuestionWithAWordTheCardDoesNotKnowMakesNoCard() {
        let notUnderstood = ["demain en huit", "Friday fortnight", "dans deux jours", "in two days", "next Monday",
                             "lundi prochain", "the week after", "tomorrow after 3pm", "le 12 novembre", "Monday the eighth",
                             "jeudi en quinze", "this weekend", "tomorrow or the day after next", "What did I do yesterday?",
                             "hier", "ce mois-ci",
                             // A word that turns the day around: the old deny-list let these through.
                             "any day except Friday", "everything but tomorrow", "not tomorrow", "instead of tomorrow",
                             "the day after the day after tomorrow"]
        XCTAssertEqual(notUnderstood.filter { CalendarCard.window($0, now: asked, calendar: paris) != nil }, [])
    }

    /// CAL-PARSE-ALLOWLIST-1 r2: a range of days is not one day. "Monday to Friday" would show Monday
    /// and Friday and hide Tuesday, Wednesday and Thursday: a wrong day is worse than no card.
    func testARangeOfDaysMakesNoCard() {
        XCTAssertNil(CalendarCard.window("Monday to Friday", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("du lundi au vendredi", now: asked, calendar: paris))
        // "on" and the day alone still work.
        XCTAssertEqual(CalendarCard.window("What do I have on Monday?", now: asked, calendar: paris)?.days.map(clock), ["Mon 00:00"])
        XCTAssertEqual(CalendarCard.window("Qu'ai-je lundi ?", now: asked, calendar: paris)?.days.map(clock), ["Mon 00:00"])
    }

    /// CAL-PARSE-ALLOWLIST-1 r2: "mon" is "my" in French and "Mon" is Monday in English. An English
    /// question that says "Mon" is a day the card cannot place: no card, never a wrong day.
    func testAnEnglishWeekdayAbbreviationIsNotAFrenchWord() {
        XCTAssertNil(CalendarCard.window("Am I free Mon or tomorrow?", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("Am I free Sat or tomorrow?", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("Free on Sat?", now: asked, calendar: paris))
        // A French question may say "mon" in lower case: "my agenda".
        XCTAssertEqual(CalendarCard.window("j'ai mon agenda demain ?", now: asked, calendar: paris)?.days.map(clock), ["Fri 00:00"])
        // "dans" is a date word ("dans deux jours"), not a question word: no card.
        XCTAssertNil(CalendarCard.window("Qu'est-ce que j'ai dans mon agenda demain ?", now: asked, calendar: paris))
    }

    /// CAL-PARSE-RANGE-2: a range of days is not one day. "Monday-Friday" would show Monday and
    /// Friday and hide Tuesday, Wednesday and Thursday, so the card shows nothing: we do not expand
    /// a range, a wrong day is worse than no card.
    func testAWeekdayRangeMakesNoCard() {
        for phrase in ["Monday-Friday", "Monday/Friday", "Monday – Friday", "Monday — Friday", "Monday ~ Friday",
                       "lundi-vendredi", "lundi à vendredi", "de lundi à vendredi",
                       "today-Monday?", "tomorrow to Monday", "demain à lundi", "aujourd'hui-vendredi"] {
            XCTAssertNil(CalendarCard.window(phrase, now: asked, calendar: paris), phrase)
        }
    }

    /// CAL-PARSE-RANGE-3: every dash Unicode writes joins the two ends of a range: the hyphen
    /// (U+002D), the figure dash (U+2012), the non-breaking hyphen (U+2011), the hyphen (U+2010),
    /// the horizontal bar (U+2015), the fullwidth hyphen (U+FF0D), the wave dash (U+301C) and the
    /// tilde operator (U+223C). "Monday‐Friday" would show Monday and Friday and hide Tuesday,
    /// Wednesday and Thursday: no card, a wrong day is worse than no card.
    func testAnyDashIsARangeAndMakesNoCard() {
        for phrase in ["Monday\u{2010}Friday?", "Monday\u{2011}Friday", "Monday\u{2012}Friday",
                       "Monday\u{2015}Friday", "Monday\u{FF0D}Friday", "lundi\u{301C}vendredi",
                       "Monday\u{223C}Friday"] {
            XCTAssertNil(CalendarCard.window(phrase, now: asked, calendar: paris), phrase)
        }
    }

    /// CAL-PARSE-RANGE-3: the hyphen of a French elision is not a range. "Qu'est-ce que j'ai demain
    /// et lundi ?" asks for two days, not for a range of days: the card shows tomorrow and Monday.
    func testTheHyphenOfAnElisionIsNotARange() {
        XCTAssertEqual(CalendarCard.window("Qu'est-ce que j'ai demain et lundi ?", now: asked, calendar: paris)?.days.map(clock),
                       ["Fri 00:00", "Mon 00:00"])
        XCTAssertEqual(CalendarCard.window("Y a-t-il quelque chose demain ?", now: asked, calendar: paris)?.days.map(clock),
                       ["Fri 00:00"])
    }

    /// CAL-PARSE-RANGE-2: "mon" is "my" in French and "Mon" is Monday in English. A question that
    /// mixes the two languages must not read "mon" as "my": the card would show tomorrow only and
    /// hide the Monday the owner asked about.
    func testAMixedLanguageMonGivesNoCard() {
        for phrase in ["Am I free on mon or tomorrow with the AI team?", "Am I free on mon or tomorrow with the AI?",
                       "Mon meeting demain", "Mon agenda demain ?", "Mon agenda ce soir", "Mon or Tue?",
                       "mon reunion tomorrow?", "mon chose tomorrow?"] {
            XCTAssertNil(CalendarCard.window(phrase, now: asked, calendar: paris), phrase)
        }
        // A French question may still say "mon" in lower case: "my agenda".
        XCTAssertEqual(CalendarCard.window("j'ai mon agenda demain ?", now: asked, calendar: paris)?.days.map(clock), ["Fri 00:00"])
    }

    /// CAL-PARSE-RANGE-2: the days the card still places after the range and the mixed-language fix.
    func testTheDaysTheCardStillPlaces() {
        // Two days named with no word or mark between them: both days, in calendar order.
        XCTAssertEqual(CalendarCard.window("Monday or Friday?", now: asked, calendar: paris)?.days.map(clock),
                       ["Fri 00:00", "Mon 00:00"])
        XCTAssertEqual(CalendarCard.window("Qu'est-ce que j'ai lundi ?", now: asked, calendar: paris)?.days.map(clock), ["Mon 00:00"])
        XCTAssertEqual(CalendarCard.window("Am I free tomorrow?", now: asked, calendar: paris)?.days.map(clock), ["Fri 00:00"])
        XCTAssertEqual(CalendarCard.window("Do I have the Dupont meeting on Tuesday?", now: asked, calendar: paris)?.days.map(clock), ["Tue 00:00"])
        // "dans" is a date word ("dans deux jours"), not a question word: no card, as before.
        XCTAssertNil(CalendarCard.window("j'ai quoi dans mon agenda demain", now: asked, calendar: paris))
    }

    /// CAL-PARSE-ALLOWLIST-1 r2: a capitalised function word is not a name. "Anything Except Tomorrow?"
    /// is not about tomorrow, it is about everything else: the card must not show a day.
    func testACapitalisedFunctionWordIsNotAName() {
        XCTAssertNil(CalendarCard.window("Anything Except Tomorrow?", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("Everything But Tomorrow?", now: asked, calendar: paris))
        XCTAssertEqual(CalendarCard.window("Do I have the Dupont meeting on Tuesday?", now: asked, calendar: paris)?.days.map(clock), ["Tue 00:00"])
    }

    /// A name is a capitalised word that is not the first one and not a date word.
    func testANameIsACapitalisedWordThatIsNotTheFirstOne() {
        XCTAssertNotNil(CalendarCard.window("Do I have the Dupont meeting on Tuesday?", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("Do I have the dupont meeting on Tuesday?", now: asked, calendar: paris))
        XCTAssertNil(CalendarCard.window("Zorglub?", now: asked, calendar: paris))
        XCTAssertEqual(CalendarCard.window("Tomorrow?", now: asked, calendar: paris)?.days.map(clock), ["Fri 00:00"])
    }

    func testCopyInEnglishAndFrench() {
        guard let card = CalendarCard.make(toolText: toolRow, question: "Qu'est-ce que j'ai demain ?", now: asked, readAt: asked, calendar: paris) else { return XCTFail("no card") }
        XCTAssertEqual([card.title(.en), card.title(.fr)], ["Your calendar", "Votre agenda"])
        XCTAssertEqual(CalendarCardModel(asksFree: true, rows: []).title(.fr), "Créneaux libres")
        guard let free = card.rows.first(where: { $0.kind == .free }) else { return XCTFail("no free") }
        XCTAssertEqual([CalendarCardModel.what(free, .en), CalendarCardModel.what(free, .fr)], ["Free", "Libre"])
        let allDay = CalendarCardRow(kind: .allDay, start: asked, end: asked, title: "Holiday")
        XCTAssertEqual([CalendarCardModel.time(allDay, .en), CalendarCardModel.time(allDay, .fr)], ["All day", "Toute la journée"])
        XCTAssertEqual(CalendarCardModel.day(free.start, .en, calendar: paris), "Fri 30 Oct")
        XCTAssertTrue(CalendarCardModel.day(free.start, .fr, calendar: paris).hasPrefix("ven"))
    }
}
