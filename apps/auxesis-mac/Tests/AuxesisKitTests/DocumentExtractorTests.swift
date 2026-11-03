// C2c: the pure extractor. Fixtures are generated in process; OCR runs on
// device with no socket anywhere in the path.
import XCTest
@testable import AuxesisKit
import Foundation
import PDFKit

@objcMembers @MainActor final class DocumentExtractorTests: XCTestCase {
    func testNativeTextPDFReturnsPDFTextWithTheExpectedWords() throws {
        let data = try DocsFixtures.textPDF(DocsFixtures.invoiceLine)
        let output = DocumentExtractor().extract(data: data, mime: "application/pdf")
        XCTAssertEqual(output.extractor, .pdfText)
        XCTAssertGreaterThan(output.pages, 0)
        XCTAssertTrue(output.text.contains("TOTAL TTC 42,00"), "got: \(output.text.prefix(160))")
        XCTAssertTrue(output.text.contains("Exemple SARL"))
    }

    func testImageWithRenderedTextReturnsOCRContainingIt() throws {
        let data = try DocsFixtures.textPNG("TOTAL TTC 42,00 EUR")
        let output = DocumentExtractor().extract(data: data, mime: "image/png")
        XCTAssertEqual(output.extractor, .ocr)
        XCTAssertEqual(output.pages, 1)
        let normalized = output.text.uppercased().replacingOccurrences(of: " ", with: "")
        XCTAssertTrue(normalized.contains("TOTAL"), "got: \(output.text)")
        XCTAssertTrue(normalized.contains("EUR"), "got: \(output.text)")
    }

    func testScannedPDFWithNoNativeTextFallsBackToOCR() throws {
        let data = try DocsFixtures.scannedPDF("TOTAL TTC 42,00 EUR")
        let output = DocumentExtractor().extract(data: data, mime: "application/pdf")
        XCTAssertEqual(output.extractor, .ocr)
        XCTAssertGreaterThan(output.pages, 0)
        let normalized = output.text.uppercased().replacingOccurrences(of: " ", with: "")
        XCTAssertTrue(normalized.contains("TOTAL"), "got: \(output.text)")
        XCTAssertTrue(normalized.contains("EUR"), "got: \(output.text)")
    }

    func testEncryptedPDFIsRefused() throws {
        let data = try DocsFixtures.encryptedPDF(DocsFixtures.invoiceLine)
        // The fixture really is encrypted, otherwise this proves nothing.
        guard let document = PDFDocument(data: data) else {
            return XCTFail("the encrypted fixture is not a PDF")
        }
        XCTAssertTrue(document.isEncrypted)
        XCTAssertEqual(DocumentExtractor().extract(data: data, mime: "application/pdf"), .none)
    }

    func testPageCountIsCappedAtTwoHundred() throws {
        let data = try DocsFixtures.manyPageTextPDF(
            pages: 205, text: DocsFixtures.invoiceLine,
            sentinel: "ZZZPAGE201ZZZ", sentinelPage: 200)
        let output = DocumentExtractor().extract(data: data, mime: "application/pdf")
        XCTAssertEqual(output.extractor, .pdfText)
        XCTAssertEqual(output.pages, DocumentExtractor.maxPages)
        XCTAssertFalse(output.text.contains("ZZZPAGE201ZZZ"), "page 201 must never be read")
    }

    func testHostileMediaBoxIsScaledDownToThePixelCap() {
        guard let plan = DocumentExtractor.renderPlan(width: 200_000, height: 200_000) else {
            return XCTFail("no render plan")
        }
        XCTAssertLessThanOrEqual(plan.width * plan.height, DocumentExtractor.maxPixels)
        XCTAssertLessThanOrEqual(plan.width, DocumentExtractor.maxRenderDimension)
        XCTAssertLessThanOrEqual(plan.height, DocumentExtractor.maxRenderDimension)
        // A zero-area box has no bitmap at all.
        XCTAssertNil(DocumentExtractor.renderPlan(width: 0, height: 100))
    }

    func testImageAboveThePixelCapIsRefused() throws {
        let oversize = try DocsFixtures.oversizeJPEG()
        // The header is readable and declares 6000 × 6000 = 36 M pixels.
        XCTAssertEqual(DocsFixtures.declaredPixelSize(oversize)?.width, 6000)
        XCTAssertEqual(DocsFixtures.declaredPixelSize(oversize)?.height, 6000)
        XCTAssertFalse(DocumentExtractor.imageWithinPixelCap(oversize))
        XCTAssertEqual(DocumentExtractor().extract(data: oversize, mime: "image/jpeg"), .none)
        // A normal image is still inside the cap.
        let normal = try DocsFixtures.textPNG("TOTAL TTC 42,00 EUR")
        XCTAssertTrue(DocumentExtractor.imageWithinPixelCap(normal))
    }

    func testExtractedTextIsCappedAtOneMiBEndToEnd() throws {
        let page = String(repeating: "FACTURE Exemple SARL 42,00 EUR ", count: 800) // 24 000 chars
        let data = try DocsFixtures.manyPageTextPDF(pages: 60, text: page, fontSize: 3)
        let output = DocumentExtractor().extract(data: data, mime: "application/pdf")
        XCTAssertEqual(output.extractor, .pdfText)
        XCTAssertEqual(output.text.utf8.count, DocumentExtractor.maxTextBytes)
    }

    func testGarbageBytesGiveNoneAndNeverCrash() {
        let extractor = DocumentExtractor()
        let garbage = Data([0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0x7F, 0x80])
        for mime in ["application/pdf", "image/png", "image/heic", "text/plain", nil] {
            let output = extractor.extract(data: garbage, mime: mime)
            XCTAssertEqual(output, .none, "mime \(mime ?? "nil")")
        }
        // A PDF magic prefix with a broken body is refused, not a crash.
        let brokenPDF = Data("%PDF-1.7 broken body".utf8)
        XCTAssertEqual(extractor.extract(data: brokenPDF, mime: "application/pdf"), .none)
    }

    func testOversizeInputIsRefusedBeforeParsing() {
        let oversize = Data(repeating: 0x41, count: DocumentExtractor.maxInputBytes + 1)
        XCTAssertEqual(DocumentExtractor().extract(data: oversize, mime: "application/pdf"), .none)
        XCTAssertEqual(DocumentExtractor().extract(data: oversize, mime: "image/png"), .none)
    }

    func testTextTruncatesOnACharacterBoundary() {
        let text = String(repeating: "é", count: 600_000) // 1.2 MiB of UTF-8
        let cut = DocumentExtractor.truncated(text, cap: 1000)
        XCTAssertLessThanOrEqual(cut.utf8.count, 1000)
        XCTAssertTrue(text.hasPrefix(cut))
        XCTAssertEqual(cut.count, 500, "two bytes per é, never half a character")
    }

    func testPageAccumulatorStopsRetainingTextAtTheWireCap() {
        var retained = ""
        DocumentExtractor.appendCapped(
            String(repeating: "é", count: DocumentExtractor.maxTextBytes), to: &retained)
        DocumentExtractor.appendCapped("must not be retained", to: &retained)

        XCTAssertEqual(retained.utf8.count, DocumentExtractor.maxTextBytes)
        XCTAssertFalse(retained.contains("must not be retained"))
    }

    func testTextRoomEndsNearTheWireCapSoLaterPagesAreNotRecognised() {
        XCTAssertTrue(DocumentExtractor.hasTextRoom(""))
        let nearlyFull = String(repeating: "a", count: DocumentExtractor.maxTextBytes - 3)
        XCTAssertFalse(DocumentExtractor.hasTextRoom(nearlyFull),
            "a cut just short of the cap must still stop the OCR page loop")
        var retained = ""
        DocumentExtractor.appendCapped(nearlyFull, to: &retained)
        DocumentExtractor.appendCapped("later page", to: &retained)
        XCTAssertFalse(retained.contains("later page"))
    }

    func testAccumulatorStillFillsTheSlackUpToTheHardCap() {
        var retained = String(repeating: "a", count: DocumentExtractor.maxTextBytes - 10)
        DocumentExtractor.appendCapped("x", to: &retained)
        XCTAssertEqual(retained.utf8.count, DocumentExtractor.maxTextBytes - 8)
    }
}
