// The Mac extraction unit (C2c): PDFKit native text first,
// then Vision OCR on rendered pages or on an image. Pure and synchronous:
// bytes in, `{extractor, text, pages}` out, never a throw and never a crash on
// malformed input.
//
// Privacy: this file uses no networking API of any kind — no Foundation
// session, no Network framework, no low-level network module. `VNRecognizeTextRequest`
// runs on device; the text never leaves the process except through
// `ExtractionWorker`'s loopback post.
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import PDFKit
import Vision

/// The extractor spelling auxd stores (`xml` is Rust-only and never the
/// bridge's to send).
public enum ExtractionKind: String, Equatable, Sendable {
    case pdfText = "pdf_text"
    case ocr = "ocr"
    case none = "none"
}

/// One extraction result: the extractor that answered, its text, and how many
/// pages it read (`0` when nothing was extracted).
public struct ExtractionOutput: Equatable, Sendable {
    public let extractor: ExtractionKind
    public let text: String
    public let pages: Int

    public init(extractor: ExtractionKind, text: String, pages: Int) {
        self.extractor = extractor
        self.text = text
        self.pages = pages
    }

    /// The honest "nothing extracted" answer.
    public static let none = ExtractionOutput(extractor: .none, text: "", pages: 0)
}

/// Pure, testable extraction. No stored state, no I/O.
public struct DocumentExtractor {
    /// One evidence item is at most 25 MiB. Enforced before
    /// any parser sees a byte.
    public static let maxInputBytes = 25 * 1024 * 1024
    /// `aux_docs::MAX_TEXT_BYTES`: the daemon refuses a larger extraction body.
    public static let maxTextBytes = 1024 * 1024
    /// Hostile mail PDFs can be enormous; only the first 200 pages are read.
    public static let maxPages = 200
    /// Under this many non-space characters per page on average, the native
    /// text is not text: the page is a scan and OCR takes over.
    public static let minimumNativeCharactersPerPage = 20
    /// OCR a rendered PDF page at about 2x so Vision has enough pixels.
    public static let renderScale: CGFloat = 2
    /// A hostile media box or a hostile image header must not allocate a
    /// gigapixel bitmap: at most 25 M pixels in total (about 100 MB at 4
    /// bytes/pixel), shared by rendered pages and decoded images.
    public static let maxPixels = 25_000_000
    /// And a rendered page may be at most 20 000 pixels on either side.
    public static let maxRenderDimension = 20_000
    /// French first, then English: the owner's documents.
    public static let ocrLanguages = ["fr-FR", "en-US"]

    public init() {}

    /// Extract one document. `nil`/unknown MIME is sniffed from the bytes.
    public func extract(data: Data, mime: String?) -> ExtractionOutput {
        guard data.count <= Self.maxInputBytes else { return .none }
        switch Self.inputKind(mime: mime, data: data) {
        case .pdf: return extractPDF(data)
        case .image: return extractImage(data)
        case .unknown: return .none
        }
    }

    // MARK: - PDF

    private func extractPDF(_ data: Data) -> ExtractionOutput {
        guard let document = PDFDocument(data: data) else { return .none }
        // Encrypted or locked documents are refused, never guessed at.
        guard !document.isEncrypted, !document.isLocked else { return .none }
        let pageCount = min(document.pageCount, Self.maxPages)
        guard pageCount > 0 else { return .none }

        var text = ""
        var characters = 0
        for index in 0..<pageCount {
            let pageText = document.page(at: index)?.string ?? ""
            characters += Self.nonSpaceCount(pageText)
            Self.appendCapped(pageText, to: &text)
        }
        if characters >= pageCount * Self.minimumNativeCharactersPerPage {
            guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .none }
            return ExtractionOutput(
                extractor: .pdfText, text: text, pages: pageCount)
        }
        // A scan: render the pages and OCR them.
        return ocrPDFPages(document, pageCount: pageCount)
    }

    private func ocrPDFPages(_ document: PDFDocument, pageCount: Int) -> ExtractionOutput {
        var text = ""
        for index in 0..<pageCount {
            // Once the text cap is reached, later pages would be discarded, so
            // stop rendering and recognising them.
            guard Self.hasTextRoom(text) else { break }
            // One page's bitmap and Vision objects are released before the next
            // page: a 200-page scan must not accumulate them.
            autoreleasepool {
                guard let page = document.page(at: index), let image = Self.render(page) else {
                    return
                }
                Self.appendCapped(Self.recognize(cgImage: image) ?? "", to: &text)
            }
        }
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .none }
        return ExtractionOutput(
            extractor: .ocr, text: text, pages: pageCount)
    }

    /// Render one PDF page to a bitmap; nil on any failure. The bitmap size is
    /// bounded by `renderPlan`, so a hostile media box cannot ask for gigabytes.
    static func render(_ page: PDFPage) -> CGImage? {
        let bounds = page.bounds(for: .mediaBox)
        guard let plan = renderPlan(width: bounds.width, height: bounds.height) else { return nil }
        guard let context = CGContext(
            data: nil, width: plan.width, height: plan.height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
        ) else { return nil }
        context.setFillColor(CGColor(gray: 1, alpha: 1))
        context.fill(
            CGRect(x: 0, y: 0, width: CGFloat(plan.width), height: CGFloat(plan.height)))
        context.scaleBy(x: plan.scale, y: plan.scale)
        context.translateBy(x: -bounds.origin.x, y: -bounds.origin.y)
        page.draw(with: .mediaBox, to: context)
        return context.makeImage()
    }

    /// The bitmap size for one page: `renderScale` when that fits, otherwise
    /// scaled down so `width × height ≤ maxPixels` and neither side exceeds
    /// `maxRenderDimension`. Pure, so the cap is testable without allocating.
    static func renderPlan(width: CGFloat, height: CGFloat)
        -> (width: Int, height: Int, scale: CGFloat)?
    {
        guard width > 0, height > 0, width.isFinite, height.isFinite else { return nil }
        var scale = renderScale
        let pixels = Double(width) * Double(height) * Double(scale) * Double(scale)
        guard pixels > 0, pixels.isFinite else { return nil }
        if pixels > Double(maxPixels) {
            scale *= CGFloat((Double(maxPixels) / pixels).squareRoot())
        }
        let scaledWidth = Double(width) * Double(scale)
        if scaledWidth > Double(maxRenderDimension) {
            scale *= CGFloat(Double(maxRenderDimension) / scaledWidth)
        }
        let scaledHeight = Double(height) * Double(scale)
        if scaledHeight > Double(maxRenderDimension) {
            scale *= CGFloat(Double(maxRenderDimension) / scaledHeight)
        }
        // Floor the sides so rounding can never push the product over the cap.
        let pixelWidth = max(1, Int((Double(width) * Double(scale)).rounded(.down)))
        let pixelHeight = max(1, Int((Double(height) * Double(scale)).rounded(.down)))
        return (pixelWidth, pixelHeight, scale)
    }

    // MARK: - Images

    private func extractImage(_ data: Data) -> ExtractionOutput {
        guard Self.imageWithinPixelCap(data) else { return .none }
        guard let text = Self.recognize(data: data) else { return .none }
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .none }
        return ExtractionOutput(extractor: .ocr, text: Self.truncated(text), pages: 1)
    }

    /// Read the declared pixel dimensions from the image header before Vision
    /// decodes anything. An image above the shared 25 M-pixel cap is refused,
    /// exactly like a hostile PDF page.
    static func imageWithinPixelCap(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil)
                as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? Int,
              let height = properties[kCGImagePropertyPixelHeight] as? Int,
              width > 0, height > 0
        else { return false }
        // Double, so a hostile header cannot overflow the comparison.
        return Double(width) * Double(height) <= Double(Self.maxPixels)
    }

    // MARK: - Vision

    /// One accurate, on-device text request with an explicit revision.
    static func textRequest() -> VNRecognizeTextRequest {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = true
        request.recognitionLanguages = ocrLanguages
        request.revision = VNRecognizeTextRequestRevision3
        return request
    }

    static func recognize(cgImage: CGImage) -> String? {
        let request = textRequest()
        do {
            try VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
        } catch {
            return nil
        }
        return recognizedText(request)
    }

    static func recognize(data: Data) -> String? {
        let request = textRequest()
        do {
            try VNImageRequestHandler(data: data, options: [:]).perform([request])
        } catch {
            return nil
        }
        return recognizedText(request)
    }

    private static func recognizedText(_ request: VNRecognizeTextRequest) -> String {
        (request.results ?? [])
            .compactMap { $0.topCandidates(1).first?.string }
            .joined(separator: "\n")
    }

    // MARK: - Shapes and caps

    enum InputKind { case pdf, image, unknown }

    static func inputKind(mime: String?, data: Data) -> InputKind {
        switch normalizedMime(mime) {
        case "application/pdf", "application/x-pdf": return .pdf
        case let value where value.hasPrefix("image/"): return .image
        default: break
        }
        if data.prefix(4).elementsEqual(Array("%PDF".utf8)) { return .pdf }
        if looksLikeImage(data) { return .image }
        return .unknown
    }

    static func normalizedMime(_ mime: String?) -> String {
        guard let mime else { return "" }
        let lowered = mime.lowercased()
        return lowered.split(separator: ";", maxSplits: 1).first
            .map { $0.trimmingCharacters(in: .whitespaces) } ?? lowered
    }

    static func looksLikeImage(_ data: Data) -> Bool {
        let bytes = [UInt8](data.prefix(12))
        if bytes.count >= 3, bytes[0] == 0xFF, bytes[1] == 0xD8, bytes[2] == 0xFF { return true }
        if bytes.count >= 8, bytes[0] == 0x89, bytes[1] == 0x50, bytes[2] == 0x4E, bytes[3] == 0x47 {
            return true
        }
        if bytes.count >= 4, bytes[0] == 0x49, bytes[1] == 0x49, bytes[2] == 0x2A, bytes[3] == 0x00 {
            return true
        }
        if bytes.count >= 4, bytes[0] == 0x4D, bytes[1] == 0x4D, bytes[2] == 0x00, bytes[3] == 0x2A {
            return true
        }
        // HEIC/HEIF are ISO BMFF: `ftyp` at byte 4.
        if bytes.count >= 8, bytes[4] == 0x66, bytes[5] == 0x74, bytes[6] == 0x79, bytes[7] == 0x70 {
            return true
        }
        return false
    }

    static func nonSpaceCount(_ text: String) -> Int {
        text.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) }.count
    }

    /// Whether more page text can still be retained under the wire text cap.
    /// A few bytes of slack count as full: a cut on a character boundary can
    /// stop just short of the cap, and that tail is never worth another page.
    static func hasTextRoom(_ text: String) -> Bool {
        text.utf8.count < maxTextBytes - 16
    }

    /// Retain at most the wire text cap while walking pages. PDFKit and Vision
    /// may each produce a large single-page String, but completed pages are
    /// discarded instead of accumulating up to 200 pages in memory.
    static func appendCapped(_ page: String, to text: inout String) {
        guard !page.isEmpty, text.utf8.count < maxTextBytes else { return }
        if !text.isEmpty {
            text.append("\n")
        }
        let remaining = maxTextBytes - text.utf8.count
        text.append(truncated(page, cap: remaining))
    }

    /// Truncate to `cap` UTF-8 bytes without splitting a character.
    static func truncated(_ text: String, cap: Int = DocumentExtractor.maxTextBytes) -> String {
        guard text.utf8.count > cap else { return text }
        var used = 0
        var end = text.startIndex
        for index in text.indices {
            let next = text.index(after: index)
            let size = text[index..<next].utf8.count
            if used + size > cap { break }
            used += size
            end = next
        }
        return String(text[text.startIndex..<end])
    }
}
