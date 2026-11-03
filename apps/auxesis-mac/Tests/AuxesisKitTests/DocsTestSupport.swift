// C2c test support: fictional fixtures built in process and a scripted,
// in-process auxd. No socket, no URLProtocol, no real home.
import AppKit
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import PDFKit
import UniformTypeIdentifiers
@testable import AuxesisKit

enum DocsFixtureError: Error {
    case graphics
    case encode
}

enum DocsFixtures {
    static let hashA = String(repeating: "a", count: 64)
    static let hashB = String(repeating: "b", count: 64)
    static let invoiceLine = "FACTURE Exemple SARL TOTAL TTC 42,00 EUR"

    /// One page of real, extractable text (CoreGraphics + CoreText; nothing on
    /// disk).
    static func textPDF(_ text: String) throws -> Data {
        let data = NSMutableData()
        var mediaBox = CGRect(x: 0, y: 0, width: 612, height: 792)
        guard let consumer = CGDataConsumer(data: data),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil)
        else { throw DocsFixtureError.graphics }
        context.beginPDFPage(nil)
        let font = CTFontCreateWithName("Helvetica" as CFString, 24, nil)
        let attributed = NSAttributedString(
            string: text,
            attributes: [.font: font, .foregroundColor: CGColor(gray: 0, alpha: 1)])
        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        let path = CGPath(rect: CGRect(x: 40, y: 420, width: 520, height: 260), transform: nil)
        let frame = CTFramesetterCreateFrame(framesetter, CFRangeMake(0, 0), path, nil)
        CTFrameDraw(frame, context)
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    /// A PNG with the text drawn large enough for Vision to read.
    static func textPNG(_ text: String, width: Int = 1000, height: Int = 260) throws -> Data {
        guard let context = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { throw DocsFixtureError.graphics }
        context.setFillColor(CGColor(gray: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let font = CTFontCreateWithName("Helvetica-Bold" as CFString, 80, nil)
        let attributed = NSAttributedString(
            string: text,
            attributes: [.font: font, .foregroundColor: CGColor(gray: 0, alpha: 1)])
        context.textPosition = CGPoint(x: 30, y: 90)
        CTLineDraw(CTLineCreateWithAttributedString(attributed), context)
        guard let image = context.makeImage() else { throw DocsFixtureError.graphics }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            out, UTType.png.identifier as CFString, 1, nil)
        else { throw DocsFixtureError.encode }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw DocsFixtureError.encode }
        return out as Data
    }

    /// A one-page PDF that carries only an image of the text (a scan): PDFKit
    /// finds no native text, so the extractor must OCR the rendered page.
    static func scannedPDF(_ text: String) throws -> Data {
        guard let image = NSImage(data: try textPNG(text)) else { throw DocsFixtureError.encode }
        guard let page = PDFPage(image: image) else { throw DocsFixtureError.graphics }
        let document = PDFDocument()
        document.insert(page, at: 0)
        guard let data = document.dataRepresentation() else { throw DocsFixtureError.encode }
        return data
    }

    /// A password-protected PDF: the extractor must refuse it, never guess.
    static func encryptedPDF(_ text: String) throws -> Data {
        let data = NSMutableData()
        var mediaBox = CGRect(x: 0, y: 0, width: 612, height: 792)
        let options: [CFString: Any] = [
            kCGPDFContextEncryptionKeyLength: 128,
            kCGPDFContextOwnerPassword: "Exemple-owner",
            kCGPDFContextUserPassword: "Exemple-user",
        ]
        guard let consumer = CGDataConsumer(data: data),
              let context = CGContext(
                consumer: consumer, mediaBox: &mediaBox, options as CFDictionary)
        else { throw DocsFixtureError.graphics }
        context.beginPDFPage(nil)
        Self.draw(text, in: context, fontSize: 24, rect: CGRect(x: 40, y: 420, width: 520, height: 260))
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    /// A text PDF with `pages` pages, optionally drawing `sentinel` on
    /// `sentinelPage` (zero-based). Used for the page cap and the text cap.
    static func manyPageTextPDF(
        pages: Int,
        text: String,
        sentinel: String? = nil,
        sentinelPage: Int? = nil,
        fontSize: CGFloat = 6
    ) throws -> Data {
        let data = NSMutableData()
        var mediaBox = CGRect(x: 0, y: 0, width: 612, height: 792)
        guard let consumer = CGDataConsumer(data: data),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil)
        else { throw DocsFixtureError.graphics }
        let body = CGPath(rect: CGRect(x: 10, y: 10, width: 560, height: 740), transform: nil)
        let sentinelPath = CGPath(rect: CGRect(x: 10, y: 758, width: 560, height: 30), transform: nil)
        for index in 0..<pages {
            context.beginPDFPage(nil)
            Self.draw(text, in: context, fontSize: fontSize, path: body)
            if index == sentinelPage, let sentinel {
                Self.draw(sentinel, in: context, fontSize: fontSize, path: sentinelPath)
            }
            context.endPDFPage()
        }
        context.closePDF()
        return data as Data
    }

    /// A real JPEG whose SOF marker declares 6000 × 6000 = 36 M pixels, above
    /// the shared 25 M-pixel cap, with no need to allocate the bitmap. `ImageIO`
    /// reads the dimensions from the header without decoding the scan.
    static func oversizeJPEG(width: UInt16 = 6000, height: UInt16 = 6000) throws -> Data {
        guard let context = CGContext(
            data: nil, width: 1, height: 1, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
            let image = context.makeImage()
        else { throw DocsFixtureError.graphics }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            out, UTType.jpeg.identifier as CFString, 1, nil)
        else { throw DocsFixtureError.encode }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw DocsFixtureError.encode }

        var bytes = [UInt8](out as Data)
        // SOF0: FF C0, length(2), precision(1), height(2), width(2), …
        guard let sof = bytes.indices.first(where: { index in
            index + 8 < bytes.count && bytes[index] == 0xFF && bytes[index + 1] == 0xC0
        }) else { throw DocsFixtureError.encode }
        func highLow(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)] }
        bytes.replaceSubrange(sof + 5..<sof + 7, with: highLow(height))
        bytes.replaceSubrange(sof + 7..<sof + 9, with: highLow(width))
        return Data(bytes)
    }

    /// The dimensions an image header declares, without decoding.
    static func declaredPixelSize(_ data: Data) -> (width: Int, height: Int)? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil)
                as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? Int,
              let height = properties[kCGImagePropertyPixelHeight] as? Int
        else { return nil }
        return (width, height)
    }

    private static func draw(_ text: String, in context: CGContext, fontSize: CGFloat, rect: CGRect) {
        draw(text, in: context, fontSize: fontSize, path: CGPath(rect: rect, transform: nil))
    }

    private static func draw(_ text: String, in context: CGContext, fontSize: CGFloat, path: CGPath) {
        let font = CTFontCreateWithName("Helvetica" as CFString, fontSize, nil)
        let attributed = NSAttributedString(
            string: text,
            attributes: [.font: font, .foregroundColor: CGColor(gray: 0, alpha: 1)])
        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        let frame = CTFramesetterCreateFrame(framesetter, CFRangeMake(0, 0), path, nil)
        CTFrameDraw(frame, context)
    }
}

/// A scripted auxd: `pending` / `blob` / `post` answers set per test. Locked,
/// because a started worker calls it from its own task.
final class FakeDocsAuxd: DocsExtractionClient {
    struct Post: Equatable {
        let sha256: String
        let extractor: ExtractionKind
        let text: String
        let pages: Int
    }

    private let lock = NSLock()
    private var _pendingResult: Result<[PendingDocument], Error> = .success([])
    private var _blobs: [String: Result<Data, Error>] = [:]
    private var _postResult: Result<Void, Error> = .success(())
    private var _pendingCalls: [Int] = []
    private var _blobCalls: [String] = []
    private var _posts: [Post] = []

    var pendingResult: Result<[PendingDocument], Error> {
        get { lock.withLock { _pendingResult } }
        set { lock.withLock { _pendingResult = newValue } }
    }
    var blobs: [String: Result<Data, Error>] {
        get { lock.withLock { _blobs } }
        set { lock.withLock { _blobs = newValue } }
    }
    var postResult: Result<Void, Error> {
        get { lock.withLock { _postResult } }
        set { lock.withLock { _postResult = newValue } }
    }
    var pendingCalls: [Int] { lock.withLock { _pendingCalls } }
    var blobCalls: [String] { lock.withLock { _blobCalls } }
    var posts: [Post] { lock.withLock { _posts } }

    func pendingDocuments(limit: Int) async throws -> [PendingDocument] {
        try lock.withLock {
            _pendingCalls.append(limit)
            return try _pendingResult.get()
        }
    }

    func documentBlob(sha256: String) async throws -> Data {
        try lock.withLock {
            _blobCalls.append(sha256)
            // An unregistered hash is an expired claim: auxd answers 404.
            return try (_blobs[sha256] ?? .failure(AuxdError.http(status: 404, body: ""))).get()
        }
    }

    func postExtraction(
        sha256: String, extractor: ExtractionKind, text: String, pages: Int
    ) async throws {
        try lock.withLock {
            _posts.append(Post(sha256: sha256, extractor: extractor, text: text, pages: pages))
            return try _postResult.get()
        }
    }
}

/// Lock-protected event recorder: the worker's loop may report off-main.
final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [ExtractionEvent] = []

    var events: [ExtractionEvent] { lock.withLock { stored } }
    func record(_ event: ExtractionEvent) { lock.withLock { stored.append(event) } }
}
