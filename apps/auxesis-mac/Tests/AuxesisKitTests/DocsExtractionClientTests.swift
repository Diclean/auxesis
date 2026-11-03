// C2c: the real `AuxdClient` docs routes, over `RecordingURLProtocol` only — no
// socket. The bearer token and the loopback host are the client's existing
// rules; these tests pin the paths, the body and the decoding.
import XCTest
@testable import AuxesisKit
import Foundation

@objcMembers @MainActor final class DocsExtractionClientTests: XCTestCase {
    private func tempHome() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-docs-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func mockClient(home: URL) throws -> AuxdClient {
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: tokenFile, lockPID: nil, source: "test")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        return AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
    }

    private func response(_ request: URLRequest, _ status: Int, _ body: Data) -> (HTTPURLResponse, Data) {
        let http = HTTPURLResponse(
            url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        return (http, body)
    }

    /// A URLProtocol request carries the body as a stream; read it back.
    private static func body(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }

    func testPendingRouteDecodesClaimedDocumentsWithTheToken() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let hash = DocsFixtures.hashA
        RecordingURLProtocol.respond { request in
            self.response(
                request, 200,
                Data("[{\"hash\":\"\(hash)\",\"mime\":\"application/pdf\",\"size\":42}]".utf8))
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)

        let documents = try await client.pendingDocuments(limit: 3)
        XCTAssertEqual(documents, [PendingDocument(hash: hash, mime: "application/pdf", size: 42)])
        let record = RecordingURLProtocol.recorded.first
        XCTAssertEqual(record?.url, "http://127.0.0.1:2893/v1/docs/extract/pending?limit=3")
        XCTAssertEqual(record?.authorization, "Bearer deadbeef")
    }

    func testPendingLimitIsClampedToTheDaemonMaximum() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in self.response(request, 200, Data("[]".utf8)) }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        _ = try await client.pendingDocuments(limit: 10_000)
        XCTAssertEqual(
            RecordingURLProtocol.recorded.first?.url,
            "http://127.0.0.1:2893/v1/docs/extract/pending?limit=256")
    }

    func testBlobRouteFetchesTheClaimedBytes() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let hash = DocsFixtures.hashA
        let bytes = Data("fictional invoice bytes".utf8)
        RecordingURLProtocol.respond { request in
            XCTAssertEqual(request.url?.path, "/v1/docs/\(hash)/blob")
            return self.response(request, 200, bytes)
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        let fetched = try await client.documentBlob(sha256: hash)
        XCTAssertEqual(fetched, bytes)
    }

    func testBlobRouteRefusesAMalformedHashBeforeAnyRequest() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        do {
            _ = try await client.documentBlob(sha256: "not-a-hash")
            XCTFail("expected badURL")
        } catch {
            XCTAssertEqual(error as? AuxdError, .badURL)
        }
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty)
    }

    func testBlobRouteRefusesAnOversizeDeclaredLength() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let hash = DocsFixtures.hashA
        RecordingURLProtocol.respond { request in
            // The header alone already says the body is too large.
            let http = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
                headerFields: ["Content-Length": "\(DocumentExtractor.maxInputBytes + 1)"])!
            return (http, Data())
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        do {
            _ = try await client.documentBlob(sha256: hash)
            XCTFail("expected a too-large refusal")
        } catch {
            XCTAssertEqual(error as? AuxdError, .http(status: 413, body: ""))
        }
    }

    func testBlobRouteAbortsAStreamPastTheCap() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let hash = DocsFixtures.hashA
        let oversize = Data(repeating: 0x41, count: DocumentExtractor.maxInputBytes + 1)
        RecordingURLProtocol.respond { request in
            // No declared length: only the byte count can stop the body.
            let http = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (http, oversize)
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        do {
            _ = try await client.documentBlob(sha256: hash)
            XCTFail("expected a too-large refusal")
        } catch {
            XCTAssertEqual(error as? AuxdError, .http(status: 413, body: ""))
        }
    }

    func testPostExtractionSendsTheExactBodyToTheHashRoute() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let hash = DocsFixtures.hashA
        RecordingURLProtocol.respond { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/docs/\(hash)/extraction")
            guard let body = Self.body(of: request),
                  let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
            else {
                XCTFail("no JSON body")
                return self.response(request, 200, Data("{}".utf8))
            }
            // Exactly `{extractor, text, pages}`: the route denies unknown fields.
            XCTAssertEqual(Set(object.keys), ["extractor", "text", "pages"])
            XCTAssertEqual(object["extractor"] as? String, "ocr")
            XCTAssertEqual(object["text"] as? String, "TOTAL TTC 42,00 EUR")
            XCTAssertEqual(object["pages"] as? Int, 1)
            return self.response(request, 200, Data("{\"document_id\":7,\"checks\":[]}".utf8))
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        try await client.postExtraction(
            sha256: hash, extractor: .ocr, text: "TOTAL TTC 42,00 EUR", pages: 1)
        XCTAssertEqual(RecordingURLProtocol.recorded.count, 1)
    }

    func testPostExtractionSurfacesAConflictAsAnHTTPError() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            self.response(request, 409, Data("{\"error\":{\"code\":\"docs_not_claimed\"}}".utf8))
        }
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        do {
            try await client.postExtraction(
                sha256: DocsFixtures.hashA, extractor: .none, text: "", pages: 0)
            XCTFail("expected an HTTP error")
        } catch {
            XCTAssertEqual(error as? AuxdError, .http(status: 409, body: "{\"error\":{\"code\":\"docs_not_claimed\"}}"))
        }
    }
}
