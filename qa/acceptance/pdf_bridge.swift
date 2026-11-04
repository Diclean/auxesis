// The PDFKit half of the receipt-collection acceptance: it does what the Mac
// app's `ExtractionWorker` does — claim one pending document, read its bytes,
// extract the text with PDFKit (the app's own extractor) and post it back —
// so the demo receipt is read by the real Mac extractor, not by a stand-in.
//
//   pdf_bridge <base-url>
//
// The token comes from AUX_BRIDGE_TOKEN in the environment, never from the
// command line.
import Foundation
import PDFKit

let base = URL(string: CommandLine.arguments[1])!
let token = ProcessInfo.processInfo.environment["AUX_BRIDGE_TOKEN"]!

/// One authenticated call to the daemon's loopback API.
func call(_ method: String, _ path: String, _ body: Data? = nil) -> Data? {
    var request = URLRequest(url: URL(string: path, relativeTo: base)!.absoluteURL)
    request.httpMethod = method
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.httpBody = body
    var out = Data()
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: request) { data, _, _ in
        out = data ?? Data()
        done.signal()
    }.resume()
    return done.wait(timeout: .now() + 30) == .timedOut ? nil : out
}

while true {
    guard let data = call("GET", "/v1/docs/extract/pending?limit=1"),
          let pending = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
          let hash = (pending.first?["hash"] as? String),
          let blob = call("GET", "/v1/docs/\(hash)/blob"), !blob.isEmpty else {
        Thread.sleep(forTimeInterval: 0.02)
        continue
    }
    var text = ""
    var pages = 0
    if let pdf = PDFDocument(data: blob) {
        pages = pdf.pageCount
        text = (0..<pages)
            .map { pdf.page(at: $0)?.string ?? "" }
            .joined(separator: "\n")
    }
    let body = try? JSONSerialization.data(withJSONObject: [
        "extractor": text.isEmpty ? "none" : "pdf_text",
        "text": text,
        "pages": pages,
    ])
    _ = call("POST", "/v1/docs/\(hash)/extraction", body)
}
