// ReleaseSigner — the offline release-manifest signer.
//
// It is a SwiftPM executable target, not part of Auxesis.app: the app only
// ever holds the public key. CryptoKit's Ed25519 is the whole dependency set.
//
// Key file format: base64 of the 32-byte raw key, one trailing newline.
// The private key must be mode 0600 (no group/other bits) or signing refuses.
//
//   ReleaseSigner generate <key-path>
//   ReleaseSigner sign <key-path> <manifest.json> [<out.sig>]
//   ReleaseSigner verify <public-key-path> <manifest.json> <sig>
//
// The release flow around it — the manifest, the feed, the update — is in
// docs/releasing.md.
import CryptoKit
import Foundation

enum SignerError: Error, CustomStringConvertible {
    case usage(String)
    case message(String)

    var description: String {
        switch self {
        case .usage(let text): return text
        case .message(let text): return text
        }
    }
}

func readBase64File(_ path: String) throws -> Data {
    let text: String
    do {
        text = try String(contentsOfFile: path, encoding: .utf8)
    } catch {
        throw SignerError.message("cannot read \(path): \(error.localizedDescription)")
    }
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = Data(base64Encoded: trimmed) else {
        throw SignerError.message("\(path) is not base64")
    }
    return data
}

/// Refuse a key any other user on the machine could read.
func assertPrivateKeyMode(_ path: String) throws {
    let attributes: [FileAttributeKey: Any]
    do {
        attributes = try FileManager.default.attributesOfItem(atPath: path)
    } catch {
        throw SignerError.message("cannot stat \(path): \(error.localizedDescription)")
    }
    let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    if mode & 0o077 != 0 {
        throw SignerError.message(
            "refusing \(path): mode \(String(mode, radix: 8)) lets group/other read the key; expected 0600")
    }
}

func generate(keyPath: String) throws {
    if FileManager.default.fileExists(atPath: keyPath) {
        throw SignerError.message("refusing to overwrite existing \(keyPath)")
    }
    let key = Curve25519.Signing.PrivateKey()
    let privateText = key.rawRepresentation.base64EncodedString() + "\n"
    let publicText = key.publicKey.rawRepresentation.base64EncodedString() + "\n"
    guard FileManager.default.createFile(
        atPath: keyPath,
        contents: Data(privateText.utf8),
        attributes: [.posixPermissions: 0o600]
    ) else {
        throw SignerError.message("cannot write \(keyPath)")
    }
    // createFile honours the attributes, but set them again to be explicit.
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
    let publicPath = keyPath + ".pub"
    do {
        try Data(publicText.utf8).write(to: URL(fileURLWithPath: publicPath))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicPath)
    } catch {
        throw SignerError.message("cannot write \(publicPath): \(error.localizedDescription)")
    }
    print("wrote \(keyPath) (0600) and \(publicPath)")
    print("public key: \(key.publicKey.rawRepresentation.base64EncodedString())")
}

func sign(keyPath: String, manifestPath: String, outPath: String) throws {
    try assertPrivateKeyMode(keyPath)
    let raw = try readBase64File(keyPath)
    let key: Curve25519.Signing.PrivateKey  // gitleaks:allow
    do {
        key = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    } catch {
        throw SignerError.message("\(keyPath) is not a 32-byte Ed25519 private key")
    }
    let message: Data
    do {
        message = try Data(contentsOf: URL(fileURLWithPath: manifestPath))
    } catch {
        throw SignerError.message("cannot read \(manifestPath): \(error.localizedDescription)")
    }
    let signature = try key.signature(for: message)
    do {
        try Data((signature.base64EncodedString() + "\n").utf8).write(to: URL(fileURLWithPath: outPath))
    } catch {
        throw SignerError.message("cannot write \(outPath): \(error.localizedDescription)")
    }
    print("signed \(manifestPath) -> \(outPath) (\(signature.count) bytes)")
}

func verify(publicKeyPath: String, manifestPath: String, signaturePath: String) throws -> Bool {
    let raw = try readBase64File(publicKeyPath)
    let key: Curve25519.Signing.PublicKey
    do {
        key = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    } catch {
        throw SignerError.message("\(publicKeyPath) is not a 32-byte Ed25519 public key")
    }
    guard let signature = Data(base64Encoded: try String(contentsOfFile: signaturePath, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)) else {
        throw SignerError.message("\(signaturePath) is not base64")
    }
    let message: Data
    do {
        message = try Data(contentsOf: URL(fileURLWithPath: manifestPath))
    } catch {
        throw SignerError.message("cannot read \(manifestPath): \(error.localizedDescription)")
    }
    let ok = key.isValidSignature(signature, for: message)
    print(ok ? "signature OK" : "signature INVALID")
    return ok
}

func main() throws -> Int32 {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let rawCommand = arguments.first else {
        throw SignerError.usage(
            "usage: ReleaseSigner generate|sign|verify … (see scripts/sign-release.sh, docs/releasing.md)")
    }
    // Accept both `generate` and `--generate`.
    let command = rawCommand.hasPrefix("--") ? String(rawCommand.dropFirst(2)) : rawCommand
    switch command {
    case "generate":
        guard arguments.count == 2 else {
            throw SignerError.usage("usage: ReleaseSigner generate <key-path>")
        }
        try generate(keyPath: arguments[1])
        return 0
    case "sign":
        guard arguments.count == 3 || arguments.count == 4 else {
            throw SignerError.usage("usage: ReleaseSigner sign <key-path> <manifest.json> [<out.sig>]")
        }
        let out = arguments.count == 4 ? arguments[3] : arguments[2] + ".sig"
        try sign(keyPath: arguments[1], manifestPath: arguments[2], outPath: out)
        return 0
    case "verify":
        guard arguments.count == 4 else {
            throw SignerError.usage("usage: ReleaseSigner verify <public-key-path> <manifest.json> <sig>")
        }
        return try verify(
            publicKeyPath: arguments[1], manifestPath: arguments[2], signaturePath: arguments[3]) ? 0 : 1
    default:
        throw SignerError.usage("unknown command '\(command)'; expected generate, sign or verify")
    }
}

do {
    exit(try main())
} catch {
    FileHandle.standardError.write(Data("ReleaseSigner: \(error)\n".utf8))
    exit(2)
}
