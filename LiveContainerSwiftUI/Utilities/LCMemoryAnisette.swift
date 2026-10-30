import Foundation
import CryptoKit
import StosSign_Common

// Anisette v3 provisioning for the separate Apple sign-in used by memory setup.
// The anisette service receives provisioning messages, never the Apple password.
// Authentication/provisioning material stays in memory for this setup screen.
final class LCMemoryAnisette {
    private let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 90
        return URLSession(configuration: config)
    }()
    private let identifier = UUID()
    private var provisioningBlob: String?
    private var clientInfo = ""
    private var userAgent = ""
    private var localUser: String {
        var uuid = identifier.uuid
        return SHA256.hash(data: withUnsafeBytes(of: &uuid) { Data($0) })
            .map { String(format: "%02X", $0) }.joined()
    }
    private var encodedIdentifier: String {
        var uuid = identifier.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }.base64EncodedString()
    }

    func headers(server: URL) async throws -> AnisetteData {
        let info = try await json(URLRequest(url: server.appendingPathComponent("v3/client_info")))
        guard let client = info["client_info"] as? String, let agent = info["user_agent"] as? String else {
            throw LCMemoryCapabilityRequest.failure("The server does not provide Anisette v3 client information.")
        }
        // Older v3 servers advertise an obsolete AuthKit client. Use the same
        // contemporary client identity as the pinned StosSign/GetMoreRam flow.
        clientInfo = client.contains("<macOS;27.") ? client : "<iMac18,3> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        userAgent = client.contains("<macOS;27.") ? agent : "AuthKit/1 (Macintosh; OS X 27.0) (com.apple.akd/1.0)"
        if provisioningBlob == nil { try await provision(server: server) }
        guard let blob = provisioningBlob else { throw LCMemoryCapabilityRequest.failure("Anisette provisioning did not complete.") }
        var request = URLRequest(url: server.appendingPathComponent("v3/get_headers"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["identifier": encodedIdentifier, "adi_pb": blob])
        let response = try await json(request)
        guard let machine = response["X-Apple-I-MD-M"] as? String,
              let otp = response["X-Apple-I-MD"] as? String,
              let routing = response["X-Apple-I-MD-RINFO"].map({ String(describing: $0) }),
              let routingNumber = UInt64(routing) else {
            provisioningBlob = nil
            throw LCMemoryCapabilityRequest.failure("Anisette headers were unavailable. Try signing in again.")
        }
        return AnisetteData(machineID: machine, oneTimePassword: otp, localUserID: localUser,
                            routingInfo: routingNumber, deviceUniqueIdentifier: identifier.uuidString,
                            deviceSerialNumber: "0", deviceDescription: clientInfo, date: Date(),
                            locale: .current, timeZone: .current)
    }

    private func provision(server: URL) async throws {
        let lookup = try await applePlist(url: URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!)
        guard let urls = lookup["urls"] as? [String: Any],
              let start = urls["midStartProvisioning"] as? String, let startURL = URL(string: start),
              let finish = urls["midFinishProvisioning"] as? String, let finishURL = URL(string: finish),
              isAppleURL(startURL), isAppleURL(finishURL) else {
            throw LCMemoryCapabilityRequest.failure("Apple did not return valid provisioning endpoints.")
        }
        var components = URLComponents(url: server.appendingPathComponent("v3/provisioning_session"), resolvingAgainstBaseURL: false)!
        components.scheme = "wss"
        let socket = session.webSocketTask(with: components.url!)
        socket.resume()
        let deadline = Task {
            do { try await Task.sleep(nanoseconds: 90_000_000_000) }
            catch { return }
            socket.cancel(with: .goingAway, reason: nil)
        }
        defer { deadline.cancel(); socket.cancel(with: .normalClosure, reason: nil) }
        try await withTaskCancellationHandler(operation: {
            for _ in 0..<12 {
                try Task.checkCancellation()
                let message = try await socket.receive()
                guard case .string(let text) = message,
                      let data = text.data(using: .utf8),
                      let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let result = json["result"] as? String else {
                    throw LCMemoryCapabilityRequest.failure("Invalid anisette provisioning response.")
                }
                let reply: [String: String]
                switch result {
                case "GiveIdentifier": reply = ["identifier": encodedIdentifier]
                case "GiveStartProvisioningData":
                    let result = try await applePlist(url: startURL, body: ["Header": [:], "Request": [:]])
                    guard let response = result["Response"] as? [String: Any], let spim = response["spim"] as? String else {
                        throw LCMemoryCapabilityRequest.failure("Apple could not start anisette provisioning.")
                    }
                    reply = ["spim": spim]
                case "GiveEndProvisioningData":
                    guard let cpim = json["cpim"] as? String else { throw LCMemoryCapabilityRequest.failure("Missing provisioning challenge.") }
                    let result = try await applePlist(url: finishURL, body: ["Header": [:], "Request": ["cpim": cpim]])
                    guard let response = result["Response"] as? [String: Any],
                          let ptm = response["ptm"] as? String, let tk = response["tk"] as? String else {
                        throw LCMemoryCapabilityRequest.failure("Apple could not finish anisette provisioning.")
                    }
                    reply = ["ptm": ptm, "tk": tk]
                case "ProvisioningSuccess":
                    guard let blob = json["adi_pb"] as? String, !blob.isEmpty else { throw LCMemoryCapabilityRequest.failure("Missing provisioning data.") }
                    provisioningBlob = blob
                    return
                default:
                    throw LCMemoryCapabilityRequest.failure("Anisette provisioning was refused. Check the server and try again.")
                }
                let data = try JSONSerialization.data(withJSONObject: reply)
                try await socket.send(.string(String(decoding: data, as: UTF8.self)))
            }
            throw LCMemoryCapabilityRequest.failure("Anisette provisioning exceeded its message limit.")
        }, onCancel: { socket.cancel(with: .goingAway, reason: nil) })
    }

    private func isAppleURL(_ url: URL) -> Bool {
        url.scheme == "https" && (url.host == "apple.com" || url.host?.hasSuffix(".apple.com") == true)
    }

    private func applePlist(url: URL, body: [String: Any]? = nil) async throws -> [String: Any] {
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.setValue(clientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(localUser, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(identifier.uuidString, forHTTPHeaderField: "X-Mme-Device-Id")
        request.setValue(ISO8601DateFormatter().string(from: Date()), forHTTPHeaderField: "X-Apple-I-Client-Time")
        request.setValue(Locale.current.identifier, forHTTPHeaderField: "X-Apple-Locale")
        request.setValue(TimeZone.current.abbreviation(), forHTTPHeaderField: "X-Apple-I-TimeZone")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        if let body { request.httpBody = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0) }
        let data = try await data(request)
        guard let result = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw LCMemoryCapabilityRequest.failure("Invalid Apple provisioning response.")
        }
        return result
    }

    private func data(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw LCMemoryCapabilityRequest.failure("The provisioning service returned an HTTP error.")
        }
        return data
    }

    private func json(_ request: URLRequest) async throws -> [String: Any] {
        let response = try await data(request)
        guard let result = try JSONSerialization.jsonObject(with: response) as? [String: Any] else {
            throw LCMemoryCapabilityRequest.failure("Invalid anisette server response.")
        }
        return result
    }
}
