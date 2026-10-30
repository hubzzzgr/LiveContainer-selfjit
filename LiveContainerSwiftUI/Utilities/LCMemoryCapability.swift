import Foundation
import SwiftUI
import StosSign_API
import StosSign_Auth
import StosSign_Common

struct LCMemoryHost: Identifiable {
    let id: String
    let teamID: String
    let name: String
    let signedRequest: Bool

    static func installed() throws -> [LCMemoryHost] {
        var bundles = [Bundle.main]
        if let url = Bundle.main.builtInPlugInsURL?.appendingPathComponent("LiveProcess.appex"),
           FileManager.default.fileExists(atPath: url.path) {
            guard let bundle = Bundle(url: url) else {
                throw LCMemoryCapabilityRequest.failure("Could not read the installed LiveProcess bundle.")
            }
            bundles.append(bundle)
        }
        return try bundles.map { bundle in
            guard let xml = getExecutableEntitlementXML(bundle.executablePath),
                  let data = xml.data(using: .utf8),
                  let entitlements = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let applicationID = entitlements["application-identifier"] as? String,
                  let separator = applicationID.firstIndex(of: "."),
                  let team = entitlements["com.apple.developer.team-identifier"] as? String,
                  !team.isEmpty, !team.contains("$") else {
                throw LCMemoryCapabilityRequest.failure("Could not read this install's signing identity. Use a LiveContainer build signed with your Apple account.")
            }
            let identifier = String(applicationID[applicationID.index(after: separator)...])
            guard !identifier.isEmpty, !identifier.contains("*"), !identifier.contains("$") else {
                throw LCMemoryCapabilityRequest.failure("The installed signature does not identify a specific App ID.")
            }
            return LCMemoryHost(id: identifier, teamID: team,
                                name: bundle == Bundle.main ? "LiveContainer" : "LiveProcess",
                                signedRequest: entitlements[LCMemoryCapabilityRequest.entitlement] as? Bool == true)
        }
    }
}

@MainActor
final class LCMemoryCapability: ObservableObject {
    @Published var email = ""
    @Published var password = ""
    @Published var verificationCode = ""
    @Published private(set) var needsVerification = false
    @Published private(set) var busy = false
    @Published private(set) var signedIn = false
    @Published private(set) var status = ""
    @Published private(set) var failed = false
    @Published private(set) var hosts: [LCMemoryHost] = []
    @Published private(set) var availableBytes: UInt64?
    @Published private(set) var currentGrant: Bool?

    private var session: AppleAPISession?
    private var team: Team?
    private var anisette = LCMemoryAnisette()
    private var verification: ((String?) -> Void)?
    private var operation: Task<Void, Never>?
    private var cancelRequested = false

    func refresh() {
        availableBytes = LCUtils.availableProcessMemory()?.uint64Value
        currentGrant = LCUtils.increasedMemoryEntitlement()?.boolValue
        do { hosts = try LCMemoryHost.installed() }
        catch { status = error.localizedDescription; failed = true }
    }

    func signIn(server: String) {
        guard !busy else { return }
        guard let url = URL(string: server.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "https", url.host != nil, url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil else {
            status = "Enter an HTTPS Anisette v3 server URL."
            failed = true
            return
        }
        refresh()
        guard !hosts.isEmpty else { return }
        let address = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret = password
        password = ""
        busy = true
        cancelRequested = false
        failed = false
        status = "Signing in…"
        operation = Task {
            defer { busy = false; verification = nil; needsVerification = false; verificationCode = "" }
            do {
                let headers = try await anisette.headers(server: url)
                try Task.checkCancellation()
                let (account, authenticated) = try await AppleAPI.shared.authenticate(
                    appleID: address, password: secret, anisetteData: headers
                ) { [weak self] callback in
                    await MainActor.run {
                        guard let self, !self.cancelRequested else { callback(nil); return }
                        self.verification = callback
                        self.needsVerification = true
                        self.status = "Enter the verification code sent by Apple."
                    }
                }
                try Task.checkCancellation()
                let teams = try await AppleAPI.shared.fetchTeamsForAccount(account: account, session: authenticated)
                try Task.checkCancellation()
                let requiredTeams = Set(hosts.map(\.teamID))
                guard requiredTeams.count == 1, let expected = requiredTeams.first,
                      let matching = teams.first(where: { $0.identifier == expected }) else {
                    throw LCMemoryCapabilityRequest.failure("This account does not contain the team that signed both guest hosts. Sign in with the account used to install LiveContainer.")
                }
                session = authenticated
                team = matching
                signedIn = true
                status = "Signed in to the installed app's team. Ready to enable Increased Memory Limit."
            } catch {
                if Task.isCancelled { return }
                failed = true
                status = error.localizedDescription
            }
        }
    }

    func submitCode() {
        let callback = verification
        verification = nil
        needsVerification = false
        callback?(verificationCode.trimmingCharacters(in: .whitespacesAndNewlines))
        verificationCode = ""
    }

    func enable() {
        guard !busy, let session, let team else { return }
        busy = true
        failed = false
        status = "Finding the installed guest hosts on Apple's service…"
        operation = Task {
            var enabled: [String] = []
            defer { busy = false }
            do {
                let registered = try await AppleAPI.shared.fetchAppIDsForTeam(team: team, session: session)
                try Task.checkCancellation()
                // Validate all identities before making any capability changes.
                let matches = Dictionary(registered.map { ($0.bundleIdentifier, $0.identifier) }, uniquingKeysWith: { first, _ in first })
                let targetIDs = try LCMemoryCapabilityRequest.targetIDs(required: hosts.map(\.id), registered: matches)
                for (host, id) in zip(hosts, targetIDs) {
                    try Task.checkCancellation()
                    guard let appID = registered.first(where: { $0.identifier == id }) else { throw LCMemoryCapabilityRequest.failure("Registered App ID disappeared.") }
                    status = "Enabling the App ID capability for \(host.name)…"
                    let payload = LCMemoryCapabilityRequest.payload(id: id, name: appID.name, bundleID: host.id, teamID: team.identifier)
                    let result = try await AppleAPI.shared.sendEditRequest(
                        requestURL: AppleAPI.shared.v1URL.appendingPathComponent("bundleIds").appendingPathComponent(id),
                        body: payload, session: session, json: true, appendClientId: false)
                    guard let updated = result["data"] as? [String: Any], updated["id"] as? String == id,
                          result["errors"] == nil else {
                        throw LCMemoryCapabilityRequest.failure("Apple did not accept Increased Memory Limit for \(host.name). Check the account's capability support and try again.")
                    }
                    enabled.append(host.name)
                }
                status = "Apple accepted the capability for \(enabled.joined(separator: " and ")). Reinstall this LiveContainer IPA through your signer, keeping extensions, to generate new profiles and signatures. Then return here to check the installed grant. This running process has not gained memory."
            } catch {
                failed = true
                let partial = enabled.isEmpty ? "" : "\(enabled.joined(separator: ", ")) was updated; the other host was not confirmed. "
                status = partial + (Task.isCancelled ? "Setup canceled. Recheck the App IDs before retrying." : error.localizedDescription)
            }
        }
    }

    func signOut() {
        cancelRequested = true
        operation?.cancel()
        verification?(nil)
        verification = nil
        needsVerification = false
        password = ""
        verificationCode = ""
        session = nil
        team = nil
        signedIn = false
        anisette = LCMemoryAnisette()
    }
}
