import Foundation

// Same additive developer-services request used by GetMoreRam. This runs only
// during explicit account setup; it cannot alter the entitlement of a live task.
enum LCMemoryCapabilityRequest {
    static let entitlement = "com.apple.developer.kernel.increased-memory-limit"
    static let capability = "INCREASED_MEMORY_LIMIT"

    static func payload(id: String, name: String, bundleID: String, teamID: String) -> [String: Any] {
        ["data": [
            "type": "bundleIds", "id": id,
            "attributes": ["identifier": bundleID, "name": name, "teamId": teamID,
                           "seedId": teamID, "bundleType": "bundle", "hasExclusiveManagedCapabilities": false],
            "relationships": ["bundleIdCapabilities": ["data": [[
                "type": "bundleIdCapabilities",
                "attributes": ["enabled": true, "settings": [Any]()],
                "relationships": ["capability": ["data": ["type": "capabilities", "id": capability]]]
            ]]]]
        ]]
    }

    // Resolve *every* host before the first write. Never use guest bundle IDs,
    // a fuzzy suffix match, or a guessed ID belonging to another LiveContainer.
    static func targetIDs(required: [String], registered: [String: String]) throws -> [String] {
        guard !required.isEmpty, Set(required).count == required.count else {
            throw failure("The installed guest-host identifiers could not be determined.")
        }
        return try required.map {
            guard let id = registered[$0] else {
                throw failure("No registered App ID matches \($0). Sign in with the Apple account that installed this LiveContainer.")
            }
            return id
        }
    }

    static func failure(_ message: String) -> NSError {
        NSError(domain: "LiveContainer.MemoryCapability", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
