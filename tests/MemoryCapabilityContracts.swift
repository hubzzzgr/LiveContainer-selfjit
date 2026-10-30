import Foundation

@main
enum MemoryCapabilityContracts {
    static func main() throws {
        let required = ["com.example.LiveContainer", "com.example.LiveContainer.LiveProcess"]
        let registered = [required[0]: "HOST123", required[1]: "PROCESS123", "com.example.guest": "GUEST123"]
        let resolved = try LCMemoryCapabilityRequest.targetIDs(required: required, registered: registered)
        precondition(resolved == ["HOST123", "PROCESS123"])
        do {
            _ = try LCMemoryCapabilityRequest.targetIDs(required: required, registered: [required[0]: "HOST123"])
            fatalError("Must resolve LiveProcess before any write")
        } catch {}
        do {
            _ = try LCMemoryCapabilityRequest.targetIDs(required: [], registered: registered)
            fatalError("Must reject unidentified hosts")
        } catch {}
        let payload = LCMemoryCapabilityRequest.payload(id: "HOST123", name: "LC", bundleID: required[0], teamID: "TEAM123")
        let data = payload["data"] as! [String: Any]
        precondition(data["id"] as? String == "HOST123")
        let attributes = data["attributes"] as! [String: Any]
        precondition(attributes["identifier"] as? String == required[0])
        precondition(attributes["teamId"] as? String == "TEAM123")
        let relationships = data["relationships"] as! [String: Any]
        let capabilities = (relationships["bundleIdCapabilities"] as! [String: Any])["data"] as! [[String: Any]]
        precondition(capabilities.count == 1)
        let capability = capabilities[0]
        precondition((capability["attributes"] as! [String: Any])["enabled"] as? Bool == true)
        let relation = (capability["relationships"] as! [String: Any])["capability"] as! [String: Any]
        precondition((relation["data"] as! [String: String])["id"] == "INCREASED_MEMORY_LIMIT")
        _ = try JSONSerialization.data(withJSONObject: payload)
        print("Memory capability request contracts passed")
    }
}
