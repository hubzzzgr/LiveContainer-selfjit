import Foundation
import Darwin

#if targetEnvironment(simulator)
@objc(LCJITHelperHandler)
final class LCJITHelperHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        context.cancelRequest(withError: NSError(domain: "LCJITHelper", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Built-in StikJIT requires a physical iOS device."]))
    }
}
#else
// StikJIT 1.9.0 is compiled from source into this extension only. The host never loads it.
@objc(LCJITHelperHandler)
final class LCJITHelperHandler: NSObject, NSExtensionRequestHandling {
    private static let queue = DispatchQueue(label: "com.kdt.livecontainer.builtin-jit")

    func beginRequest(with context: NSExtensionContext) {
        guard let request = (context.inputItems.first as? NSExtensionItem)?.userInfo,
              request["version"] as? Int == 1,
              let id = request["id"] as? String, UUID(uuidString: id) != nil,
              let pid = request["pid"] as? Int32,
              let operation = request["operation"] as? String,
              ["prepare", "enable", "resetDDI"].contains(operation),
              let expires = request["expires"] as? Double,
              expires >= Date.timeIntervalSinceReferenceDate,
              expires <= Date.timeIntervalSinceReferenceDate + 310 else {
            context.cancelRequest(withError: Self.error("Invalid or expired JIT helper request."))
            return
        }
        Self.queue.async {
            let result = Self.perform(request, pid: pid, operation: operation) {
                // Only an unguessable request-specific signal crosses this channel; no credentials or logs.
                // Keeping NSExtensionItem.userInfo to property-list values avoids decoder class overrides.
                let name = "com.kdt.livecontainer.jit.\(id).attached"
                name.withCString { _ = notify_post($0) }
            }
            let item = NSExtensionItem()
            item.userInfo = ["version": 1, "id": id, "pid": pid,
                             "success": result.0, "message": result.1]
            context.completeRequest(returningItems: [item], completionHandler: nil)
        }
    }

    private static func perform(_ request: [AnyHashable: Any], pid: Int32, operation: String,
                                attached: @escaping () -> Void) -> (Bool, String) {
        let manager = FileManager.default
        let root = manager.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("StikJIT", isDirectory: true)
        let paths = DDIPaths.default(in: root)
        do {
            try manager.createDirectory(at: root, withIntermediateDirectories: true,
                                        attributes: [.posixPermissions: 0o700])
            // Different helper instances share their cache. Lock preparation, never a running debugger.
            let lockFD = open(root.appendingPathComponent("cache.lock").path, O_CREAT | O_RDWR, 0o600)
            guard lockFD >= 0, flock(lockFD, LOCK_EX) == 0 else {
                if lockFD >= 0 { close(lockFD) }
                throw error("Could not lock the developer image cache.")
            }
            var locked = true
            defer {
                if locked { flock(lockFD, LOCK_UN) }
                close(lockFD)
            }
            if operation == "resetDDI" {
                try StikJIT.resetCachedDDI(at: paths)
                return (true, "Developer image cache reset. Prepare again to download it when needed.")
            }
            guard let pairing = request["pairing"] as? Data, pairing.count <= 1024 * 1024,
                  let plist = try PropertyListSerialization.propertyList(from: pairing, format: nil) as? [String: Any],
                  (plist["public_key"] as? Data)?.count == 32,
                  (plist["private_key"] as? Data)?.count == 32,
                  let identifier = plist["identifier"] as? String, !identifier.isEmpty,
                  let portValue = request["port"] as? Int, let port = UInt16(exactly: portValue), port > 0 else {
                throw error("A valid Remote Pairing file and port are required.")
            }
            // Remove credentials only when their owning helper process no longer exists.
            // Another active helper may still be opening its pairing file after releasing the cache lock.
            for file in try manager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
                where file.lastPathComponent.hasPrefix("pairing-") && file.pathExtension == "plist" {
                let parts = file.lastPathComponent.split(separator: "-")
                if parts.count > 2, let owner = Int32(parts[1]), kill(owner, 0) != 0, errno == ESRCH {
                    try manager.removeItem(at: file)
                }
            }
            let pairingURL = root.appendingPathComponent("pairing-\(getpid())-\(UUID().uuidString).plist")
            try pairing.write(to: pairingURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pairingURL.path)
            try (pairingURL as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
            defer { try? manager.removeItem(at: pairingURL) }

            let configuration = StikJIT.Configuration(rsdPort: port)
            let readiness = StikJIT.prepareDevice(pairingFile: pairingURL, paths: paths,
                                                  configuration: configuration)
            flock(lockFD, LOCK_UN)
            locked = false
            switch readiness {
            case .ready(let security):
                if operation == "prepare" {
                    let txm = security.isTXMPresent.map { $0 ? "present" : "absent" } ?? "unknown"
                    return (true, "Developer services ready. TXM: \(txm). Guest JIT still depends on its engine and script.")
                }
            case .unreachable(let reason), .preparationFailed(let reason):
                return (false, reason)
            }
            guard pid > 0, pid != getpid(),
                  let script = request["script"] as? String,
                  let decoded = Data(base64Encoded: script), !decoded.isEmpty,
                  decoded.count <= 1024 * 1024, String(data: decoded, encoding: .utf8) != nil else {
                throw error("Invalid target PID or guest JIT script.")
            }
            // A typed notification from the transport after a successful vAttach reply.
            // This never infers readiness from human-readable log strings or helper completion.
            ScriptRunner.didAttach = { attachedPID in
                if attachedPID == pid { attached() }
            }
            defer { ScriptRunner.didAttach = nil }
            // Device preparation above is protected across instances; this session must not re-enter it.
            try StikJIT.enableJIT(targetPID: pid, pairingFile: pairingURL,
                                 configuration: configuration, script: .customBase64(script),
                                 forceScript: false)
            return (true, "Debugger session finished.")
        } catch {
            // Do not log request dictionaries, pairing credentials, scripts, or raw debugger traffic.
            return (false, error.localizedDescription)
        }
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "LCJITHelper", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
#endif
