import SwiftUI
import UniformTypeIdentifiers

struct LCBuiltInJITSetupView: View {
    @State private var importing = false
    @State private var hasPairing = LCBuiltInJIT.hasPairing
    @State private var busy = false
    @State private var status = ""
    @State private var failed = false
    @State private var removing = false
    @AppStorage("LCBuiltInJITPort", store: LCUtils.appGroupUserDefault) private var port = 0
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Form {
            Section {
                if let reason = LCBuiltInJIT.unavailableReason {
                    Text(reason).foregroundStyle(.red)
                }
                Text("Uses LiveContainer’s own debugger helper. Keep Extensions when installing, enable Developer Mode, and import a signing certificate for JIT-less loading on iOS 26 and later.")
                Text("Guest engines must support their selected JIT script. Preparing the device or attaching a debugger does not prove that a guest can execute generated code.")
            }
            Section {
                Label(hasPairing ? "Remote Pairing file imported" : "No Remote Pairing file",
                      systemImage: hasPairing ? "checkmark.circle" : "doc.badge.plus")
                Button(hasPairing ? "Replace Pairing File…" : "Import Pairing File…") { importing = true }
                Link("Create a pairing file for this device", destination: URL(string: "https://github.com/StikDebug/StikDebug-Guide/blob/main/pairing_file.md")!)
                if hasPairing {
                    Button("Remove Pairing File", role: .destructive) { removing = true }
                }
            } header: {
                Text("Pairing")
            } footer: {
                Text("Import an existing Remote Pairing (RP) plist created for this phone with idevice_pair. It contains public_key, private_key and identifier. SideStore lockdown/.mobiledevicepairing files cannot be used here. Pairing credentials are device-specific; there is no universal pre-created file. The imported file is stored privately and excluded from backups.")
            }
            .disabled(busy)
            Section {
                Button("Connect LocalDevVPN") {
                    var url = URLComponents()
                    url.scheme = "localdevvpn"
                    url.host = "enable"
                    url.queryItems = [URLQueryItem(name: "scheme", value: LCUtils.appUrlScheme())]
                    if let target = url.url { UIApplication.shared.open(target) }
                }
                Link("Get LocalDevVPN", destination: URL(string: "https://apps.apple.com/app/id6755608044")!)
                Button("Prepare Developer Services") { run(reset: false) }
                    .disabled(busy || !hasPairing || LCBuiltInJIT.unavailableReason != nil)
                Button("Reset Developer Image Cache") { run(reset: true) }
                    .disabled(busy || LCBuiltInJIT.unavailableReason != nil)
                if busy { ProgressView("Preparing developer services…") }
                if !status.isEmpty {
                    Text(status).foregroundColor(failed ? .red : .primary).textSelection(.enabled)
                }
            } footer: {
                Text("Connect LocalDevVPN before preparing or launching. The first preparation may download a developer image. Prepare again after a reboot. A guest marked Needs JIT then uses this helper automatically, including in multitasking.")
            }
            Section {
                TextField("Remote Pairing port", value: $port, format: .number.grouping(.never))
                    .keyboardType(.numberPad)
                    .disabled(busy)
            } header: {
                Text("Advanced")
            } footer: {
                Text("Use 0 for automatic Bonjour discovery of this device’s port, falling back to 49152. If Local Network access is denied or discovery fails after a reboot, allow it in Settings or enter the current Remote Pairing port. Valid ports: 1–65535.")
            }
        }
        .navigationTitle("Built-in StikJIT")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
            do {
                try LCBuiltInJIT.importPairingFile(result.get())
                hasPairing = LCBuiltInJIT.hasPairing
                status = "Pairing file imported. Connect LocalDevVPN, then Prepare Developer Services."
                failed = false
            } catch {
                status = error.localizedDescription
                failed = true
            }
        }
        .confirmationDialog("Remove this device’s stored pairing credentials?", isPresented: $removing, titleVisibility: .visible) {
            Button("Remove Pairing File", role: .destructive) {
                do {
                    try LCBuiltInJIT.removePairingFile()
                    hasPairing = false
                    status = "Pairing file removed."
                    failed = false
                } catch {
                    status = error.localizedDescription
                    failed = true
                }
            }
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active { hasPairing = LCBuiltInJIT.hasPairing }
        }
    }

    private func run(reset: Bool) {
        guard port >= 0 && port <= 65535 else {
            status = "Enter 0 for automatic discovery or a port between 1 and 65535."
            failed = true
            return
        }
        busy = true
        status = reset ? "Resetting developer image cache…" : "Preparing developer services. Keep LiveContainer open…"
        failed = false
        let completion: (String?, Error?) -> Void = { message, error in
            busy = false
            failed = error != nil
            status = error?.localizedDescription ?? message ?? "Finished."
        }
        if reset { LCBuiltInJIT.resetDDI(completion: completion) }
        else { LCBuiltInJIT.prepare(completion: completion) }
    }
}
