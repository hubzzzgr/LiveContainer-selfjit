import SwiftUI

struct LCMemorySetupView: View {
    @StateObject private var model = LCMemoryCapability()
    @AppStorage("LCMemoryAnisetteServer") private var server = "https://ani.sidestore.io"

    var body: some View {
        Form {
            Section {
                HStack {
                    Text("Current process grant")
                    Spacer()
                    Text(model.currentGrant.map { $0 ? "Present" : "Missing" } ?? "Unknown")
                        .foregroundColor(model.currentGrant == true ? .green : .secondary)
                }
                if let bytes = model.availableBytes {
                    HStack {
                        Text("Available process memory")
                        Spacer()
                        Text(String(format: "%.0f MiB", Double(bytes) / 1_048_576))
                    }
                }
                ForEach(model.hosts) { host in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(host.name)
                        Text(host.id).font(.caption).foregroundColor(.secondary).textSelection(.enabled)
                        Text(host.signedRequest ? "Installed signature requests increased memory" : "Installed signature is missing increased memory")
                            .font(.caption).foregroundColor(host.signedRequest ? .green : .secondary)
                    }
                }
                Button("Check Installed Grant Again") { model.refresh() }
            } header: {
                Text("Installed Memory Capability")
            } footer: {
                Text("This is shared by all guests in the same host process. Available memory is remaining headroom, not total RAM. LiveProcess's own budget is measured when a multitasking guest starts.")
            }

            Section {
                if !model.signedIn {
                    TextField("Apple Account", text: $model.email)
                        .textInputAutocapitalization(.never).disableAutocorrection(true)
                        .keyboardType(.emailAddress).disabled(model.busy)
                    SecureField("Password", text: $model.password).disabled(model.busy)
                    if model.needsVerification {
                        TextField("Apple Verification Code", text: $model.verificationCode)
                            .keyboardType(.numberPad).textContentType(.oneTimeCode)
                        Button("Submit Verification Code") { model.submitCode() }
                            .disabled(model.verificationCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    Button("Sign In") { model.signIn(server: server) }
                        .disabled(model.busy || model.email.isEmpty || model.password.isEmpty || model.hosts.isEmpty)
                } else {
                    Button("Enable Increased Memory Limit for Guest Hosts") { model.enable() }
                        .disabled(model.busy)
                }
                if model.busy { ProgressView() }
                if model.busy || model.signedIn {
                    Button(model.busy ? "Cancel Setup" : "Sign Out") { model.signOut() }
                        .disabled(model.busy && model.signedIn)
                }
                if !model.status.isEmpty {
                    Text(model.status).foregroundColor(model.failed ? .red : .primary).textSelection(.enabled)
                }
            } header: {
                Text("Enable on Apple's App IDs")
            } footer: {
                Text("Use the Apple account that installed LiveContainer. Passwords and sessions are not saved. The anisette server receives provisioning data, not your password. Enabling the capability affects LiveContainer and its installed LiveProcess extension, not individual guest App IDs. Re-signing and reinstalling are required before iOS can grant additional memory.")
            }

            Section {
                TextField("Anisette v3 Server", text: $server)
                    .textInputAutocapitalization(.never).disableAutocorrection(true)
                    .keyboardType(.URL).disabled(model.busy || model.signedIn)
                Link("GetMoreRam â€” Inspiration", destination: URL(string: "https://github.com/hugeBlack/GetMoreRam")!)
            } header: {
                Text("Setup")
            }
        }
        .navigationTitle("Add More RAM")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { model.refresh() }
        .onDisappear { model.signOut() }
    }
}
