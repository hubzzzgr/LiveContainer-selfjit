import SwiftUI

struct LCMemorySetupView: View {
    @StateObject private var model = LCMemoryCapability()
    @AppStorage("LCMemoryAnisetteServer") private var server = "https://ani.sidestore.io"

    var body: some View {
        Form {
            Section {
                HStack {
                    Text("Running Entitlement Status")
                    Spacer()
                    Text(model.entitlementStatus)
                        .foregroundColor(model.entitlementStatus == "Enabled" ? .green : .secondary)
                }
                HStack {
                    Text("Available Memory Now")
                    Spacer()
                    Text(model.availableMemory)
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
                Text("Guests share their host process's entitlement. Available memory is current headroom; it does not prove an increase. LiveProcess has a separate signature and profile; its running grant is not verified here.")
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
                    Button("Request Increased Memory Limit") { model.enable() }
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
                Link("GetMoreRam Reference", destination: URL(string: "https://github.com/hugeBlack/GetMoreRam")!)
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
