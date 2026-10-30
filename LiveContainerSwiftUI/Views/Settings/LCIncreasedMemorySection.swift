import SwiftUI

struct LCIncreasedMemorySection: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var evidence: [String: Any] = [:]
    @State private var refreshing = false

    private var status: String { evidence["status"] as? String ?? "Unable to Verify" }

    private var statusColor: Color {
        switch status {
        case "Enabled": return .green
        case "Not Enabled": return .secondary
        default: return .orange
        }
    }

    var body: some View {
        Section {
            HStack {
                Text("Entitlement Status")
                Spacer()
                Label(status, systemImage: status == "Enabled" ? "checkmark.circle.fill" : "info.circle")
                    .foregroundStyle(statusColor)
                    .multilineTextAlignment(.trailing)
            }
            row("Host", "host")
            row("Build Configuration", "buildRequest")
            row("Running Process Signature", "runningSignature")
            row("Granted by iOS", "grant")
            row("Installed App Signature", "installedSignature")
            row("Provisioning Profile", "profile")
            row("Available Memory Now", "headroom")
            HStack {
                Text("Actual Memory Increase")
                Spacer()
                Text("Not independently confirmed")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
            }
            if let detail = evidence["runtimeDetail"] as? String {
                Text(detail).font(.footnote).foregroundStyle(.secondary)
            }
            if let detail = evidence["signatureDetail"] as? String {
                Text(detail).font(.footnote).foregroundStyle(.secondary)
            }
            if let issues = evidence["issues"] as? [String] {
                ForEach(issues, id: \.self) { issue in
                    Label(issue, systemImage: "exclamationmark.triangle")
                        .font(.footnote).foregroundStyle(.orange)
                }
            }
            if evidence["liveProcessSignature"] != nil {
                row("LiveProcess Installed Signature", "liveProcessSignature")
                row("LiveProcess Profile", "liveProcessProfile")
                Text("Multitasking guests run in separate LiveProcess hosts. Each host needs its own authorized signature and profile. These installed-file checks do not verify a running LiveProcess entitlement or its memory allowance.")
                    .font(.footnote).foregroundStyle(.secondary)
                if let issues = evidence["liveProcessIssues"] as? [String] {
                    ForEach(issues, id: \.self) { issue in
                        Text("LiveProcess: \(issue)").font(.footnote).foregroundStyle(.orange)
                    }
                }
            } else {
                Text("LiveProcess is not included in this installation. Other LiveContainer installations must be checked separately.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Button(action: refresh) {
                HStack {
                    Text("Refresh Status")
                    if refreshing {
                        Spacer()
                        ProgressView()
                    }
                }
            }
            .disabled(refreshing)
            if let checkedAt = evidence["checkedAt"] as? Date {
                Text("Checked \(checkedAt.formatted(date: .abbreviated, time: .standard))")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } header: {
            Text("Increased Memory Limit")
        } footer: {
            Text("Increased Memory Limit is applied to the LiveContainer host process. Guest apps running inside LiveContainer share this entitlement.\n\nAvailable memory is an advisory snapshot, not proof of an increase. Additional memory depends on the device and iOS. Provisioning profile payload checks do not authenticate the profile or signing certificate.\n\nIf the profile does not allow the request, enable Increased Memory Limit for the host App ID, renew the profile, then re-sign and reinstall through SideStore, AltStore, or your signing tool. A certificate alone does not grant this entitlement.")
        }
        .onAppear(perform: refresh)
        .onChange(of: scenePhase) { phase in
            if phase == .active { refresh() }
        }
    }

    private func row(_ title: String, _ key: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
            Spacer()
            Text(evidence[key] as? String ?? "Unable to Verify")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }

    private func refresh() {
        guard !refreshing else { return }
        refreshing = true
        DispatchQueue.global(qos: .userInitiated).async {
            let result = LCMemoryDiagnostics.snapshot()
            DispatchQueue.main.async {
                evidence = result
                refreshing = false
            }
        }
    }
}
