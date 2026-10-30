# Increased Memory Limit

LiveContainer requests `com.apple.developer.kernel.increased-memory-limit` as a
Boolean `true`. This request was already present in the fork's entitlement files;
the runtime diagnostic and archive/IPA checks make its use observable and verify
that packaging preserves it. All other entitlement values remain unchanged.

## Executable targets

| Target / file | Request | Reason |
| --- | --- | --- |
| LiveContainer / `entitlements.xml` | `true`, Debug and Release | Runs guests in the main app process. |
| LiveProcess / `LiveProcess/LiveProcess.entitlements` | `true`, Debug and Release | Runs multitasking guests and built-in SideStore in a separate process; the host app's grant does not replace its own signature/profile. |
| Catalyst template / `entitlements.catalyst.xml` | Existing `true` retained | Not an iOS IPA signing input; no guarantee of a memory increase on macOS. |
| LCJITHelper | No added request | Performs pairing/debugger work; does not execute the guest workload. |
| ShareExtension, LaunchAppExtension, bundled LiveWidgetExtension | No added request | Share, intent and widget operations do not host guests. |
| LiveContainerShared, SwiftUI, TweakLoader, ZSign, TestJITLess and SideStore libraries | No separate request | Libraries execute under the hosting executable's process entitlements. |

This is a signing capability of each guest-hosting executable. It is never toggled
per guest app at runtime, and does not depend on the guest's own entitlement plist.
The existing JIT providers, debugger entitlements, keychain groups, application
groups and SideStore signing steps are preserved.

## App IDs, provisioning and re-signing

### Built-in Add More RAM setup

Open **Settings → Add More RAM**, or an individual guest's **Settings → Add More
RAM**. Sign in with the Apple account that installed LiveContainer and complete
Apple's verification prompt. The screen automatically matches the signing team
and exact App IDs of this installed LiveContainer and LiveProcess, then offers
**Enable Increased Memory Limit for Guest Hosts**. It uses the additive
`INCREASED_MEMORY_LIMIT` developer-services request used by
[GetMoreRam](https://github.com/hugeBlack/GetMoreRam), through the pinned
StosSign API/authentication library. No guest App ID is modified, no unrelated
capabilities are disabled, and no certificates or App IDs are created or revoked.

After Apple accepts the request, reinstall this fork's IPA using your signer,
keeping extensions, so it generates new provisioning profiles and signatures.
This screen does not re-sign or replace the installed app itself. Plain refresh
may preserve a stale signature/profile; verify the installed grant afterward.
The displayed **Current process grant** comes from the running process's security
task, while each host's installed signature request and current available memory
are displayed separately. App ID setup success is never treated as a runtime
grant. Memory limits still depend on the device, OS, and process type.

A real per-guest entitlement toggle is not available: guests running in the same
host share that host's signed entitlement. The guest settings entry therefore
opens the shared setup instead of pretending to switch the capability at runtime.
Apple passwords, verification codes, sessions and anisette provisioning material
are held in memory for setup and cleared on sign-out/leaving the screen. The
configurable HTTPS Anisette v3 service receives provisioning messages, not the
Apple password. The default service is `https://ani.sidestore.io`, as in GetMoreRam.
Actual account login, Apple capability acceptance and post-reinstall device
behavior require device validation; CI never logs into an Apple account.

### Manual setup

1. In Apple Developer **Certificates, Identifiers & Profiles**, enable the
   **Increased Memory Limit** capability for the App IDs used to sign LiveContainer
   and LiveProcess, where your account/platform supports it. LiveProcess uses
   `$(LIVECONTAINER_BUNDLE_IDENTIFIER).LiveProcess`; check the actual IDs after
   sideloading, since a signer may change them.
2. Regenerate and download provisioning profiles after changing the App IDs.
   Each host's profile must include
   `Entitlements:com.apple.developer.kernel.increased-memory-limit = true`.
   Keep the other capabilities used by this fork in those profiles as well.
3. Sign both executables with their respective profiles and preserve the Boolean
   entitlement in the final signatures. The source plist or an ad hoc signature
   alone cannot grant this capability on a provisioned device.
4. SideStore/AltStore or another signer may remove unsupported entitlements or
   replace provisioning profiles during install/refresh. Verify the re-signed IPA
   again after that operation. A profile or account without the grant does not
   provide increased memory; editing the plist cannot remedy that limitation.

Apple applies the entitlement only on supported devices/OS versions. It does not
promise a fixed RAM allowance or remove memory pressure and extension limits.
LiveProcess retains the request, but its actual extension budget must be measured
on the intended device.

## Runtime diagnostic

On an iOS device, the shared bootstrap logs once per entry before loading a guest:

```text
[LCMemory] LiveContainer pid=123: os_proc_available_memory()=... bytes (... MiB available)
[LCMemory] LiveProcess pid=456: os_proc_available_memory()=... bytes (... MiB available)
```

Use Xcode's device console or macOS Console and filter for `[LCMemory]`. The value
is the process's remaining allocation headroom at that moment, not physical RAM,
total process budget, or proof that the entitlement was granted. Simulator and
Catalyst builds omit the device-only diagnostic. Compare normal and multitasking
launches on the same phone after signing and again after a SideStore refresh.

## Build and verify

On macOS with Xcode and the iOS SDK, from the repository root:

```sh
python3 scripts/verify_memory_entitlements.py
python3 -m unittest discover -s scripts -p 'test_*.py'
xcodebuild archive -project LiveContainer.xcodeproj -scheme LiveContainer \
  -sdk iphoneos -arch arm64 -configuration Release -archivePath archive
python3 scripts/verify_memory_entitlements.py \
  --app archive.xcarchive/Products/Applications/LiveContainer.app
```

The existing macOS CI runs these configuration/product checks and checks both
`LiveContainer.ipa` and `LiveContainer+SideStore.ipa` after packaging. It reads the
signed entitlement from each guest host's Mach-O binary using `codesign`; a missing
or false value fails packaging. Embedded profiles, when present, must also grant
the entitlement. Certificate-free CI artifacts can have ad hoc signatures without
profiles; that verifies preservation of the request, not device authorization.

For the final IPA signed for installation, require both provisioning grants:

```sh
python3 scripts/verify_memory_entitlements.py --require-profile \
  --ipa LiveContainer.ipa --ipa LiveContainer+SideStore.ipa
```

Source validation works on Windows. Xcode compilation, signature inspection and
device measurements require Apple tools/hardware; passing source checks does not
establish that a built or installed IPA has the capability.

CI also compiles/runs `tests/MemoryCapabilityContracts.swift`, which exercises the
actual additive request payload and exact host matching before any write.
StosSign API/Auth/Common are pinned to GetMoreRam's revision
`01dd7bc4f5084ade9e2ebbc7e338dc2e3f454d77` and linked only into the UI framework;
StosSign's signing engine is not used to replace the existing guest signer/JIT flow.

References: [Apple entitlement reference](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit),
[available process memory](https://developer.apple.com/documentation/os/os_proc_available_memory),
[enable App ID capabilities and regenerate profiles](https://developer.apple.com/help/account/identifiers/enable-app-capabilities/).
