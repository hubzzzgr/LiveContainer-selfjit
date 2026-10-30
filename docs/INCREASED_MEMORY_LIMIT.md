# Increased Memory Limit

This feature applies to each **host process**, not to individual guest settings.
Normal guests run inside LiveContainer; multitasking guests run inside separately
signed LiveProcess extension processes. Each host needs its own entitlement and
authorized provisioning profile. A second LiveContainer installation also needs
its own signing configuration.

## Architecture and research

`LiveContainer/LCBootstrap.m` loads the guest with `dlopen_nolock`, locates its
entry point, and calls it inside the existing process. `LiveProcess/main.m`
enters the same bootstrap inside an extension process. Loading a guest's code
signature does not replace the host task's entitlements. Guest signing through
`LCUtils` / ZSign makes the guest loadable; it cannot authorize host capabilities.

Apple's [Increased Memory Limit documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit)
describes a Boolean request that only gives additional memory on supported
devices. [XNU's memory-limit implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_memorystatus.c)
checks this entitlement on the task and applies a process footprint limit. That
rules out genuine per-guest entitlement switches within a single host task.

[GetMoreRam's implementation](https://github.com/hugeBlack/GetMoreRam/blob/main/GetMoreRam/AppIDViewModel.swift)
uses StosSign to request the Developer Services capability `INCREASED_MEMORY_LIMIT`
for an App ID. Its [instructions](https://github.com/hugeBlack/GetMoreRam#how-to-use)
then require reinstalling the target through SideStore/AltStore. This is a
provisioning step, not an in-process memory-limit switch. Its external setup
approach can be used with this fork; this implementation does not import its
authentication stack, store Apple ID credentials, or add dependencies.

## What is requested

Both existing entitlement files already contain Boolean true for:

```text
com.apple.developer.kernel.increased-memory-limit
```

`entitlements.xml` is selected for LiveContainer in Debug and Release;
`LiveProcess/LiveProcess.entitlements` is selected for LiveProcess in both
configurations. These requests are retained. `LCIncreasedMemoryLimitRequested`
in each host's Info.plist is an informational build-request marker, checked
against the actual entitlement files by CI. It never enables the status indicator.

CI checks the archived executable and both packaged IPA variants using
`codesign -d --entitlements :-`. Missing true entitlements fail packaging. A
profile missing from an ad hoc distribution artifact is reported as a signing
diagnostic: the installer still needs to supply an authorized profile and final
signature. The ordinary release workflow does not require private certificates
or credentials.

## Runtime evidence and limits

Settings → **Increased Memory Limit** refreshes on opening, returning to the
foreground, and pressing **Refresh Status**. File inspection runs off the UI
thread. The following observations remain separate:

| Observation | Evidence | What it establishes |
| --- | --- | --- |
| Build Configuration | Info.plist marker, checked against build settings by CI | Source requested the capability |
| Installed App Signature | Bounds-checked arm64 Mach-O signature XML | Installed executable contains the request; does not authenticate it |
| Running Process Signature | `SecTaskCreateFromSelf` + `SecTaskCopyValueForEntitlement` for the exact key | Entitlement value on this running task |
| Granted by iOS | True running entitlement **and** `SecTaskEntitlementsValidated` | OS validation of the running task's entitlements |
| Provisioning Profile | Embedded CMS XML payload, expiration and identifier checks | Advisory signing diagnostics; does not authenticate CMS or its certificate |
| Available Memory Now | Public `os_proc_available_memory()` | Current advisory headroom, not a baseline comparison |
| Actual Memory Increase | Not independently confirmed | No extra RAM claim or exhaustion test |

Apple's [SecTask inspection interface](https://github.com/apple-oss-distributions/Security/blob/main/sectask/SecTask.h)
is published on macOS but is not a supported public iOS SDK interface. This fork
already uses these Security entry points. The diagnostics resolve them optionally
with `dlsym`, including the separate validation helper described by
[Apple's Security implementation](https://github.com/apple-oss-distributions/Security/blob/main/sectask/SecTask.c).
There is no new mandatory private-symbol linkage. If an entry point is absent,
task creation fails, retrieval errors, the value has the wrong type, or validation
cannot be established, the result remains **Unable to Verify**. A false validation
result is not interpreted as proof of an explicit denial. On Simulator, macOS,
or Catalyst, an iOS runtime grant is not claimed.

**Enabled** requires a true running-task value and OS validation. **Not Enabled**
means that the runtime query succeeded and found the entitlement absent or false.
The installed signature and profile alone never yield Enabled. Errors are not
silently converted into missing entitlements. A true entitlement without OS
validation is Unable to Verify.

Before guest hooks change the main bundle, the shared bootstrap captures the host
bundle and a SHA-256 fingerprint of its signature and profile. A later readable
fingerprint change yields **Restart Required**, taking precedence over other
states. This baseline is process-local, not saved as a granted preference. An
unreadable signature cannot establish a change; an Apple portal change alone is
not observable until the signed files change. Relaunching takes a new baseline
and re-queries the actual task. No toggle or persisted user preference can grant
the entitlement. Existing guest/JIT settings and launch decisions are untouched.

LiveProcess rows inspect that extension's installed files and profile separately.
They explicitly do **not** claim to inspect a running extension, a remote
LiveContainer, or the extension's actual memory allowance.

Apple documents [available memory](https://developer.apple.com/documentation/os/os_proc_available_memory)
as current limit minus footprint, subject to change. The reported value is
sampled again on every refresh. It cannot prove an entitlement-induced increase
without an otherwise comparable baseline on the same device and OS.

## Signing and installation

1. Enable Increased Memory Limit for the App ID used to sign **LiveContainer**.
   Do the same for **LiveProcess** if keeping the multitasking extension. If using
   GetMoreRam, select the actual host App IDs for the installation being used.
2. Regenerate the appropriate profiles. Confirm their `Entitlements` dictionaries
   authorize a true memory entitlement. Account/team/capability availability is
   controlled by Apple; this implementation does not promise support for every
   free account, paid certificate, enterprise profile, or installer version.
3. Re-sign/reinstall or refresh with SideStore, AltStore, or an authorized signing
   tool. The final signatures must retain the entitlement. Retain LiveProcess
   when using multitasking. A signing certificate alone, importing a certificate
   into LiveContainer for guests, or enabling an App ID without reinstalling does
   not change a running process's entitlements.
4. Fully close the affected host and guest processes, relaunch, then refresh
   Settings. Follow any profile-expiration, App ID, team, or missing-entitlement
   diagnostics. If signing is incompatible, iOS may reject installation/launch
   before Settings is reachable; use the install log and offline checks below.

These requirements follow Apple's [entitlement troubleshooting workflow](https://developer.apple.com/library/archive/technotes/tn2415/_index.html).
No code changes profile authorization, bypasses validation, increases a jetsam
limit through private mutation APIs, or performs an allocation stress test.

On macOS, check an archive or final IPA:

```sh
python3 scripts/verify_memory_limit.py --app archive.xcarchive/Products/Applications/LiveContainer.app
python3 scripts/verify_memory_limit.py --ipa LiveContainer.ipa
# After final authorized signing (requires both hosts):
python3 scripts/verify_memory_limit.py --ipa signed.ipa --require-authorized
```

The final check additionally requires a compatible unexpired profile payload,
matching App ID/team, valid bundle seal, and a signing certificate included in the
profile. It still cannot prove the iPhone's runtime grant or device memory gain.

## Validation

Portable tests: `python3 scripts/verify_memory_limit.py` and
`python3 -m unittest discover -s scripts -p 'test_*.py'`.
`tests/MemoryDiagnosticsContracts.m` compiles the actual diagnostic implementation
with mocked Security functions. GitHub Actions compiles and executes it on macOS
before archiving. It covers present/granted, missing/false, unvalidated, unavailable
APIs, retrieval failure, malformed values/signatures, DER-only signatures,
universal arm64 slices, expired/incompatible profiles and signing fingerprints.
The new Python tests cover archive/IPA checks and entitlement stripping by signers.

There is no new persisted setting to test. Status is recomputed rather than
persisted as a preference; the native policy tests check a missing entitlement
after a previous granted evaluation. On-device persistence/regression testing
must confirm existing guest and JIT settings still survive relaunches.

The implementation was prepared on Windows. Portable checks passed (20 tests,
one existing macOS-only test skipped). Subsequent [macOS CI validation](https://github.com/hubzzzgr/LiveContainer-selfjit/actions/runs/41114539488)
passed for commit `b671650`: native memory/JIT contract tests, the Xcode Release
archive, archived host entitlement checks, both IPA packaging checks, uploads and
the nightly release. The profile extraction test compares serialized payloads
because XML plist dates lose fractional-second precision. These artifacts still
require authorized signing for installation. Device launches, final provisioned
signatures and an actual on-device memory increase remain unverified.

Device validation still required:

| Scenario | Expected check |
| --- | --- |
| Authorized signature and running grant | Enabled; running signature true; iOS grant verified |
| Entitlement absent/false | Not Enabled; guest still launches normally |
| Source request retained but installer strips it | Build Requested; running signature absent; Not Enabled |
| API unavailable, errors or no validation evidence | Unable to Verify, never Enabled |
| Unsupported/expired/mismatched profile | Actionable Settings diagnostic or iOS install rejection |
| Re-signing while a host remains running | Restart Required when the file change is observable; fresh query after relaunch |
| Existing settings after relaunch | Guest/JIT choices unchanged; memory status refreshed |
| Guests with/without host grant | Launch same guest in each valid installation, switch apps, exercise JIT as before |
| Multitasking | Keep extension, authorize its App ID, launch a guest; host status does not imply a measured extension limit |

For an optional effectiveness comparison, collect foreground headroom and
footprint observations on the same physical device/OS with equivalent launches
of valid builds with and without the entitlement. Account for JIT/debugger state
and memory pressure. A single headroom number is not proof of increased usable
memory; do not exhaust memory to test it.

## Changed files

| Area | Files added or modified |
| --- | --- |
| Runtime diagnostics | `LiveContainer/LCMemoryDiagnostics.h`, `LiveContainer/LCMemoryDiagnostics.m` |
| Host startup baseline | `LiveContainer/LCBootstrap.m` |
| Settings | `LiveContainerSwiftUI/Views/Settings/LCIncreasedMemorySection.swift`, `LiveContainerSwiftUI/Views/Settings/LCSettingsView.swift`, `LiveContainerSwiftUI/LiveContainerSwiftUI-Bridging-Header.h` |
| Build membership and request markers | `LiveContainer.xcodeproj/project.pbxproj`, `LiveContainer/Info.plist`, `LiveProcess/Info.plist` |
| Portable and native tests | `scripts/test_verify_memory_limit.py`, `tests/MemoryDiagnosticsContracts.m` |
| Source and artifact checks | `scripts/verify_memory_limit.py` |
| CI and packaging | `.github/workflows/build.yml`, `.github/build_github.sh` |
| Documentation | `README.md`, `docs/INCREASED_MEMORY_LIMIT.md` |

The two existing entitlement request files were inspected and retained unchanged;
they already request the correct entitlement for both guest hosts.
