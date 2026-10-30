# Built-in StikJIT (Husk Self-JIT)

Select **Settings → JIT Enabler → Built-in StikJIT (Husk Self-JIT)**, then open
**Built-in StikJIT Setup**. This implementation uses a separate embedded
`LCJITHelper.appex`, with StikJIT 1.9.0 compiled from source in that helper.

## Pairing and first launch

1. Install with a development profile that grants the target `get-task-allow`.
   Keep app extensions when SideStore/AltStore asks, and enable Developer Mode.
2. Import your signing certificate in LiveContainer's settings. iOS 26+ still
   requires certificate-based JIT-less loading, even for guests that need runtime JIT.
3. Tap **Import Pairing File…** and select a **Remote Pairing (RP) plist** already
   created for this phone. The importer accepts XML or binary plists with 32-byte
   `public_key` and `private_key` data and a nonempty `identifier`. A SideStore
   lockdown `.mobiledevicepairing` record is a different protocol and is rejected.
   Existing valid RP records can be reused. To create one, follow the
   [StikDebug pairing-file guide](https://github.com/StikDebug/StikDebug-Guide/blob/main/pairing_file.md)
   or use a compatible idevice remote-pairing tool and export its RP plist to Files.
   If your tool only offers “Place”, export the generated RP record from its
   destination app before importing it here. An installed debugger app is not
   needed for subsequent LiveContainer launches.
4. Install/connect LocalDevVPN using the setup buttons. Allow Local Network access.
5. Tap **Prepare Developer Services** and wait for the developer image to be ready.
6. Launch a guest marked **Needs JIT**. LiveContainer prepares developer services
   before restarting, then its replacement process starts its own helper and waits
   for attachment before loading the guest. Multitasked guests use their own PID
   and a separate retained helper session.

A working RP file contains private credentials bound to device trust. There is
no universal pre-created file to bundle in an IPA, and this repository does not
include one. Import is the implemented pairing method; Husk's experimental iOS 27
on-device PIN enrollment is not included. A computer may be needed once to create
the RP file, but is not part of subsequent JIT sessions. Replace the file if trust
is reset or it stops authenticating after a device update.

Imported credentials live in the host's private Application Support directory,
are protected on disk, and are excluded from backups. They travel only to the
selected LiveProcess and the built-in helper. The helper deletes its temporary
copy when its session returns, and cleans orphaned files from dead helper PIDs on
the next operation. Pairing data and raw scripts/debugger logs are never logged.
Do not put a real RP file in this repository or upload it to CI.

## Scripts, recovery and limits

- Existing provider values 0–6 and the default provider are preserved; the new
  option is 7. Guest custom base64 scripts remain supported. A missing script uses
  LiveContainer's bundled `universal.js`; the existing 32-bit script policy is
  preserved when launching from the app list. Neither Husk's allocator nor its
  fixed preallocated arena is imported.
- Device preparation and debugger attachment are separate from guest engine
  readiness. A TXM device requires the guest's matching executable-memory protocol.
  The startup gate does not claim to test arbitrary engines. It observes a typed
  successful `vAttach` event plus the target's debugger flag (or successful
  attach/detach on non-TXM devices), then lets the guest perform its protocol.
  Requests and replies use property-list values in `NSExtensionItem`; a Darwin
  notification named with a fresh request UUID carries the attach signal. The
  signal is registered before helper launch and carries no pairing bytes or logs.
- Bonjour discovery runs asynchronously on the main run loop and only accepts
  service addresses belonging to this device. Each operation discovers afresh;
  nothing persists a potentially stale discovered port across reboots. Advanced
  port **0** falls back to **49152** if discovery fails; enter the actual port if
  local-network policy prevents discovery. Manual overrides must be 1–65535.
- Keep LiveContainer foregrounded during the first developer-image download.
  Preparation times out after four minutes. Check VPN, unlock the phone, retry
  Prepare, or reset the developer-image cache. Reset does not unmount the image.
- Guest startup waits at most 30 seconds while servicing the main run loop.
  A failed startup exits the affected target and records the existing launch error;
  it never enters the guest or silently switches provider. Relaunch LiveContainer
  to see the error. An unexpected helper failure while attached exits that guest,
  since later unserviced breakpoint requests are unsafe. Successful guest-driven
  detach leaves the guest running. Closing a guest ends its debugger session;
  there is no invented StikJIT cancellation API or “Launch Now” bypass.
  A broken custom script that leaves the target stopped can also stop its local
  deadline from running; force-close that guest and repair its script before retrying.
- The native extension APIs, scheduling before UIApplicationMain, sibling helper
  launch from LiveProcess, effective signing after sideloader refresh, guest
  engine compatibility and iOS 27 behavior require physical-device validation.
  The responsive run loop does not guarantee exemption from OS launch watchdogs.

## Build and verification

Build the existing `LiveContainer` scheme with Xcode on macOS. The host depends on
the helper target, and both ordinary and +SideStore IPAs retain it. StikJIT's Swift
sources and bundled arm64 `libidevice_ffi.a` are pinned in
`ThirdParty/StikJIT.lock.json`. Compiling the sources with the selected compiler
avoids importing Husk's Swift 6.4 binary module into Xcode 26.2. StikJIT and its FFI
are isolated in the helper, with no debugger framework dependency in the host.
The IOKit module uses a small ABI declaration header and links through SDKROOT,
avoiding the checkout's previous hard-coded macOS 27 SDK path. The same queries
and detection policy are retained for the existing providers.
Simulator builds use an unavailable helper stub and exclude the device-only FFI.
Sources, licenses, provenance and the local attach callback / I/O error handling
modification are included. The FFI archive is the unmodified upstream prebuilt artifact, not
a reproducible Rust build with a known upstream lockfile.

Portable validation:

```sh
python3 scripts/verify_builtin_jit.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

CI also compiles/runs `tests/BuiltInJITContracts.m` on macOS. It exercises the
actual Foundation pairing parser with malformed records, and the native intent
store with concurrent guests, replay, expiry and explicit no-JIT overrides.

After an archive or packaging (also done in CI):

```sh
python3 scripts/verify_builtin_jit.py --app archive.xcarchive/Products/Applications/LiveContainer.app
python3 scripts/verify_builtin_jit.py --ipa LiveContainer.ipa --ipa LiveContainer+SideStore.ipa
```

These checks validate dependency hashes, provider values, Xcode memberships,
helper embedding, identifiers, versions, notices and Mach-O linkage/architecture.
They cannot prove device operation. No Xcode compilation or iPhone execution was
possible in the Windows implementation environment.

Before advertising support, test the actual produced IPA on the intended phone:
normal and multitask launches with a known script-compatible guest, missing and
invalid pairing records, disconnected VPN, changed port after reboot, DDI reset,
helper interruption, guest termination/detach, multiple concurrent guests,
SideStore refresh, and regression launches using existing providers and non-JIT
guests. Record the OS/build, sideloader signing mode, guest revision and script,
and an observed guest action that actually executes generated code.
