#!/usr/bin/env python3
"""Validate the pinned dependency, Xcode memberships and built/packaged helper. No credentials required."""
import argparse
import hashlib
import json
import plistlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def openstep(text):
    """Read the subset of OpenStep plist syntax used by an Xcode project, including comments."""
    tokens = re.findall(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}()=;,]|[^\s{}()=;,]+', text, re.S)
    tokens = [t for t in tokens if not t.startswith(('/*', '//'))]
    index = 0

    def take(expected=None):
        nonlocal index
        require(index < len(tokens), 'Unexpected end of project')
        token = tokens[index]
        index += 1
        require(expected is None or token == expected, f'Expected {expected}, got {token}')
        return token

    def value():
        token = take()
        if token == '{':
            result = {}
            while tokens[index] != '}':
                key = take()
                if key.startswith('"'):
                    key = json.loads(key)
                take('=')
                require(key not in result, f'Duplicate project key: {key}')
                result[key] = value()
                take(';')
            take('}')
            return result
        if token == '(':
            result = []
            while tokens[index] != ')':
                result.append(value())
                if tokens[index] == ',':
                    take(',')
            take(')')
            return result
        return json.loads(token) if token.startswith('"') else token

    result = value()
    require(index == len(tokens), 'Unexpected trailing project tokens')
    return result


def verify_sources(root=ROOT):
    manifest = json.loads((root / 'ThirdParty/StikJIT.lock.json').read_text())
    require(manifest['revision'] == '32287268fa5824f9edce4cb359f5833ce0cf7b00', 'Unexpected StikJIT revision')
    for file, expected in manifest['files'].items():
        path = root / 'ThirdParty/StikJIT' / file
        require(path.is_file(), f'Missing StikJIT dependency: {file}')
        data = path.read_bytes()
        if path.suffix != '.a':
            data = data.replace(b'\r\n', b'\n')  # Git's Windows text checkout uses CRLF.
        require(hashlib.sha256(data).hexdigest() == expected, f'StikJIT checksum mismatch: {file}')
    objects = openstep((root / 'LiveContainer.xcodeproj/project.pbxproj').read_text())['objects']
    targets = {obj['name']: obj for obj in objects.values() if obj.get('isa') == 'PBXNativeTarget'}
    helper = targets['LCJITHelper']
    host = targets['LiveContainer']
    shared = targets['LiveContainerShared']

    def memberships(target, phase_type):
        return [objects[objects[entry]['fileRef']]['path']
                for phase in target['buildPhases'] if objects[phase]['isa'] == phase_type
                for entry in objects[phase]['files']]

    helper_sources = memberships(helper, 'PBXSourcesBuildPhase')
    for path in (root / 'ThirdParty/StikJIT/Sources').glob('*.swift'):
        require(path.relative_to(root).as_posix() in helper_sources, f'Helper does not compile {path.name}')
    require('LCJITHelper/LCJITHelper.swift' in helper_sources, 'Helper handler is not compiled')
    require('LiveContainer/LCBuiltInJIT.m' in memberships(shared, 'PBXSourcesBuildPhase'), 'Shared bootstrap client is not compiled')
    require('LCJITHelper.appex' in memberships(host, 'PBXCopyFilesBuildPhase'), 'Helper is not embedded')
    helper_copies = [objects[entry] for phase in host['buildPhases']
                     if objects[phase]['isa'] == 'PBXCopyFilesBuildPhase'
                     for entry in objects[phase]['files']
                     if objects[objects[entry]['fileRef']]['path'] == 'LCJITHelper.appex']
    require(all('CodeSignOnCopy' in entry.get('settings', {}).get('ATTRIBUTES', []) for entry in helper_copies),
            'Embedded helper must be signed with the host identity')
    require('Resources/BuiltInJITNotices' in memberships(host, 'PBXResourcesBuildPhase'), 'License notices are not packaged')
    require(any(objects[dep]['target'] == next(key for key, obj in objects.items() if obj is helper)
                for dep in host['dependencies']), 'Missing host/helper build dependency')
    for name in ['LiveContainer', 'LiveContainerShared', 'LiveContainerSwiftUI', 'LiveProcess']:
        paths = memberships(targets[name], 'PBXSourcesBuildPhase') + memberships(targets[name], 'PBXFrameworksBuildPhase')
        require(not any('StikJIT' in path or 'idevice_ffi' in path for path in paths), f'Debugger linked into target: {name}')
    settings = (root / 'xcconfigs/LCJITHelper.xcconfig').read_text()
    require('-hidden-lidevice_ffi' in settings, 'Missing helper FFI linkage')
    require('CODE_SIGN_ENTITLEMENTS = LCJITHelper/LCJITHelper.entitlements' in settings,
            'Missing helper signing configuration')
    require(plistlib.loads((root / 'LCJITHelper/LCJITHelper.entitlements').read_bytes()) == {},
            'Unexpected helper entitlements')
    enum = (root / 'LiveContainerSwiftUI/Views/Settings/LCSettingsView.swift').read_text()
    for name, raw in [('SideJITServer', 0), ('StikJIT', 1), ('JITStreamerEBLegacy', 2), ('StikJITLC', 3),
                      ('SideStore', 4), ('StosDebug', 5), ('StosDebugLC', 6), ('BuiltInStikJIT', 7)]:
        require(re.search(rf'case {name} = {raw}\b', enum), f'Provider persistence changed: {name}')


def verify_app(app, inspect_macho=True):
    def plist(path):
        require(path.is_file(), f'Missing product plist: {path.name}')
        return plistlib.loads(path.read_bytes())

    host = plist(app / 'Info.plist')
    extension = app / 'PlugIns/LCJITHelper.appex'
    helper = plist(extension / 'Info.plist')
    binary = extension / helper['CFBundleExecutable']
    require(binary.is_file() and binary.stat().st_size > 0, 'Missing helper executable')
    require(helper['CFBundleIdentifier'].startswith(host['CFBundleIdentifier'] + '.'), 'Helper bundle ID is outside the host bundle ID')
    for key in ['CFBundleShortVersionString', 'CFBundleVersion']:
        require(helper[key] == host[key], f'Helper/host {key} mismatch')
    require(helper['NSExtension']['NSExtensionPointIdentifier'] == 'com.apple.ar.viewer', 'Wrong helper extension point')
    require(helper['NSExtension']['NSExtensionPrincipalClass'] == 'LCJITHelperHandler', 'Wrong helper entry class')
    require(float(helper['MinimumOSVersion']) >= 26, 'Helper minimum OS is too old')
    require((app / 'universal.js').is_file(), 'Missing LiveContainer universal guest script')
    for file in ['LICENSE-StikJIT-MPL-2.0.txt', 'LICENSE-idevice-MIT.txt', 'LICENSES-rppairing-crates.txt', 'NOTICE.txt']:
        require((app / 'BuiltInJITNotices' / file).is_file(), f'Missing notice: {file}')
    require(not any(p.name.lower() in ('pairing.plist', 'pairingfile.plist') or
                    (p.name.startswith('pairing-') and p.suffix == '.plist') or p.suffix == '.mobiledevicepairing'
                    for p in app.rglob('*')), 'Unexpected private pairing data in the product')
    if inspect_macho and sys.platform == 'darwin':
        subprocess.run(['lipo', '-verify_arch', 'arm64', str(binary)], check=True, capture_output=True)
        for executable in [app / host['CFBundleExecutable'], app / 'Frameworks/LiveContainerShared.framework/LiveContainerShared']:
            linked = subprocess.check_output(['otool', '-L', str(executable)], text=True)
            require('StikJIT.framework' not in linked and 'libidevice' not in linked, 'Host strongly links the debugger')
        linked = subprocess.check_output(['otool', '-L', str(binary)], text=True)
        require('StikJIT.framework' not in linked, 'Source-built helper unexpectedly requires an external StikJIT framework')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path, action='append', default=[])
    args = parser.parse_args()
    verify_sources()
    if args.app:
        verify_app(args.app)
    for ipa in args.ipa:
        # Extract only files needed by validation; no untrusted paths are written.
        with tempfile.TemporaryDirectory() as folder, zipfile.ZipFile(ipa) as archive:
            prefix = 'Payload/LiveContainer.app/'
            needed = [n for n in archive.namelist() if n.startswith(prefix) and not n.endswith('/') and
                      (n == prefix + 'Info.plist' or n == prefix + 'LiveContainer' or n == prefix + 'universal.js' or
                       n == prefix + 'Frameworks/LiveContainerShared.framework/LiveContainerShared' or
                       n.startswith(prefix + 'PlugIns/LCJITHelper.appex/') or n.startswith(prefix + 'BuiltInJITNotices/'))]
            for name in needed:
                target = Path(folder) / name
                require(target.resolve().is_relative_to(Path(folder).resolve()), 'Invalid IPA path')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
            verify_app(Path(folder) / prefix)
    print('Built-in JIT validation passed' + (' (source checks only)' if not args.app and not args.ipa else ''))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'Built-in JIT validation failed: {error}')
