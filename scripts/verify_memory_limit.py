#!/usr/bin/env python3
"""Check requests and final host signatures. Offline packaging checks never prove a runtime grant."""
import argparse
import datetime
import plistlib
import subprocess
import tempfile
import zipfile
from pathlib import Path

from verify_builtin_jit import ROOT, openstep, require

ENTITLEMENT = 'com.apple.developer.kernel.increased-memory-limit'
HOSTS = ('', 'PlugIns/LiveProcess.appex/')


def verify_sources(root=ROOT):
    objects = openstep((root / 'LiveContainer.xcodeproj/project.pbxproj').read_text())['objects']
    targets = {obj['name']: obj for obj in objects.values() if obj.get('isa') == 'PBXNativeTarget'}
    for target_name, entitlement_path, info_path in (
        ('LiveContainer', 'entitlements.xml', 'LiveContainer/Info.plist'),
        ('LiveProcess', 'LiveProcess/LiveProcess.entitlements', 'LiveProcess/Info.plist'),
    ):
        require(plistlib.loads((root / entitlement_path).read_bytes()).get(ENTITLEMENT) is True,
                f'{target_name} must request a Boolean true memory entitlement')
        require(plistlib.loads((root / info_path).read_bytes()).get('LCIncreasedMemoryLimitRequested') is True,
                f'{target_name} build-request marker must match the entitlement request')
        configs = objects[targets[target_name]['buildConfigurationList']]['buildConfigurations']
        for config_id in configs:
            config = objects[config_id]
            require(config['buildSettings'].get('CODE_SIGN_ENTITLEMENTS') == entitlement_path,
                    f'{target_name} {config["name"]} does not use the host entitlement file')
    shared = targets['LiveContainerShared']
    sources = [objects[objects[entry]['fileRef']]['path']
               for phase in shared['buildPhases'] if objects[phase]['isa'] == 'PBXSourcesBuildPhase'
               for entry in objects[phase]['files']]
    require('LiveContainer/LCMemoryDiagnostics.m' in sources, 'Memory diagnostics are not compiled into the host bootstrap')


def command_plist(command):
    result = subprocess.run(command, capture_output=True, check=True)
    return plistlib.loads(result.stdout)


def profile_issues(entitlements, profile, bundle_id, now=None):
    """Advisory payload checks; iOS is the authority for actual signature/profile validity."""
    issues = []
    allowed = profile.get('Entitlements', {})
    if not isinstance(allowed, dict):
        return ['Provisioning profile has no valid entitlements dictionary']
    if allowed.get(ENTITLEMENT) is not True:
        issues.append('Provisioning profile does not allow Increased Memory Limit')
    expires = profile.get('ExpirationDate')
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not isinstance(expires, datetime.datetime) or expires.replace(tzinfo=datetime.timezone.utc) <= now:
        issues.append('Provisioning profile is expired or has no expiration date')
    created = profile.get('CreationDate')
    if isinstance(created, datetime.datetime) and created.replace(tzinfo=datetime.timezone.utc) > now:
        issues.append('Provisioning profile is not yet valid')
    signed_id = entitlements.get('application-identifier', '')
    allowed_id = allowed.get('application-identifier', '')
    if not isinstance(signed_id, str) or not signed_id.endswith('.' + bundle_id):
        issues.append('Signature application identifier does not match the bundle ID')
    if not isinstance(allowed_id, str) or not allowed_id or not isinstance(signed_id, str):
        issues.append('Profile application identifier is missing or invalid')
    elif signed_id != allowed_id and not (allowed_id.endswith('.*') and signed_id.startswith(allowed_id[:-1])):
        issues.append('Signature application identifier does not match the profile')
    signed_team = entitlements.get('com.apple.developer.team-identifier')
    allowed_team = allowed.get('com.apple.developer.team-identifier')
    if not isinstance(signed_team, str) or not signed_team or signed_team != allowed_team:
        issues.append('Signature team identifier does not match the profile')
    return issues


def verify_host(bundle, require_authorized=False, read_plist=command_plist):
    info = plistlib.loads((bundle / 'Info.plist').read_bytes())
    name = info['CFBundleExecutable']
    require(Path(name).name == name and name not in ('.', '..'), 'Invalid host executable name')
    executable = bundle / name
    entitlements = read_plist(['codesign', '-d', '--entitlements', ':-', str(executable)])
    require(entitlements.get(ENTITLEMENT) is True, f'{bundle.name}: final signature lost the memory entitlement')
    issues = []
    profile_path = bundle / 'embedded.mobileprovision'
    if profile_path.is_file():
        profile = read_plist(['security', 'cms', '-D', '-i', str(profile_path)])
        issues = profile_issues(entitlements, profile, info['CFBundleIdentifier'])
    else:
        issues.append('No provisioning profile: re-sign with an authorized profile before installation')
    if require_authorized:
        require(not issues, f'{bundle.name}: ' + '; '.join(issues))
        subprocess.run(['codesign', '--verify', '--strict', str(bundle)], check=True)
        # Match the actual leaf certificate to those authorized by the profile.
        with tempfile.TemporaryDirectory() as folder:
            prefix = str(Path(folder) / 'certificate')
            subprocess.run(['codesign', '-d', '--extract-certificates', prefix, str(executable)], check=True, capture_output=True)
            leaf = Path(prefix + '0').read_bytes()
            require(leaf in profile.get('DeveloperCertificates', []), f'{bundle.name}: signing certificate is not in the profile')
    print(f'{bundle.name}: signed request preserved; runtime grant and extra memory NOT verified')
    for issue in issues:
        print(f'  Signing diagnostic: {issue}')


def verify_app(app, require_authorized=False):
    for relative in HOSTS:
        host = app / relative
        require(host.is_dir(), f'Missing guest host: {host}')
        verify_host(host, require_authorized)


def verify_ipa(ipa, require_authorized=False):
    with zipfile.ZipFile(ipa) as archive, tempfile.TemporaryDirectory() as folder:
        roots = [name[:-len('Info.plist')] for name in archive.namelist()
                 if name.startswith('Payload/') and name.endswith('/Info.plist') and name.count('/') == 2]
        require(len(roots) == 1, 'Expected exactly one top-level app in IPA')
        root = roots[0]
        for relative in HOSTS:
            prefix = root + relative
            info_data = archive.read(prefix + 'Info.plist')
            info = plistlib.loads(info_data)
            name = info['CFBundleExecutable']
            require(Path(name).name == name and name not in ('.', '..'), 'Invalid host executable name')
            host = Path(folder) / ('LiveProcess.appex' if relative else 'LiveContainer.app')
            if require_authorized:
                # Strict validation needs the complete sealed bundle. zipfile's extractor strips traversal.
                archive.extractall(folder)
                verify_app(Path(folder) / root, True)
                break
            host.mkdir()
            (host / 'Info.plist').write_bytes(info_data)
            (host / name).write_bytes(archive.read(prefix + name))
            if prefix + 'embedded.mobileprovision' in archive.namelist():
                (host / 'embedded.mobileprovision').write_bytes(archive.read(prefix + 'embedded.mobileprovision'))
            verify_host(host)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, action='append', default=[])
    parser.add_argument('--ipa', type=Path, action='append', default=[])
    parser.add_argument('--require-authorized', action='store_true', help='Also check profile payload, certificate membership and signature validity')
    args = parser.parse_args()
    verify_sources()
    for app in args.app:
        verify_app(app, args.require_authorized)
    for ipa in args.ipa:
        verify_ipa(ipa, args.require_authorized)
    print('Increased Memory Limit configuration checks passed')


if __name__ == '__main__':
    main()
