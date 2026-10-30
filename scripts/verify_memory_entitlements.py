#!/usr/bin/env python3
"""Check guest-host signing inputs, archived apps and final IPAs (Apple tools required for products)."""
import argparse
import plistlib
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from verify_builtin_jit import ROOT, openstep, require

KEY = 'com.apple.developer.kernel.increased-memory-limit'
HOSTS = {'LiveContainer': 'entitlements.xml', 'LiveProcess': 'LiveProcess/LiveProcess.entitlements'}
BUNDLES = (Path('.'), Path('PlugIns/LiveProcess.appex'))


def verify_sources(root=ROOT):
    objects = openstep((root / 'LiveContainer.xcodeproj/project.pbxproj').read_text())['objects']
    targets = {obj['name']: obj for obj in objects.values() if obj.get('isa') == 'PBXNativeTarget'}
    for name, entitlement_file in HOSTS.items():
        entitlements = plistlib.loads((root / entitlement_file).read_bytes())
        require(entitlements.get(KEY) is True, f'{entitlement_file}: {KEY} must be Boolean true')
        configurations = objects[targets[name]['buildConfigurationList']]['buildConfigurations']
        require({objects[c]['name'] for c in configurations} >= {'Debug', 'Release'},
                f'{name}: missing Debug/Release configurations')
        for configuration in configurations:
            config = objects[configuration]
            settings = config['buildSettings']
            require(settings.get('CODE_SIGN_ENTITLEMENTS') == entitlement_file,
                    f'{name} {config["name"]}: wrong signing entitlement file')
            require(settings.get('CODE_SIGNING_ALLOWED', 'YES') != 'NO', f'{name}: signing disabled')
    # This pre-existing Catalyst template is retained, though it is not an iOS IPA input.
    catalyst = plistlib.loads((root / 'entitlements.catalyst.xml').read_bytes())
    require(catalyst.get(KEY) is True, 'Catalyst entitlement request was removed')


def executable_name(info):
    name = info['CFBundleExecutable']
    require(isinstance(name, str) and name not in ('', '.', '..') and '/' not in name and '\\' not in name,
            'Invalid bundle executable name')
    return name


def verify_app(app, require_profile=False):
    require(sys.platform == 'darwin', 'Product entitlement inspection requires macOS codesign/security')
    for relative in BUNDLES:
        bundle = app / relative
        info = plistlib.loads((bundle / 'Info.plist').read_bytes())
        binary = bundle / executable_name(info)
        require(binary.is_file(), f'Missing guest-host executable: {binary}')
        # Read the Mach-O signature itself, including after a sideloader re-signs it.
        signed = subprocess.check_output(['codesign', '-d', '--entitlements', ':-', str(binary)],
                                         stderr=subprocess.PIPE)
        entitlements = plistlib.loads(signed)
        require(entitlements.get(KEY) is True, f'{bundle.name}: signed {KEY} is missing or not true')
        profile = bundle / 'embedded.mobileprovision'
        require(profile.is_file() or not require_profile, f'{bundle.name}: provisioning profile required')
        if profile.is_file():
            decoded = subprocess.check_output(['security', 'cms', '-D', '-i', str(profile)],
                                              stderr=subprocess.PIPE)
            provision = plistlib.loads(decoded)
            require(provision.get('Entitlements', {}).get(KEY) is True,
                    f'{bundle.name}: provisioning profile does not grant {KEY}')
            print(f'{bundle.name}: signed entitlement and provisioning grant verified')
        else:
            print(f'{bundle.name}: signed entitlement verified; no profile (ad hoc artifact only)')


def verify_ipa(ipa, require_profile=False):
    # Copy only known guest-host files to fixed paths; never extract arbitrary ZIP paths.
    with tempfile.TemporaryDirectory() as folder, zipfile.ZipFile(ipa) as archive:
        apps = [name for name in archive.namelist()
                if name.startswith('Payload/') and name.count('/') == 2 and name.endswith('.app/Info.plist')]
        require(len(apps) == 1, 'IPA must contain exactly one top-level app')
        prefix = apps[0][:-len('Info.plist')]
        app = Path(folder) / 'LiveContainer.app'
        names = set(archive.namelist())
        for relative in BUNDLES:
            bundle = app / relative
            bundle.mkdir(parents=True)
            bundle_prefix = prefix + (relative.as_posix() + '/' if relative != Path('.') else '')
            info_data = archive.read(bundle_prefix + 'Info.plist')
            binary = executable_name(plistlib.loads(info_data))
            (bundle / 'Info.plist').write_bytes(info_data)
            (bundle / binary).write_bytes(archive.read(bundle_prefix + binary))
            profile = 'embedded.mobileprovision'
            if bundle_prefix + profile in names:
                (bundle / profile).write_bytes(archive.read(bundle_prefix + profile))
        verify_app(app, require_profile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--ipa', type=Path, action='append', default=[])
    parser.add_argument('--require-profile', action='store_true',
                        help='Require provisioning grants in both guest hosts, for device-signed products')
    args = parser.parse_args()
    verify_sources()
    if args.app:
        verify_app(args.app, args.require_profile)
    for ipa in args.ipa:
        print(f'Checking {ipa.name}')
        verify_ipa(ipa, args.require_profile)
    print('Memory entitlement validation passed' + (' (source configuration only)' if not args.app and not args.ipa else ''))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        sys.exit(f'Memory entitlement validation failed: {error}')
