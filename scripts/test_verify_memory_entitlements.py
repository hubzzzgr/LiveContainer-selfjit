import contextlib
import io
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from verify_memory_entitlements import BUNDLES, KEY, verify_app, verify_ipa, verify_sources


class MemoryEntitlementChecks(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.app = self.folder / 'LiveContainer.app'
        for relative in BUNDLES:
            bundle = self.app / relative
            bundle.mkdir(parents=True)
            (bundle / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'Host'}))
            (bundle / 'Host').write_bytes(b'fixture')

    def inspect(self, signed=True, provision=True, required=False, ipa=None):
        def output(command, **kwargs):
            return plistlib.dumps({KEY: signed} if command[0] == 'codesign'
                                  else {'Entitlements': {KEY: provision}})
        with patch('verify_memory_entitlements.sys.platform', 'darwin'), \
                patch('verify_memory_entitlements.subprocess.check_output', side_effect=output), \
                contextlib.redirect_stdout(io.StringIO()):
            if ipa:
                verify_ipa(ipa, require_profile=required)
            else:
                verify_app(self.app, require_profile=required)

    def test_signing_inputs(self):
        verify_sources()

    def test_ad_hoc_artifact(self):
        self.inspect()

    def test_rejects_stripped_or_non_boolean_signature(self):
        for value in (False, 1, 'true'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'signed .* missing or not true'):
                self.inspect(signed=value)

    def test_missing_profile_in_device_mode(self):
        with self.assertRaisesRegex(ValueError, 'profile required'):
            self.inspect(required=True)

    def test_profiles_for_both_processes(self):
        for relative in BUNDLES:
            (self.app / relative / 'embedded.mobileprovision').write_bytes(b'CMS fixture')
        self.inspect(required=True)
        with self.assertRaisesRegex(ValueError, 'profile does not grant'):
            self.inspect(provision=False)

    def test_missing_liveprocess(self):
        (self.app / BUNDLES[1] / 'Host').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing guest-host executable'):
            self.inspect()

    def test_final_ipa(self):
        ipa = self.folder / 'LiveContainer+SideStore.ipa'
        with zipfile.ZipFile(ipa, 'w') as archive:
            for file in self.app.rglob('*'):
                if file.is_file():
                    archive.write(file, 'Payload/LiveContainer.app/' + file.relative_to(self.app).as_posix())
        self.inspect(ipa=ipa)
        with self.assertRaisesRegex(ValueError, 'signed .* missing or not true'):
            self.inspect(ipa=ipa, signed=False)

    @unittest.skipUnless(sys.platform == 'darwin', 'Requires Apple signing tools')
    def test_real_ad_hoc_signatures_and_ipa(self):
        binary = self.folder / 'Host'
        subprocess.run(['xcrun', 'clang', '-x', 'c', '-', '-o', str(binary)],
                       input='int main(void) { return 0; }', text=True, check=True)
        entitlements = self.folder / 'entitlements.plist'
        entitlements.write_bytes(plistlib.dumps({KEY: True}))
        for relative in BUNDLES:
            host = self.app / relative / 'Host'
            host.write_bytes(binary.read_bytes())
            subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', str(entitlements), str(host)],
                           check=True, capture_output=True)
        verify_app(self.app)
        ipa = self.folder / 'LiveContainer.ipa'
        with zipfile.ZipFile(ipa, 'w') as archive:
            for file in self.app.rglob('*'):
                if file.is_file():
                    archive.write(file, 'Payload/LiveContainer.app/' + file.relative_to(self.app).as_posix())
        verify_ipa(ipa)
        # Re-sign only LiveProcess without the entitlement to exercise its independent signature.
        entitlements.write_bytes(plistlib.dumps({KEY: False}))
        subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', str(entitlements),
                        str(self.app / BUNDLES[1] / 'Host')],
                       check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'LiveProcess.appex: signed .* missing or not true'):
            verify_app(self.app)


if __name__ == '__main__':
    unittest.main()
