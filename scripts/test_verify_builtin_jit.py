import plistlib
import tempfile
import unittest
from pathlib import Path

from verify_builtin_jit import openstep, verify_app, verify_sources


class ProductChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.app = Path(self.folder.name) / 'LiveContainer.app'
        self.helper = self.app / 'PlugIns/LCJITHelper.appex'
        self.helper.mkdir(parents=True)
        self.info = {'CFBundleIdentifier': 'example.lc.JITHelper', 'CFBundleExecutable': 'LCJITHelper',
                     'CFBundleShortVersionString': '1', 'CFBundleVersion': '1', 'MinimumOSVersion': '26.0',
                     'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.ar.viewer',
                                     'NSExtensionPrincipalClass': 'LCJITHelperHandler'}}
        (self.app / 'Info.plist').write_bytes(plistlib.dumps({**self.info, 'CFBundleIdentifier': 'example.lc'}))
        self.write_helper()
        (self.helper / 'LCJITHelper').write_bytes(b'fixture only; no device testing')
        (self.app / 'universal.js').write_text('// fixture')
        notices = self.app / 'BuiltInJITNotices'
        notices.mkdir()
        for name in ['LICENSE-StikJIT-MPL-2.0.txt', 'LICENSE-idevice-MIT.txt', 'LICENSES-rppairing-crates.txt', 'NOTICE.txt']:
            (notices / name).write_text('fixture')

    def write_helper(self):
        (self.helper / 'Info.plist').write_bytes(plistlib.dumps(self.info))

    def test_complete_product(self):
        verify_app(self.app, inspect_macho=False)

    def test_missing_executable(self):
        (self.helper / 'LCJITHelper').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing helper executable'):
            verify_app(self.app, inspect_macho=False)

    def test_wrong_bundle_id_after_resigning(self):
        self.info['CFBundleIdentifier'] = 'other.app.JITHelper'
        self.write_helper()
        with self.assertRaisesRegex(ValueError, 'bundle ID'):
            verify_app(self.app, inspect_macho=False)

    def test_stale_helper_version(self):
        self.info['CFBundleVersion'] = '0'
        self.write_helper()
        with self.assertRaisesRegex(ValueError, 'CFBundleVersion mismatch'):
            verify_app(self.app, inspect_macho=False)

    def test_missing_notice(self):
        (self.app / 'BuiltInJITNotices/LICENSE-StikJIT-MPL-2.0.txt').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing notice'):
            verify_app(self.app, inspect_macho=False)

    def test_pairing_credentials_not_packaged(self):
        (self.helper / 'pairing-123-test.plist').write_bytes(b'fixture')
        with self.assertRaisesRegex(ValueError, 'private pairing data'):
            verify_app(self.app, inspect_macho=False)


class SourceChecks(unittest.TestCase):
    def test_pinned_sources_and_membership(self):
        verify_sources()

    def test_project_parser_rejects_duplicate_ids(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            openstep('{ objects = { A = {}; A = {}; }; }')


if __name__ == '__main__':
    unittest.main()
