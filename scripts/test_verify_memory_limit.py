import datetime
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import verify_memory_limit as memory


class MemoryPackagingTests(unittest.TestCase):
    def setUp(self):
        self.entitlements = {
            memory.ENTITLEMENT: True,
            'application-identifier': 'TEAM.com.example.host',
            'com.apple.developer.team-identifier': 'TEAM',
        }
        self.now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        self.profile = {'Entitlements': self.entitlements.copy(), 'ExpirationDate': datetime.datetime(2027, 1, 1)}

    def issues(self):
        return memory.profile_issues(self.entitlements, self.profile, 'com.example.host', self.now)

    def test_authorized_payload(self):
        self.assertEqual(self.issues(), [])

    def test_profile_missing_entitlement(self):
        del self.profile['Entitlements'][memory.ENTITLEMENT]
        self.assertTrue(self.issues())

    def test_invalid_entitlement_values(self):
        for value in (False, 'true', 1, None):
            self.profile['Entitlements'][memory.ENTITLEMENT] = value
            self.assertTrue(self.issues())

    def test_expired_profile(self):
        self.profile['ExpirationDate'] = datetime.datetime(2025, 1, 1)
        self.assertTrue(self.issues())

    def test_incompatible_identifiers(self):
        self.profile['Entitlements']['application-identifier'] = 'OTHER.com.example.host'
        self.assertTrue(self.issues())
        self.profile['Entitlements']['application-identifier'] = 'TEAM.*'
        self.assertEqual(self.issues(), [])
        self.profile['Entitlements']['com.apple.developer.team-identifier'] = 'OTHER'
        self.assertTrue(self.issues())

    def test_signature_stripped_by_signer(self):
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder)
            (bundle / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'host', 'CFBundleIdentifier': 'com.example.host'}))
            for value in (None, False, 'true', 1):
                with self.assertRaises(ValueError):
                    memory.verify_host(bundle, read_plist=lambda command: {memory.ENTITLEMENT: value})

    def test_unsigned_profile_is_diagnostic_and_strict_check_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder)
            (bundle / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'host', 'CFBundleIdentifier': 'com.example.host'}))
            memory.verify_host(bundle, read_plist=lambda command: self.entitlements)
            with self.assertRaises(ValueError):
                memory.verify_host(bundle, True, read_plist=lambda command: self.entitlements)

    def test_ipa_checks_both_hosts(self):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / 'host.ipa'
            with zipfile.ZipFile(ipa, 'w') as archive:
                for relative in memory.HOSTS:
                    prefix = 'Payload/LiveContainer.app/' + relative
                    archive.writestr(prefix + 'Info.plist', plistlib.dumps({'CFBundleExecutable': 'host', 'CFBundleIdentifier': 'com.example.host'}))
                    archive.writestr(prefix + 'host', b'executable-fixture')
            with patch.object(memory, 'verify_host') as verify:
                memory.verify_ipa(ipa)
                self.assertEqual(verify.call_count, 2)

    def test_source_build_requests(self):
        memory.verify_sources()

    def test_strict_certificate_membership(self):
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder)
            (bundle / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'host', 'CFBundleIdentifier': 'com.example.host'}))
            (bundle / 'embedded.mobileprovision').write_bytes(b'profile-fixture')
            self.profile['ExpirationDate'] = datetime.datetime(2100, 1, 1)

            def read(command):
                return self.entitlements if command[0] == 'codesign' else self.profile

            def run(command, **kwargs):
                if '--extract-certificates' in command:
                    Path(command[3] + '0').write_bytes(b'synthetic-certificate')

            with patch.object(memory.subprocess, 'run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'signing certificate'):
                    memory.verify_host(bundle, True, read_plist=read)
                self.profile['DeveloperCertificates'] = [b'synthetic-certificate']
                memory.verify_host(bundle, True, read_plist=read)

    def test_profile_not_yet_valid(self):
        self.profile['CreationDate'] = datetime.datetime(2027, 1, 1)
        self.assertTrue(self.issues())


if __name__ == '__main__':
    unittest.main()
