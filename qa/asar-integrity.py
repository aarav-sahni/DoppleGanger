#!/usr/bin/python3
"""Regression coverage for Electron's sealed macOS ASAR integrity dictionary."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

spec = importlib.util.spec_from_file_location(
    'patcher', Path(__file__).resolve().parents[1] / 'engine/patch-deep-link.py')
patcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = patcher
spec.loader.exec_module(patcher)


class IntegrityTests(unittest.TestCase):
    old = bytes(range(32))
    new = bytes(reversed(range(32)))

    def slot(self, used=1, version=1, digest=None):
        return patcher.INTEGRITY_SENTINEL + bytes([used, version]) + (digest or self.old)

    def test_dictionary_serialization(self):
        # Electron sorts paths, then hashes path + algorithm + hash without separators.
        entries = {'Resources/z.asar': {'algorithm': 'SHA256', 'hash': 'bb'},
                   'Resources/a.asar': {'algorithm': 'SHA256', 'hash': 'aa'}}
        expected = hashlib.sha256(b'Resources/a.asarSHA256aaResources/z.asarSHA256bb').digest()
        self.assertEqual(patcher.dictionary_digest(entries), expected)

    def test_all_architecture_slots_updated_without_disabling_validation(self):
        data = b'prefix' + self.slot() + b'other slice' + self.slot() + b'suffix'
        expected = b'prefix' + self.slot(digest=self.new) + b'other slice' + self.slot(digest=self.new) + b'suffix'
        self.assertEqual(patcher.refresh_integrity_slots(data, self.old, self.new), expected)

    def test_legacy_frameworks_unchanged(self):
        for data in (b'older framework', self.slot(used=0, version=0)):
            self.assertEqual(patcher.refresh_integrity_slots(data, self.old, self.new), data)

    def test_malformed_and_mismatched_slots_rejected(self):
        for data in (self.slot(version=2), self.slot(used=2),
                     self.slot(digest=self.new), self.slot()[:-1]):
            with self.subTest(data=data), self.assertRaises(patcher.PatchError):
                patcher.refresh_integrity_slots(data, self.old, self.new)


if __name__ == '__main__':
    unittest.main()
