import unittest

from s3_auditor import audit_s3_configuration


class AuditS3ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.all_public_access_protections = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

    def audit(self, *, public_access=None, encryption_enabled=True):
        if public_access is None:
            public_access = self.all_public_access_protections.copy()
        return audit_s3_configuration({
            "block_public_access": public_access,
            "encryption_enabled": encryption_enabled,
        })

    def test_all_public_access_protections_enabled_returns_info_only(self):
        findings = self.audit()

        self.assertEqual([finding["severity"] for finding in findings], ["Info"])

    def test_each_disabled_public_access_protection_is_flagged(self):
        for setting in self.all_public_access_protections:
            with self.subTest(setting=setting):
                public_access = self.all_public_access_protections.copy()
                public_access[setting] = False

                findings = self.audit(public_access=public_access)

                self.assertIn("High", [finding["severity"] for finding in findings])

    def test_encryption_enabled_does_not_create_encryption_finding(self):
        findings = self.audit(encryption_enabled=True)

        self.assertNotIn("Medium", [finding["severity"] for finding in findings])

    def test_encryption_disabled_is_flagged(self):
        findings = self.audit(encryption_enabled=False)

        self.assertIn("Medium", [finding["severity"] for finding in findings])

    def test_missing_configuration_flags_unconfirmed_settings(self):
        findings = audit_s3_configuration({})

        severities = [finding["severity"] for finding in findings]
        self.assertIn("High", severities)
        self.assertIn("Medium", severities)

    def test_malformed_configuration_is_handled_as_unconfirmed(self):
        findings = audit_s3_configuration({
            "block_public_access": ["not", "a", "mapping"],
            "encryption_enabled": "false",
        })

        severities = [finding["severity"] for finding in findings]
        self.assertIn("High", severities)
        self.assertIn("Medium", severities)

    def test_non_mapping_configuration_does_not_raise(self):
        findings = audit_s3_configuration(None)

        severities = [finding["severity"] for finding in findings]
        self.assertIn("High", severities)
        self.assertIn("Medium", severities)


if __name__ == "__main__":
    unittest.main()
