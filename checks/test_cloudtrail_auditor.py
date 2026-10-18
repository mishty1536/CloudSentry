import unittest

from cloudTrail_auditor import audit_cloudtrail_configuration


class AuditCloudTrailConfigurationTests(unittest.TestCase):
    def test_missing_configuration_is_unconfirmed(self):
        findings = audit_cloudtrail_configuration({})

        self.assertEqual([finding["severity"] for finding in findings], ["High", "Medium", "Medium"])
        self.assertTrue(all("unconfirmed" in finding["finding"] for finding in findings))

    def test_malformed_configuration_values_are_not_treated_as_enabled(self):
        findings = audit_cloudtrail_configuration({
            "logging_enabled": "false",
            "log_validation_enabled": 1,
            "multi_region_enabled": None,
        })

        self.assertEqual(len(findings), 3)
        self.assertTrue(all("unconfirmed" in finding["finding"] for finding in findings))

    def test_explicitly_insecure_values_are_reported(self):
        findings = audit_cloudtrail_configuration({
            "logging_enabled": False,
            "log_validation_enabled": False,
            "multi_region_enabled": False,
        })

        self.assertEqual([finding["severity"] for finding in findings], ["High", "Medium", "Medium"])
        self.assertNotIn("unconfirmed", " ".join(f["finding"] for f in findings))

    def test_non_mapping_configuration_does_not_raise(self):
        findings = audit_cloudtrail_configuration(None)

        self.assertEqual(len(findings), 3)

    def test_all_controls_enabled_returns_info_only(self):
        findings = audit_cloudtrail_configuration({
            "logging_enabled": True,
            "log_validation_enabled": True,
            "multi_region_enabled": True,
        })

        self.assertEqual([finding["severity"] for finding in findings], ["Info"])


if __name__ == "__main__":
    unittest.main()
