import unittest

from iam_auditor import audit_iam_policy


class AuditIamPolicyTests(unittest.TestCase):
    def audit_statement(self, statement):
        return audit_iam_policy({"Version": "2012-10-17", "Statement": statement})

    def test_malformed_policy_structures_are_reported(self):
        invalid_inputs = [
            None,
            [],
            {},
            {"Statement": "not a statement"},
            {"Statement": [None]},
            {"Statement": [{"Effect": "Allow", "Action": [None], "Resource": "*"}]},
        ]
        for policy in invalid_inputs:
            with self.subTest(policy=policy):
                findings = audit_iam_policy(policy)
                self.assertTrue(findings)
                self.assertTrue(any(f["severity"] != "Info" for f in findings))

    def test_wildcard_action_and_resource_are_high_severity(self):
        findings = self.audit_statement({"Effect": "Allow", "Action": "*", "Resource": "*"})

        self.assertIn("High", [finding["severity"] for finding in findings])

    def test_service_wildcard_action_is_detected(self):
        findings = self.audit_statement({
            "Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::example"
        })

        self.assertIn("Medium", [finding["severity"] for finding in findings])

    def test_wildcard_resource_is_detected(self):
        findings = self.audit_statement({
            "Effect": "Allow", "Action": "s3:GetObject", "Resource": ["*"]
        })

        self.assertIn("Medium", [finding["severity"] for finding in findings])

    def test_not_action_is_reviewed_but_not_flagged_by_itself(self):
        findings = self.audit_statement({
            "Effect": "Allow",
            "NotAction": ["iam:CreateAccessKey"],
            "Resource": "arn:aws:iam::123456789012:user/example",
        })

        self.assertEqual([finding["severity"] for finding in findings], ["Info"])
        self.assertIn("contextual review", findings[0]["finding"])

    def test_not_resource_is_reviewed_but_not_flagged_by_itself(self):
        findings = self.audit_statement({
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "NotResource": "arn:aws:s3:::sensitive/*",
        })

        self.assertEqual([finding["severity"] for finding in findings], ["Info"])

    def test_condition_alone_is_not_flagged_as_a_vulnerability(self):
        findings = self.audit_statement({
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example",
            "Condition": {"Bool": {"aws:SecureTransport": "true"}},
        })

        self.assertEqual([finding["severity"] for finding in findings], ["Info"])
        self.assertIn("Condition", findings[0]["recommendation"])

    def test_malformed_condition_is_reported(self):
        findings = self.audit_statement({
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example/*",
            "Condition": "not a mapping",
        })

        self.assertIn("Medium", [finding["severity"] for finding in findings])


if __name__ == "__main__":
    unittest.main()
