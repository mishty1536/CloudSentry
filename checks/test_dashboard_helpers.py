import unittest

from dashboard_helpers import (
    assessment_status,
    calculate_risk_score,
    combine_findings,
    count_severity,
    make_findings_dataframe,
)


class DashboardHelperTests(unittest.TestCase):
    def test_empty_findings_have_zero_score(self):
        self.assertEqual(calculate_risk_score([]), 0)

    def test_mixed_severities_keep_existing_average_formula(self):
        findings = [
            {"severity": "High"},
            {"severity": "Medium"},
            {"severity": "Low"},
        ]

        # (10 + 5 + 2) / (3 * 10) * 100 = 56.67, rounded to 57.
        self.assertEqual(calculate_risk_score(findings), 57)

    def test_unknown_and_missing_severities_keep_formula_and_remain_countable(self):
        findings = [
            {"severity": "High"},
            {"severity": "Critical", "finding": "new severity value"},
            {"finding": "missing severity"},
        ]

        # Unknown values contribute zero points but remain in the denominator.
        self.assertEqual(calculate_risk_score(findings), 33)
        self.assertEqual(count_severity(findings, "Unknown"), 2)

    def test_unrecognized_severity_is_normalized_as_unknown(self):
        findings = combine_findings({"iam": [{"severity": "Critical", "finding": "new"}]})

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertEqual(findings[0]["severity_details"], "'Critical'")
        self.assertEqual(count_severity(findings, "Unknown"), 1)
        self.assertEqual(assessment_status(findings), "Incomplete")

    def test_assessment_status_uses_normalized_findings(self):
        self.assertEqual(assessment_status([]), "Complete")
        self.assertEqual(
            assessment_status([{"severity": "Unknown", "finding": "denied"}]),
            "Incomplete",
        )

    def test_combine_findings_retains_unexpected_records_and_service_fields(self):
        findings = combine_findings({
            "iam": [{"message": "record with unknown shape"}, None],
            "new_service": ["raw risky result"],
        })

        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["service"], "IAM")
        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertEqual(findings[0]["message"], "record with unknown shape")
        self.assertEqual(findings[1]["service"], "IAM")
        self.assertEqual(findings[1]["severity"], "Unknown")
        self.assertEqual(findings[2]["service"], "new_service")
        self.assertEqual(findings[2]["severity"], "Unknown")

    def test_dataframe_retains_extra_fields_and_represents_missing_fields(self):
        df = make_findings_dataframe([
            {"finding": "partial record", "raw_policy": "Action=*"},
            "unparsed record",
        ])

        self.assertIn("raw_policy", df.columns)
        self.assertEqual(df.loc[0, "severity"], "Unknown")
        self.assertEqual(df.loc[1, "finding"], "Unexpected finding data could not be parsed")
        self.assertEqual(len(df), 2)


if __name__ == "__main__":
    unittest.main()
