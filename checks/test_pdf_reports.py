import re
import unittest
from unittest.mock import patch

import pandas as pd
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import LongTable

from pdf_reports import generate_pdf_report


class PdfAuditReportTests(unittest.TestCase):
    def test_detailed_report_uses_a4_landscape_and_preserves_finding_metadata(self):
        frame = pd.DataFrame([{
            "service": "IAM",
            "severity": "High",
            "finding": "Wildcard permissions are present",
            "recommendation": "Restrict the policy to required actions and resources.",
            "resource": "arn:aws:iam::123456789012:role/ExampleRole",
            "region": "ap-southeast-2",
            "policy_name": "ExamplePolicy",
            "policy_type": "Customer managed",
            "attached_to": "Role:ExampleRole",
            "policy_document": ["Action:*", "Resource:*"],
        }])
        captured = []

        def capture_table(data, *args, **kwargs):
            captured.append((data, kwargs))
            return LongTable(data, *args, **kwargs)

        with patch("pdf_reports.LongTable", side_effect=capture_table):
            pdf = generate_pdf_report(
                "CloudSentry Security Audit Report",
                frame,
                subtitle="Mode: AWS | Region: ap-southeast-2 | Total Findings: 1",
                notes=["Assessment status: Incomplete.", "CloudTrail coverage is partial."],
            )

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"/MediaBox [ 0 0 841.8898 595.2756 ]", pdf)
        self.assertEqual(len(captured), 2)
        self.assertTrue(all(kwargs["repeatRows"] == 1 for _, kwargs in captured))

        table_text = "\n".join(
            cell.getPlainText()
            for data, _ in captured
            for row in data
            for cell in row
        )
        for expected in (
            "Wildcard permissions are present",
            "Restrict the policy to required actions and resources.",
            "arn:aws:iam::123456789012:role/ExampleRole",
            "ap-southeast-2",
            "ExamplePolicy",
            "Customer managed",
            "Role:ExampleRole",
            "['Action:*', 'Resource:*']",
        ):
            self.assertIn(expected, table_text)

        main_widths = captured[0][1]["colWidths"]
        self.assertAlmostEqual(sum(main_widths), landscape(A4)[0] - 60, places=1)
        self.assertEqual(captured[0][1]["splitInRow"], 1)

    def test_long_reports_paginate_with_repeated_headers(self):
        frame = pd.DataFrame([
            {
                "service": "S3",
                "severity": "Medium",
                "finding": f"Finding {index}: " + "configuration detail " * 12,
                "recommendation": "Review the bucket configuration. " * 14,
                "resource": f"arn:aws:s3:::bucket-{index}-" + "long-resource-name-" * 6,
            }
            for index in range(45)
        ])
        captured = []

        def capture_table(data, *args, **kwargs):
            captured.append(kwargs)
            return LongTable(data, *args, **kwargs)

        with patch("pdf_reports.LongTable", side_effect=capture_table):
            pdf = generate_pdf_report("Detailed audit", frame, subtitle="Demo report")

        page_count = len(re.findall(rb"/Type\s*/Page\b", pdf))
        self.assertGreater(page_count, 1)
        self.assertTrue(captured)
        self.assertTrue(all(options["repeatRows"] == 1 for options in captured))

    def test_summary_report_uses_a4_portrait(self):
        frame = pd.DataFrame([{"Metric": "Total Findings", "Value": 3}])
        pdf = generate_pdf_report("Summary", frame, landscape_mode=False)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"/MediaBox [ 0 0 595.2756 841.8898 ]", pdf)

    def test_summary_columns_remain_a_regular_metric_value_table(self):
        frame = pd.DataFrame([{"Metric": "Assessment Status", "Value": "Incomplete"}])
        captured = []

        def capture_table(data, *args, **kwargs):
            captured.append(data)
            return LongTable(data, *args, **kwargs)

        with patch("pdf_reports.LongTable", side_effect=capture_table):
            generate_pdf_report("Summary", frame, landscape_mode=False)

        self.assertEqual(len(captured), 1)
        table_text = [cell.getPlainText() for row in captured[0] for cell in row]
        self.assertEqual(table_text, ["Metric", "Value", "Assessment Status", "Incomplete"])


if __name__ == "__main__":
    unittest.main()
