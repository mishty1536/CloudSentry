import os
import unittest
from unittest.mock import patch, Mock
from streamlit.testing.v1 import AppTest


class AppIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))

    def _get_operating_mode_radio(self, at):
        radios = [r for r in at.sidebar.radio if r.key == "operating_mode"]
        self.assertTrue(len(radios) > 0, "operating_mode radio not found in sidebar")
        return radios[0]

    def _get_button_by_label(self, at, text):
        buttons = [b for b in at.button if text in b.label]
        self.assertTrue(len(buttons) > 0, f"Button with text '{text}' not found")
        return buttons[0]

    def test_demo_mode_initial_load(self):
        with patch.dict(os.environ, {"CLOUDSENTRY_ENABLE_AWS_SCAN": "0"}):
            at = AppTest.from_file(self.app_path, default_timeout=15)
            at.run()
        self.assertFalse(at.exception)

        radio = self._get_operating_mode_radio(at)
        self.assertIn("Demo", radio.options)
        self.assertNotIn("AWS (read-only)", radio.options)
        self.assertEqual(radio.value, "Demo")

    def test_theme_toggle(self):
        at = AppTest.from_file(self.app_path, default_timeout=15)
        at.run()
        self.assertFalse(at.exception)

        theme_radios = [r for r in at.sidebar.radio if r.key == "theme_mode"]
        self.assertTrue(len(theme_radios) > 0)
        theme_radios[0].set_value("Light").run()
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state["theme_mode"], "Light")

    def test_demo_scan_execution_and_rendering(self):
        at = AppTest.from_file(self.app_path, default_timeout=15)
        at.run()

        # Click the Scan Configuration button in Demo mode
        btn = self._get_button_by_label(at, "Scan Configuration")
        btn.click().run()
        self.assertFalse(at.exception)

        # Metrics should be present
        metric_labels = [m.label for m in at.metric]
        self.assertIn("Total Findings", metric_labels)
        self.assertIn("Overall Risk Score", metric_labels)
        self.assertIn("Services Audited", metric_labels)

        # Findings dataframe should be displayed
        self.assertGreater(len(at.dataframe), 0)

        # Download buttons should be present
        download_labels = [db.label for db in at.download_button]
        self.assertIn("⬇️ Download Audit Report (CSV)", download_labels)
        self.assertIn("📊 Download Security Summary (CSV)", download_labels)

    def test_aws_scan_with_mocked_clients_and_pagination(self):
        aws_enabled = patch.dict(os.environ, {"CLOUDSENTRY_ENABLE_AWS_SCAN": "true"})
        aws_enabled.start()
        self.addCleanup(aws_enabled.stop)
        at = AppTest.from_file(self.app_path, default_timeout=15)
        at.run()

        # Switch to AWS (read-only) mode
        mode_radio = self._get_operating_mode_radio(at)
        mode_radio.set_value("AWS (read-only)").run()
        self.assertFalse(at.exception)

        # Mock findings simulating 52 live AWS findings (reproducing the Finding 50 scenario)
        mock_findings = {
            "s3": [
                {
                    "service": "S3",
                    "resource": "Account",
                    "severity": "Info",
                    "finding": "No S3 buckets were returned by the account-level listing. No bucket-level security checks were applicable.",
                    "recommendation": "No bucket-level checks were applicable.",
                }
            ],
            "iam": [
                {
                    "service": "IAM",
                    "severity": "High",
                    "finding": "Root account MFA is not enabled",
                    "recommendation": "Enable multi-factor authentication for the root user.",
                    "resource": "Account",
                }
            ] + [
                {
                    "service": "IAM",
                    "severity": "Medium",
                    "finding": f"Wildcard action or resource detected in policy {i}",
                    "recommendation": f"Replace unnecessary wildcard permissions in policy {i}.",
                    "resource": f"Policy:{i}",
                    "policy_name": f"Policy-{i}",
                    "policy_type": "Managed",
                    "attached_to": "Role:Admin",
                }
                for i in range(1, 49)
            ],
            "cloudtrail": [
                {
                    "service": "CloudTrail",
                    "severity": "Unknown",
                    "finding": "DescribeTrails could not be verified",
                    "recommendation": "No trail was returned for this region.",
                    "region": "us-east-1",
                },
                {
                    "service": "CloudTrail",
                    "severity": "High",
                    "finding": "CloudTrail trail is not currently logging",
                    "recommendation": "Review trail status.",
                    "region": "us-east-1",
                },
            ],
        }

        with patch("aws_auditor.create_aws_clients") as mock_create, \
             patch("aws_auditor.audit_aws_account", return_value=mock_findings):
            mock_create.return_value = (Mock(), Mock(), Mock())

            btn = self._get_button_by_label(at, "Start AWS scan")
            btn.click().run()
            self.assertFalse(at.exception)

            # Total findings metric: 1 + 49 + 2 = 52
            metrics = {m.label: m.value for m in at.metric}
            self.assertEqual(metrics.get("Total Findings"), "52")
            self.assertEqual(metrics.get("High Severity"), "2")

            # Check that pagination selector is rendered with 6 pages (52 items / 10 per page)
            page_selectors = [number for number in at.number_input if number.key == "rec_page_All_10"]
            self.assertEqual(len(page_selectors), 1)
            self.assertEqual(page_selectors[0].value, 1)

            # Test switching to page 2 of findings
            page_selectors[0].set_value(2).run()
            self.assertFalse(at.exception)

            # Check that download buttons exist and are rendered cleanly
            download_labels = [db.label for db in at.download_button]
            self.assertIn("⬇️ Download Audit Report (CSV)", download_labels)
            self.assertIn("📊 Download Security Summary (CSV)", download_labels)

    def test_aws_scan_error_handling(self):
        aws_enabled = patch.dict(os.environ, {"CLOUDSENTRY_ENABLE_AWS_SCAN": "true"})
        aws_enabled.start()
        self.addCleanup(aws_enabled.stop)
        at = AppTest.from_file(self.app_path, default_timeout=15)
        at.run()

        # Switch to AWS (read-only) mode
        mode_radio = self._get_operating_mode_radio(at)
        mode_radio.set_value("AWS (read-only)").run()

        # Simulate exception during create_aws_clients
        with patch("aws_auditor.create_aws_clients", side_effect=Exception("No credentials found")):
            btn = self._get_button_by_label(at, "Start AWS scan")
            btn.click().run()
            self.assertFalse(at.exception)
            # Verify error alert is displayed
            self.assertTrue(any("AWS scan failed" in err.value for err in at.error))


if __name__ == "__main__":
    unittest.main()
