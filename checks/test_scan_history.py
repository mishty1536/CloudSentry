import os
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from scan_history import (
    ScanHistoryError,
    ScanHistoryStore,
    compare_scans,
    comparison_findings_dataframe,
    comparison_summary_rows,
    cloudtrail_describe_access_denied,
    cloudtrail_describe_scp_denied,
    cloudtrail_coverage_label,
    default_database_path,
    scan_assessment_status,
    service_assessment_statuses,
)


def finding(severity, title, resource, recommendation="Review the resource."):
    return {
        "service": "S3",
        "severity": severity,
        "finding": title,
        "resource": resource,
        "recommendation": recommendation,
        "custom_context": {"retained": True},
    }


class ScanHistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "history" / "scan_history.db"
        self.store = ScanHistoryStore(self.database_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def save(self, mode="Demo", region=None, findings=None, risk=0, status=None, coverage=None, scanned_at=None):
        return self.store.save_scan(
            mode=mode,
            region=region,
            findings=findings or [],
            risk_score=risk,
            assessment_status=status,
            coverage=coverage,
            scanned_at=scanned_at,
        )

    def test_initialization_creates_database_outside_source_by_default(self):
        with patch.dict(os.environ, {"CLOUDSENTRY_HISTORY_DB": str(self.database_path)}):
            self.assertEqual(default_database_path(), self.database_path)
        self.assertTrue(self.database_path.is_file())

    def test_save_retrieve_and_reopen_preserves_full_finding_data(self):
        original = self.save(
            findings=[finding("High", "Public access enabled", "bucket-a")],
            risk=80,
        )
        reopened = ScanHistoryStore(self.database_path).get_scan(original["scan_id"])

        self.assertEqual(reopened["scan_id"], original["scan_id"])
        self.assertEqual(reopened["findings"][0]["custom_context"], {"retained": True})
        self.assertEqual(reopened["severity_counts"]["High"], 1)
        self.assertEqual(reopened["risk_score"], 80)
        self.assertEqual(reopened["assessment_status"], "Complete")

    def test_snapshots_have_unique_ids_and_stable_timestamp_order(self):
        later_timestamp = self.save(scanned_at="2026-01-02T00:00:00+00:00")
        earlier_timestamp = self.save(scanned_at="2026-01-01T00:00:00+00:00")

        self.assertNotEqual(later_timestamp["scan_id"], earlier_timestamp["scan_id"])
        self.assertEqual(
            [x["scan_id"] for x in self.store.list_scans()],
            [later_timestamp["scan_id"], earlier_timestamp["scan_id"]],
        )
        self.assertGreater(earlier_timestamp["scan_number"], later_timestamp["scan_number"])

    def test_duplicate_scan_contents_are_saved_as_distinct_snapshots(self):
        data = [finding("Info", "Checks passed", "bucket-a")]
        first = self.save(findings=data, risk=0)
        second = self.save(findings=data, risk=0)

        self.assertNotEqual(first["scan_id"], second["scan_id"])
        self.assertEqual(len(self.store.list_scans()), 2)

    def test_demo_and_aws_histories_are_separate(self):
        demo = self.save(mode="Demo", findings=[finding("High", "Demo issue", "demo")])
        aws = self.save(mode="AWS (read-only)", region="ap-southeast-2", findings=[])

        self.assertEqual([row["scan_id"] for row in self.store.list_scans(mode="Demo")], [demo["scan_id"]])
        self.assertEqual([row["scan_id"] for row in self.store.list_scans(mode="AWS")], [aws["scan_id"]])
        self.assertEqual(self.store.list_scans(mode="AWS", region="us-east-1"), [])

    def test_unknown_findings_and_partial_account_coverage_mark_scan_incomplete(self):
        unknown = self.save(findings=[finding("Unknown", "Check unavailable", "bucket-a")])
        partial = self.save(
            mode="AWS",
            region="ap-southeast-2",
            findings=[],
            coverage={"coverage_status": "partial", "unverified_regions": [{"region": "us-east-1"}]},
        )

        self.assertEqual(unknown["assessment_status"], "Incomplete")
        self.assertEqual(partial["assessment_status"], "Incomplete")
        self.assertEqual(partial["coverage"]["unverified_regions"][0]["region"], "us-east-1")
        self.assertEqual(scan_assessment_status([], {"coverage_status": "unknown"}), "Incomplete")
        self.assertEqual(scan_assessment_status([], None, mode="AWS"), "Incomplete")
        explicit_complete = self.save(
            mode="AWS", region="us-east-1", findings=[], status="Complete", coverage=None
        )
        self.assertEqual(explicit_complete["assessment_status"], "Incomplete")

    def test_saved_scan_summary_retains_cloudtrail_access_denial_context(self):
        saved = self.save(
            mode="AWS",
            region="ap-southeast-2",
            findings=[
                {**finding("Info", "S3 checked", "bucket-a"), "service": "S3"},
                {**finding("Info", "IAM checked", "account"), "service": "IAM"},
            ],
            coverage={
                "coverage_status": "partial",
                "unverified_regions": [{
                    "region": "us-east-1",
                    "operation": "DescribeTrails",
                    "error_code": "AccessDenied",
                }],
            },
        )

        summary = self.store.list_scans(mode="AWS")[0]

        self.assertEqual(saved["assessment_status"], "Incomplete")
        self.assertEqual(summary["service_statuses"]["S3"], "Verified")
        self.assertEqual(summary["service_statuses"]["IAM"], "Verified")
        self.assertEqual(summary["service_statuses"]["CloudTrail"], "Partial / Unverified")
        self.assertTrue(summary["cloudtrail_describe_denied"])
        self.assertFalse(summary["cloudtrail_scp_denied"])

    def test_scp_attribution_requires_explicit_denial_source_evidence(self):
        access_denied = {
            "unverified_regions": [{
                "operation": "DescribeTrails",
                "error_code": "AccessDenied",
                "reason": "AWS denied this read-only request.",
            }],
        }
        confirmed_scp = {
            "unverified_regions": [{
                "operation": "DescribeTrails",
                "error_code": "AccessDenied",
                "reason": "Access denied by AWS Organizations SCP",
            }],
        }

        self.assertTrue(cloudtrail_describe_access_denied(access_denied))
        self.assertFalse(cloudtrail_describe_scp_denied(access_denied))
        self.assertTrue(cloudtrail_describe_scp_denied(confirmed_scp))
        self.assertEqual(cloudtrail_coverage_label({
            "cloudtrail_describe_denied": True,
            "cloudtrail_scp_denied": False,
        }), "Partial / Unverified - Access denied for DescribeTrails; source of denial not confirmed")
        self.assertEqual(cloudtrail_coverage_label({
            "cloudtrail_describe_denied": True,
            "cloudtrail_scp_denied": True,
        }), "Partial / Unverified - DescribeTrails denied by AWS Organizations SCP")

    def test_service_statuses_separate_verified_checks_from_partial_cloudtrail_coverage(self):
        findings = [
            {**finding("Info", "S3 check completed", "bucket-a"), "service": "S3"},
            {**finding("High", "IAM policy finding", "policy-a"), "service": "IAM"},
            {**finding("Unknown", "Trail inventory unavailable", "us-east-1"), "service": "CloudTrail"},
        ]
        coverage = {
            "coverage_status": "partial",
            "unverified_regions": [{
                "region": "us-east-1",
                "operation": "DescribeTrails",
                "error_code": "AccessDenied",
            }],
        }

        statuses = service_assessment_statuses(
            findings, coverage, mode="AWS (read-only)"
        )

        self.assertEqual(statuses["S3"], "Verified")
        self.assertEqual(statuses["IAM"], "Verified")
        self.assertEqual(statuses["CloudTrail"], "Partial / Unverified")
        self.assertEqual(
            scan_assessment_status(findings, coverage, mode="AWS (read-only)"),
            "Incomplete",
        )
        self.assertTrue(cloudtrail_describe_access_denied(coverage))
        self.assertFalse(cloudtrail_describe_access_denied({"unverified_regions": []}))

    def test_clean_checked_service_can_be_marked_verified(self):
        statuses = service_assessment_statuses(
            [], mode="Demo", checked_services={"S3", "IAM", "CloudTrail"}
        )

        self.assertEqual(set(statuses.values()), {"Verified"})

    def test_failed_scan_is_not_created_by_storage_api(self):
        self.assertEqual(self.store.list_scans(), [])

    def test_missing_database_is_initialized_and_missing_schema_is_reported(self):
        fresh_path = Path(self.temporary_directory.name) / "fresh" / "history.db"
        fresh_store = ScanHistoryStore(fresh_path)
        self.assertEqual(fresh_store.list_scans(), [])

        uninitialized = ScanHistoryStore.__new__(ScanHistoryStore)
        uninitialized.path = Path(self.temporary_directory.name) / "uninitialized.db"
        with self.assertRaises(ScanHistoryError):
            uninitialized.list_scans()

    def test_sqlite_errors_are_reported_without_raw_database_details(self):
        with patch("scan_history.sqlite3.connect", side_effect=sqlite3.OperationalError("locked")):
            with self.assertRaisesRegex(ScanHistoryError, "Could not initialize"):
                ScanHistoryStore(Path(self.temporary_directory.name) / "locked.db")

    def test_concurrent_writes_are_transactional(self):
        def write(index):
            return self.store.save_scan(
                mode="Demo",
                region=None,
                findings=[finding("Low", f"Finding {index}", f"resource-{index}")],
                risk_score=20,
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            records = list(executor.map(write, range(20)))

        summaries = self.store.list_scans(mode="Demo")
        self.assertEqual(len(records), 20)
        self.assertEqual(len(summaries), 20)
        self.assertEqual(len({item["scan_id"] for item in summaries}), 20)

    def test_concurrent_store_initialization_uses_one_schema_safely(self):
        shared_path = Path(self.temporary_directory.name) / "shared" / "concurrent.db"
        with ThreadPoolExecutor(max_workers=6) as executor:
            stores = list(executor.map(lambda _: ScanHistoryStore(shared_path), range(6)))

        self.assertEqual(len(stores[0].list_scans()), 0)
        saved = stores[0].save_scan(mode="Demo", region=None, findings=[], risk_score=0)
        self.assertEqual(stores[-1].get_scan(saved["scan_id"])["scan_id"], saved["scan_id"])


class ScanComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store = ScanHistoryStore(Path(self.temporary_directory.name) / "history.db")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def save(self, findings, risk, status="Complete", mode="Demo", region=None, coverage=None):
        return self.store.save_scan(
            mode=mode,
            region=region,
            findings=findings,
            risk_score=risk,
            assessment_status=status,
            coverage=coverage,
        )

    def test_comparison_classifies_resolved_remaining_and_new_findings(self):
        before = self.save([
            finding("High", "Public access", "bucket-a"),
            finding("Medium", "No encryption", "bucket-b"),
        ], 75)
        after = self.save([
            finding("High", "Public access", "bucket-a", "Restrict access."),
            finding("Low", "Logging disabled", "bucket-c"),
        ], 40)

        result = compare_scans(before, after)
        self.assertEqual([x["resource"] for x in result["resolved"]], ["bucket-b"])
        self.assertEqual([x["resource"] for x in result["remaining"]], ["bucket-a"])
        self.assertEqual([x["resource"] for x in result["newly_detected"]], ["bucket-c"])

    def test_arbitrary_saved_snapshots_can_be_compared(self):
        oldest = self.save([finding("High", "Issue", "a")], 100)
        middle = self.save([finding("Medium", "Issue", "b")], 50)
        latest = self.save([finding("Low", "Issue", "c")], 20)

        result = compare_scans(self.store.get_scan(oldest["scan_id"]), self.store.get_scan(latest["scan_id"]))
        self.assertEqual(result["before_total"], 1)
        self.assertEqual(result["after_total"], 1)
        self.assertEqual(len(result["newly_detected"]), 1)
        self.assertEqual(middle["scan_number"], 2)

    def test_severity_and_risk_score_comparisons_are_returned(self):
        before = self.save([finding("High", "Issue", "a"), finding("Info", "OK", "b")], 50)
        after = self.save([finding("Low", "Issue", "a"), finding("Medium", "Other", "c")], 35)

        result = compare_scans(before, after)
        self.assertEqual(result["severity"]["High"], {"before": 1, "after": 0, "delta": -1})
        self.assertEqual(result["severity"]["Info"], {"before": 1, "after": 0, "delta": -1})
        self.assertEqual(result["risk_score_delta"], -15)

    def test_incomplete_after_scan_does_not_mark_absent_findings_resolved(self):
        before = self.save([finding("High", "Issue", "a")], 100)
        after = self.save([], 0, status="Incomplete")

        result = compare_scans(before, after)
        self.assertEqual(result["resolved"], [])
        self.assertEqual(result["unverified_before"][0]["resource"], "a")

    def test_incomplete_before_scan_does_not_claim_unmatched_findings_are_new(self):
        before = self.save([], 0, status="Incomplete")
        after = self.save([finding("High", "Issue", "a")], 100)

        result = compare_scans(before, after)
        self.assertEqual(result["newly_detected"], [])
        self.assertEqual(result["unverified_after"][0]["resource"], "a")

    def test_unknown_findings_are_never_claimed_resolved(self):
        before = self.save([finding("Unknown", "Check unavailable", "a")], 0, status="Incomplete")
        after = self.save([], 0, status="Complete")

        result = compare_scans(before, after)
        self.assertEqual(result["resolved"], [])
        self.assertEqual(len(result["unverified_before"]), 1)

    def test_partial_cloudtrail_still_compares_verified_s3_and_iam(self):
        before_findings = [
            {**finding("High", "Old S3 issue", "bucket-a"), "service": "S3"},
            {**finding("High", "Old IAM issue", "policy-a"), "service": "IAM"},
            {**finding("High", "Trail issue", "trail-a"), "service": "CloudTrail"},
        ]
        after_findings = [
            {**finding("Low", "New IAM issue", "policy-b"), "service": "IAM"},
        ]
        coverage = {
            "coverage_status": "partial",
            "unverified_regions": [{"operation": "DescribeTrails", "error_code": "AccessDenied"}],
            "checked_services": ["S3", "IAM", "CloudTrail"],
            "service_statuses": {
                "S3": "Verified", "IAM": "Verified", "CloudTrail": "Partial / Unverified"
            },
        }
        before = self.save(findings=before_findings, risk=70, mode="AWS", region="us-east-1", coverage=coverage)
        after = self.save(findings=after_findings, risk=20, mode="AWS", region="us-east-1", coverage=coverage)

        result = compare_scans(before, after)
        self.assertEqual(result["comparable_services"], ["S3", "IAM"])
        self.assertEqual([item["resource"] for item in result["resolved"]], ["bucket-a", "policy-a"])
        self.assertEqual([item["resource"] for item in result["newly_detected"]], ["policy-b"])
        self.assertEqual([item["resource"] for item in result["unverified_before"]], ["trail-a"])

    def test_service_verified_only_in_one_scan_is_not_comparable(self):
        base = {
            "coverage_status": "partial", "unverified_regions": [],
            "checked_services": ["S3", "IAM"],
            "service_statuses": {"S3": "Verified", "IAM": "Unverified", "CloudTrail": "Unverified"},
        }
        other = {
            **base, "checked_services": ["S3", "IAM"],
            "service_statuses": {"S3": "Unverified", "IAM": "Verified", "CloudTrail": "Unverified"},
        }
        before = self.save(findings=[{**finding("High", "S3 issue", "bucket-a"), "service": "S3"}], risk=100,
                          mode="AWS", region="us-east-1", coverage=base)
        after = self.save(findings=[], risk=0, mode="AWS", region="us-east-1", coverage=other)
        result = compare_scans(before, after)
        self.assertNotIn("S3", result["comparable_services"])
        self.assertEqual(result["resolved"], [])
        self.assertEqual(result["unverified_before"][0]["resource"], "bucket-a")

    def test_comparison_table_has_stable_columns_and_no_missing_values(self):
        frame = comparison_findings_dataframe([
            {"service": "S3", "severity": "High", "finding": "Issue", "resource": "bucket-a"},
            {"service": "IAM", "severity": "Low", "finding_title": "Other", "policy_arn": "arn:example"},
        ])
        self.assertEqual(list(frame.columns), ["Service", "Severity", "Finding", "Resource", "Recommendation"])
        self.assertFalse(frame.isna().any().any())
        self.assertEqual(frame.loc[1, "Finding"], "Other")
        self.assertEqual(frame.loc[1, "Resource"], "arn:example")

    def test_before_after_summary_rows_have_one_consistent_delta_column(self):
        coverage = {
            "coverage_status": "partial",
            "unverified_regions": [{"operation": "DescribeTrails", "error_code": "AccessDenied"}],
            "checked_services": ["S3", "IAM", "CloudTrail"],
            "service_statuses": {
                "S3": "Verified", "IAM": "Verified", "CloudTrail": "Partial / Unverified"
            },
        }
        before = self.save([
            {**finding("High", "S3 issue", "bucket-a"), "service": "S3"},
            {**finding("Medium", "IAM issue", "policy-a"), "service": "IAM"},
            {**finding("High", "Unavailable trail", "trail-a"), "service": "CloudTrail"},
        ], 17, mode="AWS", region="us-east-1", coverage=coverage)
        after = self.save([
            {**finding("Medium", "S3 issue", "bucket-a"), "service": "S3"},
            {**finding("Low", "IAM new issue", "policy-b"), "service": "IAM"},
        ], 62, mode="AWS", region="us-east-1", coverage=coverage)

        rows = comparison_summary_rows(compare_scans(before, after))
        frame = pd.DataFrame(rows)
        self.assertEqual(list(frame.columns), ["Measure", "Before", "After", "Change"])
        self.assertFalse(frame.isna().any().any())
        self.assertEqual(frame.loc[0].to_dict(), {
            "Measure": "Comparable service findings", "Before": 2, "After": 2, "Change": 0,
        })
        self.assertEqual(frame.loc[1].to_dict(), {
            "Measure": "High", "Before": 1, "After": 0, "Change": -1,
        })
        self.assertEqual(frame.loc[2].to_dict(), {
            "Measure": "Medium", "Before": 1, "After": 1, "Change": 0,
        })
        self.assertEqual(frame.loc[3].to_dict(), {
            "Measure": "Low", "Before": 0, "After": 1, "Change": 1,
        })
        self.assertEqual(frame.loc[5].to_dict(), {
            "Measure": "Risk score", "Before": 17, "After": 62, "Change": 45,
        })

    def test_comparison_summary_uses_na_when_no_services_are_comparable(self):
        before = self.save([], 0, status="Incomplete")
        after = self.save([], 0, status="Incomplete")
        frame = pd.DataFrame(comparison_summary_rows(compare_scans(before, after)))

        self.assertEqual(list(frame.columns), ["Measure", "Before", "After", "Change"])
        self.assertEqual(frame.loc[0].to_dict(), {
            "Measure": "Comparable service findings", "Before": "N/A",
            "After": "N/A", "Change": "N/A",
        })
        self.assertEqual(frame.loc[1, "Before"], "N/A")

    def test_identical_scans_are_detected_independent_of_finding_order(self):
        first = self.save(
            [finding("High", "Issue A", "a"), finding("Low", "Issue B", "b")],
            60,
            mode="AWS",
            region="ap-southeast-2",
            coverage={"coverage_status": "complete", "covered_regions": ["ap-southeast-2", "us-east-1"]},
        )
        second = self.save(
            [finding("Low", "Issue B", "b"), finding("High", "Issue A", "a")],
            60,
            mode="AWS",
            region="ap-southeast-2",
            coverage={"coverage_status": "complete", "covered_regions": ["us-east-1", "ap-southeast-2"]},
        )

        self.assertTrue(compare_scans(first, second)["identical"])

    def test_demo_aws_and_cross_region_comparisons_are_rejected(self):
        demo = self.save([], 0)
        aws = self.save([], 0, mode="AWS", region="ap-southeast-2")
        other_region = self.save([], 0, mode="AWS", region="us-east-1")

        with self.assertRaises(ValueError):
            compare_scans(demo, aws)
        with self.assertRaises(ValueError):
            compare_scans(aws, other_region)


if __name__ == "__main__":
    unittest.main()
