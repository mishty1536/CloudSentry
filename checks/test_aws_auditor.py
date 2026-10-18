import json
import unittest
from unittest.mock import Mock
from urllib.parse import quote

from botocore.exceptions import ClientError

from aws_auditor import (
    audit_aws_account,
    audit_cloudtrail_region,
    audit_iam_account,
    audit_s3_account,
    create_aws_clients,
)


def client_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": "mocked failure"}}, operation)


def iam_policy(statement):
    return {"Version": "2012-10-17", "Statement": [statement]}


def empty_iam_authorization_details(**overrides):
    response = {
        "IsTruncated": False,
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    response.update(overrides)
    return response


class AuditS3AccountTests(unittest.TestCase):
    def test_successful_bucket_checks(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "example-bucket"}]}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        findings = audit_s3_account(s3)

        self.assertTrue(any("Public Access" in f["finding"] for f in findings) is False)
        self.assertTrue(any("encryption configuration is present" in f["finding"] for f in findings))
        self.assertTrue(all(f["resource"] == "example-bucket" for f in findings))
        s3.list_buckets.assert_called_once_with(MaxBuckets=1000)

    def test_bucket_listing_follows_continuation_tokens(self):
        s3 = Mock()
        s3.list_buckets.side_effect = [
            {"Buckets": [], "ContinuationToken": "page-2"},
            {"Buckets": []},
        ]

        audit_s3_account(s3)

        self.assertEqual(s3.list_buckets.call_count, 2)
        self.assertEqual(s3.list_buckets.call_args_list[1].kwargs["ContinuationToken"], "page-2")

    def test_missing_bucket_configurations_are_not_reported_secure(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "example-bucket"}]}
        s3.get_public_access_block.side_effect = client_error(
            "NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock"
        )
        s3.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"
        )

        findings = audit_s3_account(s3)

        self.assertTrue(any(f["severity"] == "High" for f in findings))
        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))

    def test_access_denied_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "example-bucket"}]}
        s3.get_public_access_block.side_effect = client_error("AccessDenied", "GetPublicAccessBlock")
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        findings = audit_s3_account(s3)

        self.assertTrue(any(f["severity"] == "Unknown" and f.get("operation") == "GetPublicAccessBlock" for f in findings))
        self.assertFalse(any(f["severity"] == "High" for f in findings))

    def test_throttling_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.side_effect = client_error("SlowDown", "ListBuckets")

        findings = audit_s3_account(s3)

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertIn("throttled", findings[0]["recommendation"])

    def test_service_unavailable_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.side_effect = client_error("ServiceUnavailable", "ListBuckets")

        findings = audit_s3_account(s3)

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertIn("unavailable", findings[0]["recommendation"])

    def test_unexpected_bucket_response_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": "unexpected"}

        findings = audit_s3_account(s3)

        self.assertEqual(findings[0]["severity"], "Unknown")

    def test_unexpected_encryption_response_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "example-bucket"}]}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {"Unexpected": "response"}

        findings = audit_s3_account(s3)

        self.assertTrue(any(f["severity"] == "Unknown" and f.get("error_code") == "ValueError" for f in findings))

    def test_malformed_encryption_algorithm_is_unverified(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "example-bucket"}]}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": ["AES256"]}}]
            }
        }

        findings = audit_s3_account(s3)

        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))


class AuditIamAccountTests(unittest.TestCase):
    def test_successful_account_and_inline_and_managed_policy_checks(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        managed_arn = "arn:aws:iam::123456789012:policy/Example"
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "GroupDetailList": [],
            "RoleDetailList": [],
            "UserDetailList": [{
                "UserName": "alice",
                "UserPolicyList": [{"PolicyName": "inline", "PolicyDocument": iam_policy({
                    "Effect": "Allow", "Action": "*", "Resource": "*"
                })}],
                "AttachedManagedPolicies": [{"PolicyArn": managed_arn}],
            }],
            "Policies": [{
                "Arn": managed_arn,
                "PolicyName": "Example",
                "PolicyVersionList": [{
                    "IsDefaultVersion": True,
                    "Document": quote(json.dumps(iam_policy({
                        "Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::example"
                    })))
                }],
            }],
        }

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["finding"] == "Root account MFA is enabled" for f in findings))
        self.assertTrue(any(f["severity"] == "High" and f.get("policy_type") == "Inline" for f in findings))
        self.assertTrue(any(f["severity"] == "Medium" and f.get("policy_type") == "Managed" for f in findings))
        iam.get_account_authorization_details.assert_called_once()

    def test_missing_account_mfa_value_is_unverified(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {}}
        iam.get_account_authorization_details.return_value = empty_iam_authorization_details()

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["severity"] == "Unknown" and f.get("operation") == "GetAccountSummary" for f in findings))

    def test_access_denied_authorization_details_is_unverified(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.side_effect = client_error(
            "AccessDenied", "GetAccountAuthorizationDetails"
        )

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["severity"] == "Unknown" and f.get("operation") == "GetAccountAuthorizationDetails" for f in findings))

    def test_throttled_authorization_details_is_unverified(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.side_effect = client_error(
            "Throttling", "GetAccountAuthorizationDetails"
        )

        findings = audit_iam_account(iam)

        self.assertTrue(any("throttled" in f["recommendation"] for f in findings if f["severity"] == "Unknown"))

    def test_unexpected_policy_response_is_unverified(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.return_value = empty_iam_authorization_details(
            UserDetailList="unexpected"
        )

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))

    def test_omitted_required_collections_are_unverified_not_no_policies(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.return_value = {"IsTruncated": False}

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))
        self.assertFalse(any("No inline or attached" in f["finding"] for f in findings))

    def test_malformed_required_collection_is_unverified(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.return_value = empty_iam_authorization_details(
            Policies={"unexpected": "mapping"}
        )

        findings = audit_iam_account(iam)

        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))
        self.assertFalse(any("No inline or attached" in f["finding"] for f in findings))

    def test_explicit_empty_required_collections_are_valid(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.return_value = empty_iam_authorization_details()

        findings = audit_iam_account(iam)

        self.assertFalse(any(f["severity"] == "Unknown" for f in findings))
        self.assertTrue(any("No inline or attached" in f["finding"] for f in findings))

    def test_authorization_details_pagination_requires_complete_collection_pages(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.side_effect = [
            empty_iam_authorization_details(IsTruncated=True, Marker="page-2"),
            empty_iam_authorization_details(),
        ]

        findings = audit_iam_account(iam)

        self.assertFalse(any(f["severity"] == "Unknown" for f in findings))
        self.assertEqual(iam.get_account_authorization_details.call_count, 2)
        self.assertEqual(
            iam.get_account_authorization_details.call_args_list[1].kwargs["Marker"],
            "page-2",
        )


class AuditCloudTrailRegionTests(unittest.TestCase):
    def test_successful_regional_trail_checks(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": [{
            "Name": "regional-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/regional-trail",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
        }]}
        cloudtrail.get_trail_status.return_value = {"IsLogging": True}

        findings = audit_cloudtrail_region(cloudtrail, "us-east-1")

        self.assertEqual(findings[0]["severity"], "Info")
        self.assertEqual(findings[0]["region"], "us-east-1")
        cloudtrail.get_trail_status.assert_called_once_with(
            Name="arn:aws:cloudtrail:us-east-1:123456789012:trail/regional-trail"
        )

    def test_missing_trails_are_unverified_and_region_scoped(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": []}

        findings = audit_cloudtrail_region(cloudtrail, "ap-south-1")

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertEqual(findings[0]["region"], "ap-south-1")
        self.assertIn("other regions", findings[0]["recommendation"])

    def test_access_denied_is_unverified(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.side_effect = client_error("AccessDeniedException", "DescribeTrails")

        findings = audit_cloudtrail_region(cloudtrail, "us-east-1")

        self.assertEqual(findings[0]["severity"], "Unknown")

    def test_throttled_status_is_unverified(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": [{
            "Name": "trail", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
        }]}
        cloudtrail.get_trail_status.side_effect = client_error("ThrottlingException", "GetTrailStatus")

        findings = audit_cloudtrail_region(cloudtrail, "us-west-2")

        self.assertTrue(any(f["severity"] == "Unknown" and f.get("operation") == "GetTrailStatus" for f in findings))

    def test_missing_or_malformed_fields_are_unverified(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": [{"Name": "trail"}]}
        cloudtrail.get_trail_status.return_value = {"IsLogging": "yes"}

        findings = audit_cloudtrail_region(cloudtrail, "us-east-2")

        self.assertGreaterEqual(sum(f["severity"] == "Unknown" for f in findings), 3)

    def test_unexpected_trail_response_is_unverified(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": "unexpected"}

        findings = audit_cloudtrail_region(cloudtrail, "us-east-1")

        self.assertEqual(findings[0]["severity"], "Unknown")


class AuditAwsAccountTests(unittest.TestCase):
    def test_orchestrator_uses_only_injected_clients(self):
        s3 = Mock(list_buckets=Mock(return_value={"Buckets": []}))
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_authorization_details.return_value = empty_iam_authorization_details()
        cloudtrail = Mock(describe_trails=Mock(return_value={"trailList": []}))

        results = audit_aws_account(s3, iam, cloudtrail, "eu-west-1")

        self.assertEqual(set(results), {"s3", "iam", "cloudtrail"})
        self.assertFalse(any(f["severity"] != "Info" for f in results["iam"]))

    def test_client_factory_uses_injected_session_and_region(self):
        session = Mock()
        session_factory = Mock(return_value=session)

        create_aws_clients("eu-west-1", session_factory=session_factory)

        session_factory.assert_called_once_with(region_name="eu-west-1")
        self.assertEqual(
            [call.args[0] for call in session.client.call_args_list],
            ["s3", "iam", "cloudtrail"],
        )
        self.assertEqual(session.client.call_args_list[2].kwargs, {"region_name": "eu-west-1"})


if __name__ == "__main__":
    unittest.main()
