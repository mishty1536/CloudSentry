import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock
from urllib.parse import quote

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_auditor import (
    audit_aws_account,
    audit_cloudtrail_account_coverage,
    audit_cloudtrail_region,
    audit_iam_account,
    audit_s3_account,
    create_aws_clients,
    create_aws_clients_with_session,
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
    
    def test_empty_bucket_list_is_reported_as_no_buckets(self):
        s3 = Mock()
        s3.list_buckets.return_value = {"Buckets": []}

        findings = audit_s3_account(s3)

        self.assertTrue(any(
            "No S3 buckets were returned" in f["finding"]
            for f in findings
        ))
        self.assertFalse(any(
            f["severity"] == "Unknown"
            and f.get("operation") == "ListBuckets"
            for f in findings
        ))

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

    def test_omitted_bucket_collection_is_unverified_not_empty(self):
        s3 = Mock()
        s3.list_buckets.return_value = {}

        findings = audit_s3_account(s3)

        self.assertTrue(any(f["severity"] == "Unknown" for f in findings))
        self.assertFalse(any("No S3 buckets were returned" in f["finding"] for f in findings))

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
    def test_missing_optional_inline_policy_lists_are_treated_as_empty(self):
        iam = Mock()
        iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1}
        }
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "UserDetailList": [{"UserName": "CloudSentryUser"}],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }

        findings = audit_iam_account(iam)

        self.assertFalse(any(
            f["severity"] == "Unknown"
            and "UserPolicyList was missing" in f["finding"]
            for f in findings
        ))
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

    def test_aws_managed_service_linked_policy_is_contextual_and_not_suppressed(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        aws_arn = "arn:aws:iam::aws:policy/aws-service-role/ExampleServicePolicy"
        service_role_arn = "arn:aws:iam::aws:policy/service-role/ExampleServiceRolePolicy"
        customer_arn = "arn:aws:iam::123456789012:policy/CustomerWide"
        wildcard = quote(json.dumps(iam_policy({
            "Effect": "Allow", "Action": "*", "Resource": "*"
        })))
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [
                {
                    "RoleName": "AWSServiceRole",
                    "Path": "/aws-service-role/example.amazonaws.com/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": aws_arn}],
                },
                {
                    "RoleName": "CustomerRole",
                    "Path": "/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": customer_arn}],
                },
                {
                    "RoleName": "ServiceRole",
                    "Path": "/service-role/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": service_role_arn}],
                },
            ],
            "Policies": [
                {"Arn": arn, "PolicyName": arn.rsplit("/", 1)[-1], "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": wildcard}
                ]}
                for arn in (aws_arn, customer_arn, service_role_arn)
            ],
        }

        findings = audit_iam_account(iam)
        wildcard_findings = [
            f for f in findings
            if "wildcard" in f.get("recommendation", "").lower()
        ]
        aws_finding = next(f for f in wildcard_findings if f["policy_origin"] == "AWS-managed")
        customer_finding = next(f for f in wildcard_findings if f["policy_origin"] == "customer-managed")

        self.assertEqual(len(wildcard_findings), 3)
        self.assertEqual(aws_finding["policy_category"], "service-linked-role policy")
        self.assertEqual(aws_finding["principal_type"], "service-linked role")
        self.assertEqual(aws_finding["severity"], "Info")
        self.assertEqual(aws_finding["heuristic_severity"], "High")
        self.assertIn("AWS-managed", aws_finding["finding"])
        self.assertIn("not by itself proof", aws_finding["recommendation"])
        self.assertEqual(customer_finding["principal_type"], "IAM role")
        self.assertEqual(customer_finding["finding"], "Broad permissions across wildcard actions and resources")
        service_role_finding = next(
            f for f in wildcard_findings if f["policy_category"] == "service-role policy"
        )
        self.assertEqual(service_role_finding["principal_type"], "service role")

    def test_malformed_iam_policy_arns_are_unknown_and_never_downgraded(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        malformed_arns = [
            "arn:aws:iam::aws:role/aws-service-role/InvalidResource",
            "not-arn:aws:iam::aws:policy/aws-service-role/InvalidPrefix",
            "arn:aws:iam::not-an-account:policy/aws-service-role/InvalidOwner",
            "arn:aws:iam:us-east-1:aws:policy/aws-service-role/InvalidRegion",
        ]
        policy_document = quote(json.dumps(iam_policy({
            "Effect": "Allow", "Action": "*", "Resource": "*"
        })))
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [{
                "RoleName": "AWSServiceRole",
                "Path": "/aws-service-role/example.amazonaws.com/",
                "RolePolicyList": [],
                "AttachedManagedPolicies": [
                    {"PolicyArn": arn} for arn in malformed_arns
                ],
            }],
            "Policies": [
                {
                    "Arn": arn,
                    "PolicyName": f"InvalidPolicy{index}",
                    "PolicyVersionList": [{
                        "IsDefaultVersion": True,
                        "Document": policy_document,
                    }],
                }
                for index, arn in enumerate(malformed_arns)
            ],
        }

        findings = audit_iam_account(iam)
        malformed_policy_findings = [
            finding for finding in findings
            if finding.get("policy_type") == "Managed"
            and finding.get("policy_name", "").startswith("InvalidPolicy")
        ]

        self.assertEqual(len(malformed_policy_findings), len(malformed_arns))
        for finding in malformed_policy_findings:
            with self.subTest(policy=finding["policy_name"]):
                self.assertEqual(finding["policy_origin"], "unknown")
                self.assertEqual(finding["policy_category"], "unknown")
                self.assertEqual(finding["severity"], "High")
                self.assertNotIn("heuristic_severity", finding)

    def test_shared_service_linked_policy_is_not_downgraded_for_mixed_principals(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        policy_arn = "arn:aws:iam::aws:policy/aws-service-role/ExampleServicePolicy"
        policy_document = quote(json.dumps(iam_policy({
            "Effect": "Allow", "Action": "*", "Resource": "*"
        })))
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [
                {
                    "RoleName": "AWSServiceRole",
                    "Path": "/aws-service-role/example.amazonaws.com/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
                },
                {
                    "RoleName": "OrdinaryRole",
                    "Path": "/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
                },
            ],
            "Policies": [{
                "Arn": policy_arn,
                "PolicyName": "ExampleServicePolicy",
                "PolicyVersionList": [{"IsDefaultVersion": True, "Document": policy_document}],
            }],
        }

        findings = audit_iam_account(iam)
        wildcard = next(
            finding for finding in findings
            if finding.get("policy_name") == "ExampleServicePolicy"
            and "wildcard" in finding.get("recommendation", "").lower()
        )

        self.assertEqual(wildcard["severity"], "High")
        self.assertNotIn("heuristic_severity", wildcard)
        self.assertIn("IAM role", wildcard["principal_type"])
        self.assertIn("OrdinaryRole", wildcard["attached_to"])

    def test_incomplete_principal_inventory_prevents_service_linked_downgrade(self):
        iam = Mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        policy_arn = "arn:aws:iam::aws:policy/aws-service-role/ExampleServicePolicy"
        policy_document = quote(json.dumps(iam_policy({
            "Effect": "Allow", "Action": "*", "Resource": "*"
        })))
        iam.get_account_authorization_details.return_value = {
            "IsTruncated": False,
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [
                {
                    "RoleName": "AWSServiceRole",
                    "Path": "/aws-service-role/example.amazonaws.com/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
                },
                {
                    "RoleName": "IncompleteRole",
                    "Path": "/",
                    "RolePolicyList": [],
                },
                {
                    "Path": "/aws-service-role/unknown.amazonaws.com/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
                },
            ],
            "Policies": [{
                "Arn": policy_arn,
                "PolicyName": "ExampleServicePolicy",
                "PolicyVersionList": [{"IsDefaultVersion": True, "Document": policy_document}],
            }],
        }

        findings = audit_iam_account(iam)
        wildcard = next(
            finding for finding in findings
            if finding.get("policy_name") == "ExampleServicePolicy"
            and "wildcard" in finding.get("recommendation", "").lower()
        )

        self.assertEqual(wildcard["severity"], "High")
        self.assertNotIn("heuristic_severity", wildcard)
        self.assertTrue(any(finding["severity"] == "Unknown" for finding in findings))

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

    def test_missing_trails_are_reported_for_selected_region(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": []}

        findings = audit_cloudtrail_region(cloudtrail, "ap-south-1")

        self.assertEqual(findings[0]["severity"], "Medium")
        self.assertEqual(findings[0]["region"], "ap-south-1")
        self.assertIn("other regions", findings[0]["recommendation"])
        self.assertIn("organization-wide", findings[0]["recommendation"])
        self.assertIn("selected region", findings[0]["finding"])
        self.assertEqual(findings[0]["coverage_scope"], "selected region only")

    def test_regional_trail_is_not_flagged_if_multi_region_trail_covers_region(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": [
            {
                "Name": "regional-trail", "HomeRegion": "ap-southeast-2",
                "IsMultiRegionTrail": False, "LogFileValidationEnabled": True,
            },
            {
                "Name": "organization-trail", "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": True, "IsOrganizationTrail": True,
                "LogFileValidationEnabled": True,
            },
        ]}
        cloudtrail.get_trail_status.return_value = {"IsLogging": True}

        findings = audit_cloudtrail_region(cloudtrail, "ap-southeast-2")

        self.assertFalse(any("No multi-region" in f["finding"] for f in findings))
        self.assertFalse(any(
            "multi-region coverage is not enabled" in f["finding"] for f in findings
        ))
        self.assertTrue(any(f["severity"] == "Info" for f in findings))

    def test_only_regional_trails_report_limited_scope(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": [{
            "Name": "regional", "HomeRegion": "ap-southeast-2",
            "IsMultiRegionTrail": False, "LogFileValidationEnabled": True,
        }]}
        cloudtrail.get_trail_status.return_value = {"IsLogging": True}

        findings = audit_cloudtrail_region(cloudtrail, "ap-southeast-2")

        coverage = next(f for f in findings if "No multi-region" in f["finding"])
        self.assertEqual(coverage["severity"], "Medium")
        self.assertIn("selected region", coverage["recommendation"])

    def test_unsupported_cloudtrail_operation_is_unverified_not_absent(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.side_effect = client_error(
            "UnsupportedOperationException", "DescribeTrails"
        )

        findings = audit_cloudtrail_region(cloudtrail, "mock-region-1")

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertEqual(findings[0]["error_code"], "UnsupportedOperationException")
        self.assertIn("unsupported", findings[0]["recommendation"])
        self.assertFalse(any("No CloudTrail trail" in f["finding"] for f in findings))

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

    def test_missing_or_malformed_multi_region_flag_has_unknown_trail_scope(self):
        for case, flag in (("missing", None), ("malformed", "true")):
            with self.subTest(case=case):
                trail = {"Name": "trail", "LogFileValidationEnabled": False}
                if case == "malformed":
                    trail["IsMultiRegionTrail"] = flag
                cloudtrail = Mock()
                cloudtrail.describe_trails.return_value = {"trailList": [trail]}
                cloudtrail.get_trail_status.return_value = {"IsLogging": True}

                findings = audit_cloudtrail_region(cloudtrail, "ap-southeast-2")

                validation = next(
                    finding for finding in findings
                    if finding.get("finding") == "CloudTrail log file validation is not enabled"
                )
                self.assertEqual(validation["trail_scope"], "unknown")
                self.assertTrue(any(
                    finding["severity"] == "Unknown"
                    and finding.get("operation") == "DescribeTrails"
                    for finding in findings
                ))

    def test_unexpected_trail_response_is_unverified(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {"trailList": "unexpected"}

        findings = audit_cloudtrail_region(cloudtrail, "us-east-1")

        self.assertEqual(findings[0]["severity"], "Unknown")

    def test_omitted_trail_collection_is_unverified_not_no_trail(self):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = {}

        findings = audit_cloudtrail_region(cloudtrail, "us-east-1")

        self.assertEqual(findings[0]["severity"], "Unknown")
        self.assertNotIn("No CloudTrail trail was returned", findings[0]["finding"])


class AuditCloudTrailAccountCoverageTests(unittest.TestCase):
    def setUp(self):
        self.regions_client = Mock()
        self.regions_client.describe_regions.return_value = {"Regions": [
            {"RegionName": "ap-southeast-2", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "us-east-1", "OptInStatus": "opted-in"},
        ]}

    def _assess(self, responses):
        clients = {}

        def trail_client(region):
            client = clients.setdefault(region, Mock())
            response = responses.get(region)
            if isinstance(response, Exception):
                client.describe_trails.side_effect = response
            else:
                client.describe_trails.return_value = response
            return client

        result = audit_cloudtrail_account_coverage(
            lambda: self.regions_client,
            trail_client,
        )
        return result, clients

    def test_multi_region_organization_trail_and_shadow_duplicates_are_deduplicated(self):
        trail = {
            "Name": "org-audit",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-audit",
            "HomeRegion": "us-east-1",
            "IsMultiRegionTrail": True,
            "IsOrganizationTrail": True,
        }
        self.regions_client.describe_regions.return_value["Regions"].append(
            {"RegionName": "us-west-1", "OptInStatus": "not-opted-in"}
        )
        result, clients = self._assess({
            "ap-southeast-2": {"trailList": [dict(trail)]},
            "us-east-1": {"trailList": [dict(trail)]},
        })

        self.assertEqual(result["coverage_status"], "complete")
        self.assertEqual(result["covered_regions"], ["ap-southeast-2", "us-east-1"])
        self.assertEqual(result["uncovered_regions"], [])
        self.assertEqual(result["not_enabled_regions"], ["us-west-1"])
        self.assertEqual(len(result["trails"]), 1)
        self.assertTrue(result["trails"][0]["is_organization_trail"])
        self.assertEqual(result["trails"][0]["observed_regions"], ["ap-southeast-2", "us-east-1"])
        self.assertEqual(set(clients), {"ap-southeast-2", "us-east-1"})
        self.regions_client.describe_regions.assert_called_once_with(AllRegions=True)

    def test_partial_access_keeps_denied_region_unverified_and_reports_confirmed_gap(self):
        self.regions_client.describe_regions.return_value["Regions"].append(
            {"RegionName": "eu-west-1", "OptInStatus": "opted-in"}
        )
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": [{
                "Name": "regional", "HomeRegion": "ap-southeast-2",
                "IsMultiRegionTrail": False,
            }]},
            "us-east-1": client_error("AccessDeniedException", "DescribeTrails"),
            "eu-west-1": {"trailList": []},
        })
        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["covered_regions"], ["ap-southeast-2"])
        self.assertEqual(result["uncovered_regions"], ["eu-west-1"])
        denied = next(item for item in result["unverified_regions"] if item["region"] == "us-east-1")
        self.assertEqual(denied["error_code"], "AccessDeniedException")

    def test_empty_response_confirms_only_that_region_has_no_returned_trail(self):
        self.regions_client.describe_regions.return_value["Regions"].append(
            {"RegionName": "eu-west-1", "OptInStatus": "opted-in"}
        )
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": []},
            "us-east-1": client_error("UnrecognizedClientException", "DescribeTrails"),
            "eu-west-1": {"trailList": []},
        })
        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["uncovered_regions"], ["ap-southeast-2", "eu-west-1"])
        self.assertIn("us-east-1", result["unverified_region_names"])
        self.assertFalse(result["coverage_is_complete"])

    def test_authentication_failure_while_listing_regions_is_unknown_not_absent(self):
        self.regions_client.describe_regions.side_effect = client_error(
            "UnrecognizedClientException", "DescribeRegions"
        )
        result = audit_cloudtrail_account_coverage(lambda: self.regions_client, Mock())
        self.assertEqual(result["coverage_status"], "unknown")
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(result["enabled_regions"], [])
        self.assertEqual(result["uncovered_regions"], [])
        self.assertEqual(result["unverified_regions"][0]["error_code"], "UnrecognizedClientException")
        self.assertIn("authentication failed", result["unverified_regions"][0]["reason"])

    def test_malformed_region_and_trail_responses_remain_unverified(self):
        self.regions_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "ap-southeast-2", "OptInStatus": "opted-in"},
                {"RegionName": "us-east-1"},
            ]
        }
        result, _ = self._assess({"ap-southeast-2": {"trailList": [{
            "Name": "missing-scope", "HomeRegion": "ap-southeast-2",
        }]}})
        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["uncovered_regions"], [])
        self.assertTrue(result["unverified_regions"])

        self.regions_client.describe_regions.return_value = {"Regions": [
            {"RegionName": "ap-southeast-2", "OptInStatus": "opted-in"},
        ]}
        result, _ = self._assess({"ap-southeast-2": {"trailList": "not-a-list"}})
        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["uncovered_regions"], [])
        self.assertEqual(result["unverified_regions"][0]["region"], "ap-southeast-2")

    def test_unsupported_region_operation_does_not_claim_absence(self):
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": []},
            "us-east-1": client_error("InvalidRegionException", "DescribeTrails"),
        })
        self.assertEqual(result["coverage_status"], "partial")
        self.assertNotIn("us-east-1", result["uncovered_regions"])
        self.assertIn("us-east-1", result["unverified_region_names"])

    def test_regional_trail_covers_only_its_home_region(self):
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": [{
                "Name": "regional", "HomeRegion": "ap-southeast-2",
                "IsMultiRegionTrail": False, "IsOrganizationTrail": False,
            }]},
            "us-east-1": {"trailList": []},
        })
        self.assertEqual(result["coverage_status"], "complete")
        self.assertEqual(result["covered_regions"], ["ap-southeast-2"])
        self.assertEqual(result["uncovered_regions"], ["us-east-1"])
        self.assertFalse(result["coverage_is_complete"])

    def test_conflicting_duplicate_scope_is_unverified_without_expanded_coverage(self):
        arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/shared"
        regional = {
            "Name": "shared", "TrailARN": arn, "HomeRegion": "us-east-1",
            "IsMultiRegionTrail": False,
        }
        conflicting_shadow = {
            **regional,
            "HomeRegion": "ap-southeast-2",
            "IsMultiRegionTrail": True,
        }
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": [conflicting_shadow]},
            "us-east-1": {"trailList": [regional]},
        })

        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["covered_regions"], [])
        self.assertEqual(result["uncovered_regions"], [])
        self.assertEqual(result["unverified_region_names"], ["ap-southeast-2", "us-east-1"])

    def test_regional_trail_outside_home_does_not_confirm_home_without_home_response(self):
        trail = {
            "Name": "regional", "TrailARN": "arn:aws:cloudtrail:ap-southeast-2:123456789012:trail/regional",
            "HomeRegion": "ap-southeast-2", "IsMultiRegionTrail": False,
        }
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": []},
            "us-east-1": {"trailList": [trail]},
        })

        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["covered_regions"], [])
        self.assertEqual(result["uncovered_regions"], [])
        self.assertEqual(result["unverified_region_names"], ["ap-southeast-2", "us-east-1"])

    def test_home_region_response_confirms_regional_trail_after_inconsistent_shadow_result(self):
        trail = {
            "Name": "regional", "TrailARN": "arn:aws:cloudtrail:ap-southeast-2:123456789012:trail/regional",
            "HomeRegion": "ap-southeast-2", "IsMultiRegionTrail": False,
        }
        result, _ = self._assess({
            "ap-southeast-2": {"trailList": [trail]},
            "us-east-1": {"trailList": [trail]},
        })

        self.assertEqual(result["coverage_status"], "partial")
        self.assertEqual(result["covered_regions"], ["ap-southeast-2"])
        self.assertNotIn("ap-southeast-2", result["unverified_region_names"])
        self.assertIn("us-east-1", result["unverified_region_names"])


class AuditAwsAccountTests(unittest.TestCase):
    def test_successful_scan_uses_current_botocore_request_and_response_models(self):
        # Explicit dummy credentials prevent credential-provider lookup. Every
        # API response is served by Stubber; no network or AWS account is used.
        session = boto3.Session(
            aws_access_key_id="unit-test-key",
            aws_secret_access_key="unit-test-secret",
            region_name="ap-southeast-2",
        )
        s3 = session.client("s3")
        iam = session.client("iam")
        cloudtrail = session.client("cloudtrail")
        s3_stub = Stubber(s3)
        iam_stub = Stubber(iam)
        cloudtrail_stub = Stubber(cloudtrail)

        s3_stub.add_response(
            "list_buckets",
            {
                "Buckets": [{
                    "Name": "unit-test-bucket",
                    "CreationDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                }],
                "Owner": {"DisplayName": "Unit Test", "ID": "unit-test-owner"},
            },
            {"MaxBuckets": 1000},
        )
        s3_stub.add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }},
            {"Bucket": "unit-test-bucket"},
        )
        s3_stub.add_response(
            "get_bucket_encryption",
            {"ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }},
            {"Bucket": "unit-test-bucket"},
        )
        iam_stub.add_response(
            "get_account_summary",
            {"SummaryMap": {"AccountMFAEnabled": 1}},
            {},
        )
        iam_stub.add_response(
            "get_account_authorization_details",
            empty_iam_authorization_details(),
            {"Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"], "MaxItems": 1000},
        )
        cloudtrail_stub.add_response(
            "describe_trails",
            {"trailList": []},
            {"includeShadowTrails": True},
        )

        with s3_stub, iam_stub, cloudtrail_stub:
            results = audit_aws_account(s3, iam, cloudtrail, "ap-southeast-2")
            s3_stub.assert_no_pending_responses()
            iam_stub.assert_no_pending_responses()
            cloudtrail_stub.assert_no_pending_responses()

        self.assertEqual(set(results), {"s3", "iam", "cloudtrail"})
        self.assertFalse(any(item["severity"] == "Unknown" for values in results.values() for item in values))

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

    def test_client_factory_uses_explicit_credentials(self):
        session = Mock()
        session_factory = Mock(return_value=session)

        create_aws_clients(
            "ap-southeast-2",
            session_factory=session_factory,
            aws_access_key_id="TESTKEYID",
            aws_secret_access_key="TESTSECRETKEY",
            aws_session_token="TESTTOKEN",
        )

        session_factory.assert_called_once_with(
            region_name="ap-southeast-2",
            aws_access_key_id="TESTKEYID",
            aws_secret_access_key="TESTSECRETKEY",
            aws_session_token="TESTTOKEN",
        )

    def test_session_returning_factory_reuses_one_session_for_all_clients(self):
        session = Mock()
        session_factory = Mock(return_value=session)

        returned_session, clients = create_aws_clients_with_session(
            "ap-southeast-2", session_factory=session_factory
        )

        self.assertIs(returned_session, session)
        self.assertEqual(len(clients), 3)
        session_factory.assert_called_once_with(region_name="ap-southeast-2")
        self.assertEqual(
            [call.args[0] for call in session.client.call_args_list],
            ["s3", "iam", "cloudtrail"],
        )


if __name__ == "__main__":
    unittest.main()
