"""Read-only AWS inventory checks used by CloudSentry's explicit AWS mode.

All clients are supplied by the caller. The module never obtains credentials
or creates AWS clients itself; ``create_aws_clients`` is only called from the
explicit scan action in the UI.
"""

import json
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from cloudTrail_auditor import audit_cloudtrail_configuration
from iam_auditor import audit_iam_policy
from s3_auditor import audit_s3_configuration


def _unverified(service, operation, reason, resource=None, region=None):
    item = {
        "service": service,
        "severity": "Unknown",
        "finding": f"{operation} could not be verified",
        "recommendation": reason,
        "operation": operation,
    }
    if resource:
        item["resource"] = resource
    if region:
        item["region"] = region
    return item


def _error_reason(error):
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "UnknownError")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__

    lowered = str(code).lower()
    if "accessdenied" in lowered or "unauthorized" in lowered or code in {"403", "AccessDeniedException"}:
        return "AWS denied this read-only check. Grant only its documented read permission or retain this unverified result."
    if "throttl" in lowered or "slowdown" in lowered or "requestlimit" in lowered:
        return "AWS throttled this read-only check. Retry later; this result is unverified."
    if "unavailable" in lowered or "internalerror" in lowered or "endpointconnection" in lowered:
        return "The AWS service or endpoint is unavailable. Retry later; this result is unverified."
    return "The AWS response could not be verified. Review the operation and retry if appropriate."


def _error_code(error):
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code", "UnknownError")
    if isinstance(error, BotoCoreError):
        return type(error).__name__
    return type(error).__name__


def _operation_error(service, operation, error, resource=None, region=None):
    item = _unverified(service, operation, _error_reason(error), resource, region)
    item["error_code"] = _error_code(error)
    return item


def _add_context(finding, *, region=None, resource=None, **context):
    item = dict(finding)
    if region:
        item["region"] = region
    if resource:
        item["resource"] = resource
    item.update(context)
    return item


def _parse_policy_document(document):
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        parsed = json.loads(unquote(document))
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("Policy document is not a JSON object")


def _response_list(response, key, service, operation, findings):
    if key not in response:
        findings.append(_unverified(
            service,
            operation,
            f"AWS omitted the required {key} collection. This part of the scan is unverified.",
        ))
        return None
    value = response[key]
    if not isinstance(value, list):
        findings.append(_unverified(
            service,
            operation,
            f"AWS returned an unexpected {key} value. This part of the scan is unverified.",
        ))
        return None
    return value


def audit_s3_account(s3_client):
    """Inspect listed general-purpose buckets' bucket-level controls only."""
    findings = []
    buckets = []
    continuation_token = None
    seen_tokens = set()
    listing_complete = True
    while True:
        request = {"MaxBuckets": 1000}
        if continuation_token:
            request["ContinuationToken"] = continuation_token
        try:
            response = s3_client.list_buckets(**request)
        except (ClientError, BotoCoreError) as error:
            findings.append(_operation_error("S3", "ListBuckets", error))
            listing_complete = False
            break

        if not isinstance(response, dict) or (
            "Buckets" in response and not isinstance(response["Buckets"], list)
        ):
            findings.append(_unverified(
                "S3", "ListBuckets", "AWS returned an unexpected bucket list. Bucket coverage is unverified."
            ))
            listing_complete = False
            break
        buckets.extend(response.get("Buckets", []))
        continuation_token = response.get("ContinuationToken")
        if continuation_token is None:
            break
        if (
            not isinstance(continuation_token, str)
            or not continuation_token
            or continuation_token in seen_tokens
        ):
            findings.append(_unverified(
                "S3", "ListBuckets", "AWS returned incomplete bucket pagination data. Bucket coverage is unverified."
            ))
            listing_complete = False
            break
        seen_tokens.add(continuation_token)

    for bucket in buckets:
        if not isinstance(bucket, dict) or not isinstance(bucket.get("Name"), str) or not bucket["Name"]:
            findings.append(_unverified(
                "S3", "ListBuckets", "AWS returned a malformed bucket entry; that bucket was not checked."
            ))
            continue
        name = bucket["Name"]

        try:
            public_response = s3_client.get_public_access_block(Bucket=name)
            public_config = public_response.get("PublicAccessBlockConfiguration") if isinstance(public_response, dict) else None
            if not isinstance(public_config, dict):
                raise ValueError("Unexpected public access block response")
        except ClientError as error:
            if _error_code(error) == "NoSuchPublicAccessBlockConfiguration":
                public_findings = audit_s3_configuration({
                    "block_public_access": {},
                    "encryption_enabled": True,
                })
                findings.extend(_add_context(item, resource=name) for item in public_findings if item["severity"] != "Info")
            else:
                findings.append(_operation_error("S3", "GetPublicAccessBlock", error, name))
        except (BotoCoreError, ValueError) as error:
            findings.append(_operation_error("S3", "GetPublicAccessBlock", error, name))
        else:
            public_findings = audit_s3_configuration({
                "block_public_access": public_config,
                "encryption_enabled": True,
            })
            findings.extend(_add_context(item, resource=name) for item in public_findings if item["severity"] != "Info")

        try:
            encryption_response = s3_client.get_bucket_encryption(Bucket=name)
            encryption_config = (
                encryption_response.get("ServerSideEncryptionConfiguration")
                if isinstance(encryption_response, dict)
                else None
            )
            rules = encryption_config.get("Rules") if isinstance(encryption_config, dict) else None
            if not isinstance(rules, list) or not rules:
                raise ValueError("Unexpected encryption response")
            encryption_enabled = all(
                isinstance(rule, dict)
                and isinstance(rule.get("ApplyServerSideEncryptionByDefault"), dict)
                and isinstance(
                    rule["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm"), str
                )
                and rule["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm")
                in {"AES256", "aws:kms", "aws:kms:dsse"}
                for rule in rules
            )
            if not encryption_enabled:
                findings.append(_unverified(
                    "S3",
                    "GetBucketEncryption",
                    "AWS returned an unsupported or malformed encryption rule. Configured encryption is unverified.",
                    name,
                ))
            else:
                findings.append(_add_context({
                    "service": "S3",
                    "severity": "Info",
                    "finding": "Default bucket encryption configuration is present",
                    "recommendation": "This check confirms a supported default encryption algorithm is configured; it does not inspect existing objects.",
                }, resource=name))
        except ClientError as error:
            if _error_code(error) == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_unverified(
                    "S3",
                    "GetBucketEncryption",
                    "No explicit bucket encryption configuration was returned. S3's automatic encryption behavior for new objects is outside this configuration check; verify requirements manually.",
                    name,
                ))
            else:
                findings.append(_operation_error("S3", "GetBucketEncryption", error, name))
        except (BotoCoreError, ValueError) as error:
            findings.append(_operation_error("S3", "GetBucketEncryption", error, name))

    if not buckets and listing_complete:
        findings.append(_unverified(
            "S3", "ListBuckets", "No buckets were returned. This confirms no bucket-level checks were performed."
        ))
    return findings


def _collect_iam_authorization_details(iam_client):
    details = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    findings = []
    marker = None
    seen_markers = set()

    while True:
        request = {
            "Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"],
            "MaxItems": 1000,
        }
        if marker:
            request["Marker"] = marker
        try:
            response = iam_client.get_account_authorization_details(**request)
        except (ClientError, BotoCoreError) as error:
            findings.append(_operation_error("IAM", "GetAccountAuthorizationDetails", error))
            return details, findings, False

        if not isinstance(response, dict):
            findings.append(_unverified(
                "IAM", "GetAccountAuthorizationDetails", "AWS returned an unexpected response shape. Policy coverage is unverified."
            ))
            return details, findings, False

        page_lists = {}
        page_valid = True
        for key in details:
            rows = _response_list(response, key, "IAM", "GetAccountAuthorizationDetails", findings)
            if rows is None:
                page_valid = False
            else:
                page_lists[key] = rows

        for key, rows in page_lists.items():
            details[key].extend(rows)

        if not page_valid:
            return details, findings, False

        truncated = response.get("IsTruncated")
        if truncated is False:
            return details, findings, not any(
                finding["operation"] == "GetAccountAuthorizationDetails" for finding in findings
            )
        if truncated is not True:
            findings.append(_unverified(
                "IAM", "GetAccountAuthorizationDetails", "AWS omitted a valid pagination status. Policy coverage is unverified."
            ))
            return details, findings, False

        marker = response.get("Marker")
        if not isinstance(marker, str) or not marker or marker in seen_markers:
            findings.append(_unverified(
                "IAM", "GetAccountAuthorizationDetails", "AWS returned incomplete pagination data. Policy coverage is unverified."
            ))
            return details, findings, False
        seen_markers.add(marker)


def audit_iam_account(iam_client):
    """Inspect account summary and returned inline/attached identity policies."""
    findings = []
    try:
        summary = iam_client.get_account_summary()
    except (ClientError, BotoCoreError) as error:
        findings.append(_operation_error("IAM", "GetAccountSummary", error))
    else:
        summary_map = summary.get("SummaryMap") if isinstance(summary, dict) else None
        if not isinstance(summary_map, dict) or "AccountMFAEnabled" not in summary_map:
            findings.append(_unverified(
                "IAM", "GetAccountSummary", "Account MFA status was missing or malformed in the account summary."
            ))
        elif summary_map["AccountMFAEnabled"] == 1:
            findings.append({
                "service": "IAM",
                "severity": "Info",
                "finding": "Root account MFA is enabled",
                "recommendation": "Continue protecting privileged account access.",
            })
        elif summary_map["AccountMFAEnabled"] == 0:
            findings.append({
                "service": "IAM",
                "severity": "High",
                "finding": "Root account MFA is not enabled",
                "recommendation": "Enable multi-factor authentication for the root user through the AWS console.",
            })
        else:
            findings.append(_unverified(
                "IAM", "GetAccountSummary", "AWS returned an unexpected AccountMFAEnabled value."
            ))

    details, detail_findings, complete = _collect_iam_authorization_details(iam_client)
    findings.extend(detail_findings)
    if not complete:
        # Keep any policies that were successfully returned, but explicitly
        # report incomplete coverage instead of treating the account as clean.
        pass

    policy_inventory_complete = complete

    attachments = {}
    inline_policy_count = 0
    for key, entity_type, name_key, inline_key in (
        ("UserDetailList", "User", "UserName", "UserPolicyList"),
        ("GroupDetailList", "Group", "GroupName", "GroupPolicyList"),
        ("RoleDetailList", "Role", "RoleName", "RolePolicyList"),
    ):
        for entity in details[key]:
            if not isinstance(entity, dict):
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM", "GetAccountAuthorizationDetails", f"AWS returned a malformed {entity_type} entry; its policies were not inspected."
                ))
                continue
            entity_name = entity.get(name_key, "Unknown")
            inline_policies = entity.get(inline_key)
            if inline_policies is None and inline_key not in entity:
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM", "GetAccountAuthorizationDetails", f"{inline_key} was missing for this {entity_type}; inline policies were not verified.", str(entity.get(name_key, "Unknown"))
                ))
                inline_policies = []
            if not isinstance(inline_policies, list):
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM", "GetAccountAuthorizationDetails", f"Inline policies for this {entity_type} were malformed.", str(entity_name)
                ))
                inline_policies = []
            for inline in inline_policies:
                inline_policy_count += 1
                policy_name = inline.get("PolicyName", "Unknown") if isinstance(inline, dict) else "Unknown"
                document = inline.get("PolicyDocument") if isinstance(inline, dict) else None
                try:
                    policy = _parse_policy_document(document)
                except (TypeError, ValueError, json.JSONDecodeError):
                    findings.append(_unverified(
                        "IAM", "InspectInlinePolicy", "Inline policy document was missing or malformed.", str(entity_name)
                    ))
                    continue
                findings.extend(_add_context(
                    item,
                    resource=f"{entity_type}:{entity_name}",
                    policy_name=policy_name,
                    policy_type="Inline",
                ) for item in audit_iam_policy(policy))

            attached = entity.get("AttachedManagedPolicies")
            if attached is None and "AttachedManagedPolicies" not in entity:
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM", "GetAccountAuthorizationDetails", f"AttachedManagedPolicies was missing for this {entity_type}; attachments were not verified.", str(entity_name)
                ))
                attached = []
            if not isinstance(attached, list):
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM", "GetAccountAuthorizationDetails", f"Attached managed policies for this {entity_type} were malformed.", str(entity_name)
                ))
                continue
            for policy_ref in attached:
                if not isinstance(policy_ref, dict) or not isinstance(policy_ref.get("PolicyArn"), str):
                    policy_inventory_complete = False
                    findings.append(_unverified(
                        "IAM", "GetAccountAuthorizationDetails", "AWS returned a malformed attached managed policy reference.", str(entity_name)
                    ))
                    continue
                arn = policy_ref["PolicyArn"]
                attachments.setdefault(arn, []).append(f"{entity_type}:{entity_name}")

    managed_by_arn = {}
    for policy in details["Policies"]:
        if not isinstance(policy, dict) or not isinstance(policy.get("Arn"), str):
            findings.append(_unverified(
                "IAM", "GetAccountAuthorizationDetails", "AWS returned a malformed managed policy entry."
            ))
            continue
        versions = policy.get("PolicyVersionList", [])
        if not isinstance(versions, list):
            findings.append(_unverified(
                "IAM", "GetAccountAuthorizationDetails", "Managed policy versions were malformed.", policy.get("Arn")
            ))
            continue
        default_versions = [
            version for version in versions
            if isinstance(version, dict) and version.get("IsDefaultVersion") is True
        ]
        if len(default_versions) != 1:
            if policy["Arn"] in attachments:
                findings.append(_unverified(
                    "IAM", "InspectManagedPolicy", "Attached managed policy default version was unavailable or ambiguous.", policy["Arn"]
                ))
            continue
        managed_by_arn[policy["Arn"]] = (policy, default_versions[0])

    for arn, principals in attachments.items():
        managed = managed_by_arn.get(arn)
        if managed is None:
            findings.append(_unverified(
                "IAM", "InspectManagedPolicy", "An attached managed policy document was not returned by AWS.", arn
            ))
            continue
        policy_metadata, version = managed
        try:
            document = _parse_policy_document(version.get("Document"))
        except (TypeError, ValueError, json.JSONDecodeError):
            findings.append(_unverified(
                "IAM", "InspectManagedPolicy", "Attached managed policy document was missing or malformed.", arn
            ))
            continue
        findings.extend(_add_context(
            item,
            resource=arn,
            policy_name=policy_metadata.get("PolicyName", arn),
            policy_type="Managed",
            attached_to=", ".join(principals),
        ) for item in audit_iam_policy(document))

    if policy_inventory_complete and not attachments and inline_policy_count == 0:
        findings.append({
            "service": "IAM",
            "severity": "Info",
            "finding": "No inline or attached managed identity policies were returned",
            "recommendation": "This check covers identity permission policies returned by IAM; it does not calculate effective permissions.",
        })
    return findings


def audit_cloudtrail_region(cloudtrail_client, region):
    """Inspect trail configuration and logging status in one AWS region."""
    findings = []
    try:
        response = cloudtrail_client.describe_trails(includeShadowTrails=True)
    except (ClientError, BotoCoreError) as error:
        return [_operation_error("CloudTrail", "DescribeTrails", error, region=region)]

    if not isinstance(response, dict) or (
        "trailList" in response and not isinstance(response["trailList"], list)
    ):
        return [_unverified(
            "CloudTrail", "DescribeTrails", "AWS returned an unexpected trail list. Trail coverage is unverified.", region=region
        )]
    trails = response.get("trailList", [])
    if not trails:
        return [_unverified(
            "CloudTrail",
            "DescribeTrails",
            "No trail was returned for this region. This regional result does not establish trail coverage in other regions.",
            region=region,
        )]

    for trail in trails:
        if not isinstance(trail, dict):
            findings.append(_unverified(
                "CloudTrail", "DescribeTrails", "AWS returned a malformed trail entry.", region=region
            ))
            continue
        trail_arn = trail.get("TrailARN")
        name = trail_arn or trail.get("Name")
        trail_label = str(name or "Unknown trail")
        for key, field_label, severity in (
            ("IsMultiRegionTrail", "multi-region coverage", "Medium"),
            ("LogFileValidationEnabled", "log file validation", "Medium"),
        ):
            value = trail.get(key)
            if value is True:
                continue
            if value is False:
                findings.append(_add_context({
                    "service": "CloudTrail",
                    "severity": severity,
                    "finding": f"CloudTrail {field_label} is not enabled",
                    "recommendation": f"Review and enable {field_label} where required.",
                }, region=region, resource=trail_label))
            else:
                findings.append(_unverified(
                    "CloudTrail", "DescribeTrails", f"AWS did not return a valid {field_label} value.", trail_label, region
                ))

        if not name:
            findings.append(_unverified(
                "CloudTrail", "GetTrailStatus", "AWS returned a trail without a usable name or ARN.", region=region
            ))
            continue
        try:
            status = cloudtrail_client.get_trail_status(Name=name)
        except (ClientError, BotoCoreError) as error:
            findings.append(_operation_error("CloudTrail", "GetTrailStatus", error, trail_label, region))
            continue
        if not isinstance(status, dict) or not isinstance(status.get("IsLogging"), bool):
            findings.append(_unverified(
                "CloudTrail", "GetTrailStatus", "AWS returned a missing or malformed logging status.", trail_label, region
            ))
        elif status["IsLogging"] is False:
            findings.append(_add_context({
                "service": "CloudTrail",
                "severity": "High",
                "finding": "CloudTrail trail is not currently logging",
                "recommendation": "Review trail status and restore logging through an approved change process.",
            }, region=region, resource=trail_label))

    if not findings:
        findings.append({
            "service": "CloudTrail",
            "severity": "Info",
            "finding": f"Supported CloudTrail checks passed in {region}",
            "recommendation": "This result covers returned trail configuration and status in the selected region only.",
            "region": region,
        })
    return findings


def audit_aws_account(s3_client, iam_client, cloudtrail_client, region):
    """Run AWS checks using already-created, injectable Boto3 clients."""
    return {
        "s3": audit_s3_account(s3_client),
        "iam": audit_iam_account(iam_client),
        "cloudtrail": audit_cloudtrail_region(cloudtrail_client, region),
    }


def create_aws_clients(region, session_factory=None):
    """Create clients through Boto3's standard credential provider chain.

    This function performs no API operation. Call it only after explicit user
    action; it does not accept, persist, or display credentials.
    """
    if session_factory is None:
        import boto3
        session_factory = boto3.Session
    session = session_factory(region_name=region)
    return (
        session.client("s3"),
        session.client("iam"),
        session.client("cloudtrail", region_name=region),
    )
