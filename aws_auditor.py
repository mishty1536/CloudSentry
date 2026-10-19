"""Read-only AWS inventory checks used by CloudSentry's explicit AWS mode.

All clients are supplied by the caller. The module never obtains credentials
or creates AWS clients itself; ``create_aws_clients`` is only called from the
explicit scan action in the UI.
"""

import json
import re
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
    if any(token in lowered for token in ("unrecognizedclient", "invalidclienttoken", "expiredtoken", "signaturedoesnotmatch", "invalidsignature")):
        return "AWS authentication failed for this read-only check. Coverage is unverified; verify the instance role or credential provider configuration."
    if "accessdenied" in lowered or "unauthorized" in lowered or code in {"403", "AccessDeniedException"}:
        return "AWS denied this read-only check. Grant only its documented read permission or retain this unverified result."
    if "throttl" in lowered or "slowdown" in lowered or "requestlimit" in lowered:
        return "AWS throttled this read-only check. Retry later; this result is unverified."
    if "unsupported" in lowered or "invalidregion" in lowered or "notavailableinregion" in lowered:
        return "This AWS operation or service is unsupported in the selected region. Coverage is unverified, not absent."
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


def _iam_policy_origin(policy_arn):
    """Classify managed policy ownership from its ARN without inferring risk."""
    if not isinstance(policy_arn, str):
        return "unknown", "unknown"
    parts = policy_arn.split(":", 5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not re.fullmatch(r"aws(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?", parts[1])
        or parts[2] != "iam"
        or parts[3] != ""
        or not parts[5].startswith("policy/")
    ):
        return "unknown", "unknown"

    policy_resource = parts[5][len("policy/"):]
    path_parts = policy_resource.split("/")
    if (
        not policy_resource
        or any(not part for part in path_parts)
        or any(
            not character.isascii()
            or character.isspace()
            or ord(character) < 33
            or ord(character) > 126
            for character in policy_resource
        )
        or ":" in policy_resource
        or not re.fullmatch(r"[A-Za-z0-9+=,.@_-]+", path_parts[-1])
    ):
        return "unknown", "unknown"

    if re.fullmatch(r"[0-9]{12}", parts[4]):
        return "customer-managed", "customer-managed"
    if parts[4] != "aws":
        return "unknown", "unknown"

    policy_path = policy_resource
    if policy_path.startswith("aws-service-role/"):
        return "AWS-managed", "service-linked-role policy"
    if policy_path.startswith("service-role/"):
        return "AWS-managed", "service-role policy"
    return "AWS-managed", "AWS-managed policy"


def _principal_context(entity_type, entity):
    name_key = {"User": "UserName", "Group": "GroupName", "Role": "RoleName"}[entity_type]
    raw_name = entity.get(name_key)
    name_is_valid = isinstance(raw_name, str) and bool(raw_name.strip())
    name = raw_name if name_is_valid else "Unknown"
    principal = f"{entity_type}:{name}"
    context = {
        "principal": principal,
        "principal_type": entity_type.lower(),
        "principal_identity_complete": name_is_valid,
    }
    if entity_type != "Role":
        return context

    path = entity.get("Path")
    context["principal_path"] = path if isinstance(path, str) else "Unknown"
    context["principal_identity_complete"] = (
        name_is_valid and isinstance(path, str) and bool(path)
    )
    if isinstance(path, str) and path.startswith("/aws-service-role/"):
        context["principal_type"] = "service-linked role"
    elif isinstance(path, str) and path.startswith("/service-role/"):
        context["principal_type"] = "service role"
    elif isinstance(path, str):
        context["principal_type"] = "IAM role"
    else:
        context["principal_type"] = "IAM role (path unavailable)"
    return context


def _contextualize_policy_findings(findings, *, origin, policy_category, principals,
                                   resource, policy_name, policy_type,
                                   attachment_inventory_complete=False):
    principal_names = [item["principal"] for item in principals]
    principal_types = sorted({item["principal_type"] for item in principals})
    principal_paths = sorted({
        item["principal_path"] for item in principals if "principal_path" in item
    })
    contextual = []
    for finding in findings:
        item = _add_context(
            finding,
            resource=resource,
            policy_name=policy_name,
            policy_type=policy_type,
            policy_origin=origin,
            policy_category=policy_category,
            attached_to=", ".join(principal_names),
            principal_type=", ".join(principal_types) if principal_types else "unknown",
        )
        if principal_paths:
            item["principal_path"] = ", ".join(principal_paths)
        is_wildcard_finding = (
            "wildcard" in str(item.get("finding", "")).lower()
            or "wildcard" in str(item.get("recommendation", "")).lower()
        )
        if origin == "AWS-managed" and is_wildcard_finding:
            item["finding"] = f"{item['finding']} (AWS-managed {policy_category})"
            item["recommendation"] = (
                f"{item['recommendation']} This policy is maintained by AWS; the wildcard pattern "
                "is a review signal, not by itself proof of a customer-authored policy defect. "
                "Confirm the documented AWS service use and that the policy is attached only "
                "to the intended principal."
            )
            all_principals_are_service_linked = bool(principals) and all(
                item.get("principal_type") == "service-linked role"
                and item.get("principal_identity_complete") is True
                and isinstance(item.get("principal_path"), str)
                and item["principal_path"].startswith("/aws-service-role/")
                for item in principals
            )
            if (
                policy_category == "service-linked-role policy"
                and attachment_inventory_complete
                and all_principals_are_service_linked
            ):
                item["heuristic_severity"] = item.get("severity", "Unknown")
                item["severity"] = "Info"
                item["finding"] += " (informational AWS-managed service-linked permissions pattern)"
                item["recommendation"] += (
                    " AWS manages this service-linked role and its permissions; this heuristic is "
                    "shown for visibility but is not scored as a customer-authored policy risk."
                )
        contextual.append(item)
    return contextual


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

        if (
            not isinstance(response, dict)
            or "Buckets" not in response
            or not isinstance(response["Buckets"], list)
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
        findings.append({
            "service": "S3",
            "resource": "Account",
            "severity": "Info",
            "finding": (
                "No S3 buckets were returned by the account-level listing. "
                "No bucket-level security checks were applicable."
            ),
            "recommendation": (
                "No bucket-level checks were applicable because no buckets were returned. "
                "Verify that the scan used the intended AWS account."
            ),
        })

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
            principal_info = _principal_context(entity_type, entity)
            inline_policies = entity.get(inline_key, [])

            if inline_policies is None:
                inline_policies = []

            if not isinstance(inline_policies, list):
                policy_inventory_complete = False
                findings.append(_unverified(
                    "IAM",
                    "GetAccountAuthorizationDetails",
                    f"Inline policies for this {entity_type} were malformed.",
                    str(entity_name),
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
                findings.extend(_contextualize_policy_findings(
                    audit_iam_policy(policy),
                    origin="customer-created inline policy",
                    policy_category="inline policy",
                    principals=[principal_info],
                    resource=f"{entity_type}:{entity_name}",
                    policy_name=policy_name,
                    policy_type="Inline",
                ))

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
                attachments.setdefault(arn, []).append(principal_info)

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
        origin, policy_category = _iam_policy_origin(arn)
        findings.extend(_contextualize_policy_findings(
            audit_iam_policy(document),
            origin=origin,
            policy_category=policy_category,
            principals=principals,
            resource=arn,
            policy_name=policy_metadata.get("PolicyName", arn),
            policy_type="Managed",
            attachment_inventory_complete=policy_inventory_complete,
        ))

    if policy_inventory_complete and not attachments and inline_policy_count == 0:
        findings.append({
            "service": "IAM",
            "severity": "Info",
            "finding": "No inline or attached managed identity policies were returned",
            "recommendation": "This check covers identity permission policies returned by IAM; it does not calculate effective permissions.",
        })
    return findings


def audit_cloudtrail_region(cloudtrail_client, region):
    """Inspect trails visible in one region, including associated shadow trails."""
    findings = []
    try:
        response = cloudtrail_client.describe_trails(includeShadowTrails=True)
    except (ClientError, BotoCoreError) as error:
        return [_operation_error("CloudTrail", "DescribeTrails", error, region=region)]

    if (
        not isinstance(response, dict)
        or "trailList" not in response
        or not isinstance(response["trailList"], list)
    ):
        return [_unverified(
            "CloudTrail", "DescribeTrails", "AWS returned an unexpected trail list. Trail coverage is unverified.", region=region
        )]
    trails = response.get("trailList", [])
    if not trails:
        return [{
            "service": "CloudTrail",
            "severity": "Medium",
            "finding": f"No CloudTrail trail was returned for the selected region ({region})",
            "recommendation": (
                "DescribeTrails returned no regional or associated shadow trail for this region. "
                "Review whether audit logging should cover it. This confirms only the selected-region "
                "response; it does not establish coverage in other regions or organization-wide."
            ),
            "operation": "DescribeTrails",
            "region": region,
            "coverage_scope": "selected region only",
        }]

    parsed_trails = [trail for trail in trails if isinstance(trail, dict)]
    has_multi_region_coverage = any(
        trail.get("IsMultiRegionTrail") is True for trail in parsed_trails
    )
    multi_region_status_known = len(parsed_trails) == len(trails) and all(
        isinstance(trail.get("IsMultiRegionTrail"), bool) for trail in parsed_trails
    )

    for trail in trails:
        if not isinstance(trail, dict):
            findings.append(_unverified(
                "CloudTrail", "DescribeTrails", "AWS returned a malformed trail entry.", region=region
            ))
            continue
        trail_arn = trail.get("TrailARN")
        name = trail_arn or trail.get("Name")
        trail_label = str(name or "Unknown trail")
        trail_is_multi_region = trail.get("IsMultiRegionTrail")
        if not isinstance(trail_is_multi_region, bool):
            findings.append(_unverified(
                "CloudTrail", "DescribeTrails", "AWS did not return a valid trail scope value; multi-region coverage is unverified.", trail_label, region
            ))

        home_region = trail.get("HomeRegion")
        if trail_is_multi_region is True:
            trail_scope = "multi-region"
        elif trail_is_multi_region is False:
            trail_scope = "regional"
        else:
            trail_scope = "unknown"
        if trail_scope != "unknown" and isinstance(home_region, str) and home_region:
            trail_scope += f" (home region: {home_region})"

        for key, field_label in (
            ("LogFileValidationEnabled", "log file validation"),
        ):
            value = trail.get(key)
            if value is True:
                continue
            if value is False:
                findings.append(_add_context({
                    "service": "CloudTrail",
                    "severity": "Medium",
                    "finding": f"CloudTrail {field_label} is not enabled",
                    "recommendation": f"Review and enable {field_label} where required.",
                }, region=region, resource=trail_label, trail_scope=trail_scope))
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
            # GetTrailStatus is regional. The ARN identifies a shadow trail;
            # querying this region's endpoint checks logging status here.
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
            }, region=region, resource=trail_label, trail_scope=trail_scope))

    if not has_multi_region_coverage:
        if multi_region_status_known:
            findings.append(_add_context({
                "service": "CloudTrail",
                "severity": "Medium",
                "finding": f"No multi-region CloudTrail trail was returned for {region}",
                "recommendation": (
                    "The returned trails are regional and do not by themselves establish coverage "
                    "in other regions. A successful scan confirms only the selected region; assess "
                    "other enabled regions and organization-level coverage separately."
                ),
            }, region=region, coverage_scope="selected region only"))
        elif not any(
            finding.get("operation") == "DescribeTrails" and finding.get("severity") == "Unknown"
            for finding in findings
        ):
            findings.append(_unverified(
                "CloudTrail", "DescribeTrails", "Multi-region trail coverage could not be determined from the returned trail data.", region=region
            ))

    if not findings:
        findings.append({
            "service": "CloudTrail",
            "severity": "Info",
            "finding": f"Supported CloudTrail checks passed in {region}",
            "recommendation": "This result covers returned trail configuration and status in the selected region only.",
            "region": region,
        })
    return findings


def audit_cloudtrail_account_coverage(regions_client_factory, cloudtrail_client_factory):
    """Assess trail configuration across enabled regions without conflating unknowns with gaps.

    This assesses configured trail coverage from DescribeTrails metadata only. It
    does not establish delivery health in every region; GetTrailStatus remains
    part of the separate selected-region check.
    """
    assessment = {
        "service": "CloudTrail",
        "assessment": "account-wide configured trail coverage",
        "coverage_status": "unknown",
        "inventory_complete": False,
        "enabled_regions": [],
        "checked_regions": [],
        "covered_regions": [],
        "uncovered_regions": [],
        "unverified_regions": [],
        "not_enabled_regions": [],
        "trails": [],
        "limitations": "Configuration coverage only; logging delivery status is checked separately in the selected region.",
    }

    def mark_unverified(region, operation, error=None, reason=None):
        entry = {"region": region or "unknown", "operation": operation}
        if error is not None:
            entry["error_code"] = _error_code(error)
            entry["reason"] = _error_reason(error)
        else:
            entry["reason"] = reason or "AWS returned incomplete or malformed data; coverage is unverified."
        assessment["unverified_regions"].append(entry)

    try:
        regions_client = regions_client_factory()
        response = regions_client.describe_regions(AllRegions=True)
    except (ClientError, BotoCoreError) as error:
        mark_unverified("all", "DescribeRegions", error)
        return assessment
    except Exception:
        mark_unverified("all", "DescribeRegions")
        return assessment

    if not isinstance(response, dict) or not isinstance(response.get("Regions"), list):
        mark_unverified("all", "DescribeRegions", reason="AWS returned a missing or malformed region inventory.")
        return assessment

    regions = response["Regions"]
    enabled = set()
    not_enabled = set()
    malformed_inventory = False
    for item in regions:
        if not isinstance(item, dict):
            malformed_inventory = True
            mark_unverified("all", "DescribeRegions", reason="AWS returned a malformed region entry.")
            continue
        name = item.get("RegionName")
        opt_in = item.get("OptInStatus")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", name):
            malformed_inventory = True
            mark_unverified("all", "DescribeRegions", reason="AWS returned a region without a valid name.")
            continue
        if opt_in in {"opt-in-not-required", "opted-in"}:
            enabled.add(name)
        elif opt_in == "not-opted-in":
            not_enabled.add(name)
        else:
            malformed_inventory = True
            mark_unverified(name, "DescribeRegions", reason="AWS did not return a recognized region opt-in status.")

    assessment["enabled_regions"] = sorted(enabled)
    assessment["not_enabled_regions"] = sorted(not_enabled)
    if malformed_inventory:
        assessment["inventory_complete"] = False
    else:
        assessment["inventory_complete"] = True
    if not enabled:
        assessment["inventory_complete"] = False
        mark_unverified("all", "DescribeRegions", reason="AWS returned no enabled regions; account-wide coverage cannot be assessed.")

    trails_by_arn = {}
    checked = set()
    incomplete_regions = set()
    regional_home_claims = {}
    for region in sorted(enabled):
        try:
            client = cloudtrail_client_factory(region)
            trail_response = client.describe_trails(includeShadowTrails=True)
        except (ClientError, BotoCoreError) as error:
            mark_unverified(region, "DescribeTrails", error)
            continue
        except Exception:
            mark_unverified(region, "DescribeTrails")
            continue

        if not isinstance(trail_response, dict) or not isinstance(trail_response.get("trailList"), list):
            mark_unverified(region, "DescribeTrails", reason="AWS returned a missing or malformed trail list.")
            continue

        checked.add(region)
        region_incomplete = False
        for trail in trail_response["trailList"]:
            if not isinstance(trail, dict):
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="AWS returned a malformed trail entry.")
                continue

            multi = trail.get("IsMultiRegionTrail")
            home = trail.get("HomeRegion")
            arn = trail.get("TrailARN")
            name = trail.get("Name")
            org = trail.get("IsOrganizationTrail")
            if (
                not isinstance(multi, bool)
                or not isinstance(home, str)
                or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", home)
            ):
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="Trail scope or home region is missing or malformed.")
                continue
            if org is not None and not isinstance(org, bool):
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="Organization-trail status is malformed.")
                continue
            if arn is not None and (
                not isinstance(arn, str)
                or not re.fullmatch(
                    r"arn:[a-z0-9-]+:cloudtrail:[a-z0-9-]+:\d{12}:trail/[^\s]+",
                    arn,
                )
            ):
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="Trail ARN is malformed.")
                continue
            if name is not None and (not isinstance(name, str) or not name.strip()):
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="Trail name is malformed.")
                continue
            if arn is None and name is None:
                region_incomplete = True
                mark_unverified(region, "DescribeTrails", reason="Trail identity is missing.")
                continue

            trail_key = arn or f"{home}:{name or 'unnamed'}"
            entry = trails_by_arn.get(trail_key)
            if entry is None:
                entry = {
                    "trail_arn": arn,
                    "name": name,
                    "home_region": home,
                    "is_multi_region": multi,
                    "is_organization_trail": org,
                    "observed_regions": [],
                    "reported_home_regions": {home},
                    "metadata_conflict": False,
                }
                trails_by_arn[trail_key] = entry
            elif (
                entry["home_region"] != home
                or entry["is_multi_region"] is not multi
                or (
                    entry["is_organization_trail"] is not None
                    and org is not None
                    and entry["is_organization_trail"] is not org
                )
            ):
                entry["metadata_conflict"] = True
                entry["reported_home_regions"].add(home)
            elif entry["is_organization_trail"] is None and org is not None:
                # The field is optional in some responses; a single explicit
                # value can resolve an omitted value without contradicting it.
                entry["is_organization_trail"] = org
            if region not in entry["observed_regions"]:
                entry["observed_regions"].append(region)
            if entry["metadata_conflict"]:
                region_incomplete = True
                mark_unverified(
                    region,
                    "DescribeTrails",
                    reason="The same trail ARN was returned with conflicting metadata; its coverage is unverified.",
                )
            elif not multi and home != region:
                region_incomplete = True
                if home in enabled:
                    regional_home_claims.setdefault(home, set()).add(trail_key)
                mark_unverified(
                    region,
                    "DescribeTrails",
                    reason="A regional trail was returned outside its declared home region.",
                )

        if region_incomplete:
            incomplete_regions.add(region)

    # Derive coverage only after all regional responses have been compared.
    # Conflicting duplicates cannot expand coverage based on whichever copy
    # happened to be processed last.
    covered = set()
    regional_home_confirmed = set()
    for entry in trails_by_arn.values():
        if entry["metadata_conflict"]:
            affected_regions = set(entry["observed_regions"])
            affected_regions.update(entry["reported_home_regions"])
            for affected_region in affected_regions:
                incomplete_regions.add(affected_region)
                mark_unverified(
                    affected_region,
                    "DescribeTrails",
                    reason="The same trail ARN was returned with conflicting metadata; its coverage is unverified.",
                )
            continue
        if entry["is_multi_region"]:
            covered.update(enabled)
        elif entry["home_region"] in entry["observed_regions"]:
            covered.add(entry["home_region"])
            regional_home_confirmed.add(entry["home_region"])

    for home_region in regional_home_claims:
        if home_region in regional_home_confirmed:
            continue
        incomplete_regions.add(home_region)
        mark_unverified(
            home_region,
            "DescribeTrails",
            reason="A regional trail reported this home region, but its own regional response did not confirm the trail.",
        )

    # A region with a valid empty response is a confirmed gap only when no
    # malformed or contradictory trail data affects that region.
    uncovered = {
        region for region in checked
        if region not in covered and region not in incomplete_regions
    }

    # A malformed/denied response is not a confirmed gap, even if no trail was
    # visible elsewhere. Remove covered regions from the uncovered set.
    uncovered.difference_update(covered)
    assessment["checked_regions"] = sorted(checked)
    assessment["covered_regions"] = sorted(covered & enabled)
    assessment["uncovered_regions"] = sorted(uncovered & checked)
    assessment["trails"] = sorted(
        trails_by_arn.values(), key=lambda item: (item["home_region"], item["name"] or "")
    )
    known_unverified = {entry["region"] for entry in assessment["unverified_regions"]}
    assessment["unverified_regions"] = sorted(
        assessment["unverified_regions"], key=lambda item: (item["region"], item["operation"])
    )
    assessment["coverage_status"] = (
        "partial" if assessment["unverified_regions"] or not assessment["inventory_complete"]
        else "complete"
    )
    assessment["coverage_is_complete"] = (
        assessment["coverage_status"] == "complete"
        and not assessment["uncovered_regions"]
        and not assessment["not_enabled_regions"]
    )
    assessment["unverified_region_names"] = sorted(
        name for name in known_unverified if name != "all"
    )
    return assessment


def audit_aws_account(
    s3_client, iam_client, cloudtrail_client, region,
    regions_client_factory=None, cloudtrail_client_factory=None,
):
    """Run AWS checks using already-created, injectable Boto3 clients."""
    results = {
        "s3": audit_s3_account(s3_client),
        "iam": audit_iam_account(iam_client),
        "cloudtrail": audit_cloudtrail_region(cloudtrail_client, region),
    }
    if regions_client_factory is not None and cloudtrail_client_factory is not None:
        results["cloudtrail_account_coverage"] = audit_cloudtrail_account_coverage(
            regions_client_factory, cloudtrail_client_factory
        )
    return results


def create_aws_clients(
    region,
    session_factory=None,
    aws_access_key_id=None,
    aws_secret_access_key=None,
    aws_session_token=None,
):
    """Create clients through Boto3's standard credential provider chain or optional session credentials.

    This function performs no API operation. Call it only after explicit user
    action; it does not persist or display credentials.
    """
    session, clients = create_aws_clients_with_session(
        region,
        session_factory=session_factory,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
    )
    return clients


def create_aws_clients_with_session(
    region,
    session_factory=None,
    aws_access_key_id=None,
    aws_secret_access_key=None,
    aws_session_token=None,
):
    """Create scan clients and return their shared session for regional checks."""
    if session_factory is None:
        import boto3
        session_factory = boto3.Session

    session_kwargs = {"region_name": region}
    if aws_access_key_id and aws_secret_access_key:
        session_kwargs["aws_access_key_id"] = str(aws_access_key_id).strip()
        session_kwargs["aws_secret_access_key"] = str(aws_secret_access_key).strip()
        if aws_session_token and str(aws_session_token).strip():
            session_kwargs["aws_session_token"] = str(aws_session_token).strip()

    session = session_factory(**session_kwargs)
    clients = (
        session.client("s3"),
        session.client("iam"),
        session.client("cloudtrail", region_name=region),
    )
    return session, clients
