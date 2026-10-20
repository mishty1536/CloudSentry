"""Explicit, allowlisted S3 default-encryption remediation."""

from botocore.exceptions import BotoCoreError, ClientError


PROTECTED_BUCKET_NAME = "cloudsentry-test-mishty-2026"
MISSING_ENCRYPTION_CODE = "ServerSideEncryptionConfigurationNotFoundError"


def _error_result(error, phase):
    code = None
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
    normalized = str(code or "").lower()
    if normalized in {"accessdenied", "accessdeniedexception", "forbidden", "403"}:
        status = "access_denied"
        message = f"AWS denied the {phase} request. No success is reported."
    elif normalized in {"nosuchbucket", "notfound", "404"}:
        status = "bucket_not_found"
        message = f"AWS could not find the bucket during {phase}. No success is reported."
    else:
        status = "api_error"
        message = f"AWS {phase} failed ({type(error).__name__}). No success is reported."
    return {"success": False, "status": status, "message": message}


def _has_only_sse_s3(encryption_response):
    if not isinstance(encryption_response, dict):
        return False
    configuration = encryption_response.get("ServerSideEncryptionConfiguration")
    rules = configuration.get("Rules") if isinstance(configuration, dict) else None
    return bool(rules) and isinstance(rules, list) and all(
        isinstance(rule, dict)
        and isinstance(rule.get("ApplyServerSideEncryptionByDefault"), dict)
        and rule["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm") == "AES256"
        for rule in rules
    )


def remediate_s3_default_encryption(s3_client, bucket_name, *, allowed_bucket_name):
    """Set SSE-S3 only on one explicitly allowlisted bucket, then verify it.

    Existing encryption configurations are never replaced. The known existing
    CloudSentry bucket is hard-denied independently of the configured allowlist.
    """
    if not isinstance(bucket_name, str) or not bucket_name:
        return {"success": False, "status": "invalid_bucket", "message": "Enter a bucket name."}
    if bucket_name == PROTECTED_BUCKET_NAME or allowed_bucket_name == PROTECTED_BUCKET_NAME:
        return {
            "success": False,
            "status": "protected_bucket",
            "message": "Remediation is blocked for the protected CloudSentry bucket.",
        }
    if not isinstance(allowed_bucket_name, str) or not allowed_bucket_name:
        return {
            "success": False,
            "status": "not_configured",
            "message": "No dedicated remediation bucket is configured.",
        }
    if bucket_name != allowed_bucket_name:
        return {
            "success": False,
            "status": "not_allowlisted",
            "message": "The bucket does not match the dedicated remediation bucket allowlist.",
        }

    try:
        current = s3_client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as error:
        if _client_error_code(error) != MISSING_ENCRYPTION_CODE:
            return _error_result(error, "pre-remediation encryption check")
    except BotoCoreError as error:
        return _error_result(error, "pre-remediation encryption check")
    else:
        if _has_only_sse_s3(current):
            return {
                "success": True,
                "status": "already_configured",
                "message": "AWS confirms the bucket already uses SSE-S3 (AES256); no write was made.",
            }
        return {
            "success": False,
            "status": "existing_configuration",
            "message": (
                "An existing or malformed encryption configuration was found. "
                "It was left unchanged to avoid replacing encryption settings."
            ),
        }

    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }]
            },
        )
    except (ClientError, BotoCoreError) as error:
        return _error_result(error, "SSE-S3 remediation")

    try:
        verified = s3_client.get_bucket_encryption(Bucket=bucket_name)
    except (ClientError, BotoCoreError) as error:
        result = _error_result(error, "post-remediation verification")
        result["status"] = "verification_" + result["status"]
        return result
    if not _has_only_sse_s3(verified):
        return {
            "success": False,
            "status": "verification_failed",
            "message": (
                "The write request returned, but AWS did not confirm an AES256-only "
                "default encryption configuration. Treat the result as unverified."
            ),
        }
    return {
        "success": True,
        "status": "verified",
        "message": "AWS confirmed the bucket default encryption is SSE-S3 (AES256).",
    }


def _client_error_code(error):
    return error.response.get("Error", {}).get("Code")
