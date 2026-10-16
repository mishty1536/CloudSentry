
def audit_s3_configuration(bucket_config):
    """
    Analyze an S3 bucket configuration and return security findings.

    This first version uses sample configuration data.
    """

    findings = []

    # Check Block Public Access
    public_access = bucket_config.get("block_public_access", {})

    public_settings = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets"
    ]

    if not all(public_access.get(setting, False) for setting in public_settings):
        findings.append({
            "service": "S3",
            "severity": "High",
            "finding": "S3 Block Public Access is not fully enabled",
            "recommendation": (
                "Review all four S3 Block Public Access settings "
                "at the bucket and account levels."
            )
        })

    # Check default encryption
    if not bucket_config.get("encryption_enabled", False):
        findings.append({
            "service": "S3",
            "severity": "Medium",
            "finding": "Default bucket encryption is not confirmed",
            "recommendation": (
                "Configure default server-side encryption "
                "for the bucket."
            )
        })

    if not findings:
        findings.append({
            "service": "S3",
            "severity": "Info",
            "finding": "No issues detected by these checks",
            "recommendation": (
                "Continue reviewing bucket policies, access permissions, "
                "and other security controls."
            )
        })

    return findings


# Temporary test configuration — no AWS credentials required
if __name__ == "__main__":
    sample_bucket = {
        "block_public_access": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True
        },
        "encryption_enabled": False
    }

    results = audit_s3_configuration(sample_bucket)

    for finding in results:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")
        print(f"Recommendation: {finding['recommendation']}")
