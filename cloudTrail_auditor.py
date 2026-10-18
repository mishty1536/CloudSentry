
def audit_cloudtrail_configuration(trail_config):
    """
    Check sample CloudTrail settings for basic logging risks.
    This version uses sample data and does not connect to AWS.
    """
    findings = []

    if not isinstance(trail_config, dict):
        trail_config = {}

    if trail_config.get("logging_enabled") is not True:
        status = (
            "CloudTrail logging is disabled"
            if trail_config.get("logging_enabled") is False
            else "CloudTrail logging status is missing or unconfirmed"
        )
        findings.append({
            "service": "CloudTrail",
            "severity": "High",
            "finding": status,
            "recommendation": (
                "Enable CloudTrail logging to record account activity "
                "and support security investigations."
            )
        })

    if trail_config.get("log_validation_enabled") is not True:
        status = (
            "Log file integrity validation is disabled"
            if trail_config.get("log_validation_enabled") is False
            else "Log file integrity validation status is missing or unconfirmed"
        )
        findings.append({
            "service": "CloudTrail",
            "severity": "Medium",
            "finding": status,
            "recommendation": (
                "Enable log file integrity validation to help detect "
                "changes to delivered CloudTrail log files."
            )
        })

    if trail_config.get("multi_region_enabled") is not True:
        status = (
            "Multi-region trail is not enabled"
            if trail_config.get("multi_region_enabled") is False
            else "Multi-region trail status is missing or unconfirmed"
        )
        findings.append({
            "service": "CloudTrail",
            "severity": "Medium",
            "finding": status,
            "recommendation": (
                "Consider configuring a multi-region trail to record "
                "supported events across AWS Regions."
            )
        })

    if not findings:
        findings.append({
            "service": "CloudTrail",
            "severity": "Info",
            "finding": "No issues detected by these checks",
            "recommendation": (
                "Continue reviewing trail coverage, log storage security, "
                "and monitoring configuration."
            )
        })

    return findings


if __name__ == "__main__":
    sample_trail = {
        "logging_enabled": False,
        "log_validation_enabled": False,
        "multi_region_enabled": True
    }

    results = audit_cloudtrail_configuration(sample_trail)

    print("CloudSentry CloudTrail Audit Results")

    for finding in results:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")
        print(f"Recommendation: {finding['recommendation']}")
