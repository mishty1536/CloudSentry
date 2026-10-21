"""Dashboard helpers that retain and safely display incomplete findings."""

import pandas as pd


SEVERITY_POINTS = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

FINDING_COLUMNS = ["service", "severity", "finding", "recommendation"]


def _as_items(value):
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _service_label(service):
    known = {"s3": "S3", "iam": "IAM", "cloudtrail": "CloudTrail"}
    if isinstance(service, str):
        return known.get(service.lower(), service or "Unknown")
    return "Unknown"


def _normalize_finding(finding, service="Unknown"):
    if isinstance(finding, dict):
        record = dict(finding)
    else:
        record = {
            "details": repr(finding),
            "finding": "Unexpected finding data could not be parsed",
            "recommendation": "Review this raw audit result manually.",
        }

    if not isinstance(record.get("service"), str) or not record["service"].strip():
        record["service"] = _service_label(service)

    severity = record.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITY_POINTS and severity != "Unknown":
        if "severity" in record:
            record["severity_details"] = repr(severity)
        record["severity"] = "Unknown"

    if not isinstance(record.get("finding"), str) or not record["finding"].strip():
        if "finding" in record:
            record["finding_details"] = repr(record["finding"])
        record["finding"] = "Finding details missing or malformed"

    if not isinstance(record.get("recommendation"), str):
        if "recommendation" in record:
            record["recommendation_details"] = repr(record["recommendation"])
        record["recommendation"] = "Review the finding details manually."

    return record


def normalize_findings(findings):
    """Return displayable records without dropping malformed entries."""
    if findings is None:
        return []
    return [_normalize_finding(item) for item in _as_items(findings)]


def count_severity(findings, severity):
    """Count records at a severity, ignoring malformed record containers."""
    return sum(
        1 for finding in normalize_findings(findings)
        if finding.get("severity") == severity
    )


def assessment_status(findings):
    """Return Incomplete whenever normalized results contain unknown severity."""
    return "Incomplete" if count_severity(findings, "Unknown") else "Complete"


def calculate_risk_score(findings):
    """Calculate risk using verified findings only; exclude Unknown severities."""
    records = normalize_findings(findings)
    verified_records = [
        finding
        for finding in records
        if finding.get("severity") in SEVERITY_POINTS
    ]

    if not verified_records:
        return 0

    total_points = sum(
        SEVERITY_POINTS[finding["severity"]]
        for finding in verified_records
    )
    maximum_points = len(verified_records) * 10
    return round((total_points / maximum_points) * 100)


def has_verified_findings(findings):
    """Whether a risk score has at least one finding with verified severity."""
    return any(
        finding.get("severity") in SEVERITY_POINTS
        for finding in normalize_findings(findings)
    )

def classify_risk(score):
    if score >= 70:
        return "High Risk"
    if score >= 35:
        return "Moderate Risk"
    return "Low Risk"


def combine_findings(results):
    """Combine service results while retaining unexpected result entries."""
    if not isinstance(results, dict):
        return [_normalize_finding(results, "Unknown")]

    expected = ["s3", "iam", "cloudtrail"]
    keys = expected + [key for key in results if key not in expected]
    combined = []
    for service in keys:
        if service not in results:
            continue
        for item in _as_items(results[service]):
            combined.append(_normalize_finding(item, service))
    return combined


def make_findings_dataframe(findings):
    """Create stable columns and retain additional or malformed field data."""
    records = normalize_findings(findings)
    if not records:
        return pd.DataFrame(columns=FINDING_COLUMNS)

    df = pd.DataFrame(records)
    extra_columns = [column for column in df.columns if column not in FINDING_COLUMNS]
    return df[FINDING_COLUMNS + extra_columns]


def prepare_dataframe_for_display(df, resource_limit=96, recommendation_limit=220):
    """Shorten long table cells on a copy; exports and scan data stay complete."""
    display_df = df.copy()
    shortened = False

    def shorten(value, limit, preserve_arn=False):
        nonlocal shortened
        if not isinstance(value, str) or len(value) <= limit:
            return value
        shortened = True
        if preserve_arn and value.startswith("arn:"):
            parts = value.split(":", 5)
            if len(parts) == 6:
                prefix = ":".join(parts[:5]) + ":"
                budget = max(12, limit - len(prefix) - 1)
                head = max(8, (budget * 2) // 3)
                tail = max(4, budget - head)
                return f"{prefix}{parts[5][:head]}…{parts[5][-tail:]}"
        head = max(1, limit - 1)
        return f"{value[:head]}…"

    if "resource" in display_df.columns:
        display_df["resource"] = display_df["resource"].map(
            lambda value: shorten(value, resource_limit, preserve_arn=True)
        )
    if "recommendation" in display_df.columns:
        display_df["recommendation"] = display_df["recommendation"].map(
            lambda value: shorten(value, recommendation_limit)
        )
    return display_df, shortened
