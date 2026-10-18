
import streamlit as st
import pandas as pd
from datetime import datetime

from s3_auditor import audit_s3_configuration
from iam_auditor import audit_iam_policy
from cloudTrail_auditor import audit_cloudtrail_configuration


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CloudSentry | Cloud Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CloudSentry")
st.header("AWS Cloud Security Assessment Dashboard")

st.write(
    "Identify potential cloud security risks, understand their impact, "
    "and review recommended security improvements."
)

st.info(
    "Demo mode: Findings are generated from sample configurations. "
    "No live AWS account is being scanned."
)


# ============================================================
# CONSTANTS AND HELPER FUNCTIONS
# ============================================================

SEVERITY_POINTS = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0
}


def count_severity(findings, severity):
    """Count findings matching a severity."""
    return sum(
        1 for finding in findings
        if finding.get("severity", "Info") == severity
    )


def calculate_risk_score(findings):
    """
    Prototype risk score based on average finding severity.
    This is not an official AWS or industry-standard score.
    """
    if not findings:
        return 0

    total_points = sum(
        SEVERITY_POINTS.get(finding.get("severity", "Info"), 0)
        for finding in findings
    )

    maximum_points = len(findings) * 10

    return round((total_points / maximum_points) * 100)


def classify_risk(score):
    if score >= 70:
        return "High Risk"
    elif score >= 35:
        return "Moderate Risk"
    return "Low Risk"


def combine_findings(results):
    """Combine all service findings into one list."""
    return (
        results.get("s3", [])
        + results.get("iam", [])
        + results.get("cloudtrail", [])
    )


def make_findings_dataframe(findings):
    """Create a consistent table even when there are no findings."""
    columns = ["service", "severity", "finding", "recommendation"]

    if not findings:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(findings)

    for column in columns:
        if column not in df.columns:
            df[column] = ""

    return df[columns]


def run_audit(
    block_public_acls,
    ignore_public_acls,
    block_public_policy,
    restrict_public_buckets,
    encryption_enabled,
    allow_all_actions,
    allow_all_resources,
    logging_enabled,
    log_validation_enabled,
    multi_region_enabled
):
    """Run the three local demo auditors."""

    s3_config = {
        "BlockPublicAcls": block_public_acls,
        "IgnorePublicAcls": ignore_public_acls,
        "BlockPublicPolicy": block_public_policy,
        "RestrictPublicBuckets": restrict_public_buckets,
        "encryption_enabled": encryption_enabled
    }

    iam_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": (
                    "*" if allow_all_actions
                    else ["s3:GetObject"]
                ),
                "Resource": (
                    "*" if allow_all_resources
                    else ["arn:aws:s3:::example-bucket/*"]
                )
            }
        ]
    }

    cloudtrail_config = {
        "logging_enabled": logging_enabled,
        "log_validation_enabled": log_validation_enabled,
        "multi_region_enabled": multi_region_enabled
    }

    return {
        "s3": audit_s3_configuration(s3_config),
        "iam": audit_iam_policy(iam_policy),
        "cloudtrail": audit_cloudtrail_configuration(cloudtrail_config)
    }


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None

if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

if "previous_scan_results" not in st.session_state:
    st.session_state["previous_scan_results"] = None

if "scan_number" not in st.session_state:
    st.session_state["scan_number"] = 0


# ============================================================
# SECURITY SCAN CONFIGURATION FORM
# ============================================================

st.divider()
st.header("⚙️ Security Scan Configuration")

with st.form("security_scan_form"):

    st.subheader("🪣 S3 Security Settings")

    col1, col2 = st.columns(2)

    with col1:
        block_public_acls = st.checkbox(
            "Block public ACLs",
            value=True
        )

        ignore_public_acls = st.checkbox(
            "Ignore public ACLs",
            value=True
        )

        block_public_policy = st.checkbox(
            "Block public bucket policies",
            value=True
        )

    with col2:
        restrict_public_buckets = st.checkbox(
            "Restrict public buckets",
            value=True
        )

        encryption_enabled = st.checkbox(
            "Enable default bucket encryption",
            value=True
        )

    st.divider()
    st.subheader("🔑 IAM Permission Settings")

    col1, col2 = st.columns(2)

    with col1:
        allow_all_actions = st.checkbox(
            "Allow all actions (*)",
            value=False
        )

    with col2:
        allow_all_resources = st.checkbox(
            "Apply permissions to all resources (*)",
            value=False
        )

    st.caption(
        "Uncheck wildcard permissions to simulate a more restrictive "
        "sample IAM policy."
    )

    st.divider()
    st.subheader("📜 CloudTrail Logging Settings")

    col1, col2, col3 = st.columns(3)

    with col1:
        logging_enabled = st.checkbox(
            "CloudTrail logging enabled",
            value=True
        )

    with col2:
        log_validation_enabled = st.checkbox(
            "Log file integrity validation enabled",
            value=True
        )

    with col3:
        multi_region_enabled = st.checkbox(
            "Multi-region trail enabled",
            value=True
        )

    scan_clicked = st.form_submit_button(
        "🔍 Scan Configuration",
        type="primary",
        use_container_width=True
    )


# ============================================================
# EXECUTE SCAN AND STORE RESULTS
# ============================================================

if scan_clicked:

    new_results = run_audit(
        block_public_acls,
        ignore_public_acls,
        block_public_policy,
        restrict_public_buckets,
        encryption_enabled,
        allow_all_actions,
        allow_all_resources,
        logging_enabled,
        log_validation_enabled,
        multi_region_enabled
    )

    # Preserve the last completed scan for comparison.
    if st.session_state["scan_results"] is not None:
        st.session_state["previous_scan_results"] = (
            st.session_state["scan_results"]
        )

    st.session_state["scan_results"] = new_results
    st.session_state["scan_number"] += 1

    all_new_findings = combine_findings(new_results)
    new_risk_score = calculate_risk_score(all_new_findings)

    history_record = {
        "Scan Number": st.session_state["scan_number"],
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Total Findings": len(all_new_findings),
        "High Severity": count_severity(all_new_findings, "High"),
        "Medium Severity": count_severity(all_new_findings, "Medium"),
        "Risk Score": new_risk_score
    }

    st.session_state["scan_history"].append(history_record)

    # Keep the most recent 20 scans in this session.
    st.session_state["scan_history"] = (
        st.session_state["scan_history"][-20:]
    )

    st.success("Security scan completed successfully!")


# ============================================================
# DISPLAY RESULTS
# ============================================================

results = st.session_state["scan_results"]

if results is None:
    st.info(
        "Configure the sample settings above and click "
        "'Scan Configuration' to view the security assessment."
    )
    st.stop()


all_findings = combine_findings(results)
findings_df = make_findings_dataframe(all_findings)

high_count = count_severity(all_findings, "High")
medium_count = count_severity(all_findings, "Medium")
low_count = count_severity(all_findings, "Low")

risk_score = calculate_risk_score(all_findings)
risk_classification = classify_risk(risk_score)


# ============================================================
# SCAN HISTORY
# ============================================================

st.divider()
st.header("🕒 Scan History")

history_df = pd.DataFrame(st.session_state["scan_history"])

if not history_df.empty:
    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.caption("No scans have been recorded in this session yet.")


# ============================================================
# DASHBOARD METRICS
# ============================================================

st.divider()
st.header("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Services Audited", 3)
col2.metric("Total Findings", len(all_findings))
col3.metric("High Severity", high_count)
col4.metric("Medium Severity", medium_count)

st.divider()
st.header("📈 Security Posture Summary")

col1, col2 = st.columns(2)

with col1:
    st.metric("Overall Risk Score", f"{risk_score}/100")

with col2:
    st.metric("Risk Classification", risk_classification)

st.progress(risk_score / 100)

st.caption(
    "Prototype score based on the average severity of detected findings. "
    "Higher scores indicate greater potential risk; this is not an "
    "official AWS security score."
)


# ============================================================
# SECURITY RISK TREND
# ============================================================

st.divider()
st.header("📉 Security Risk Trend")

if len(st.session_state["scan_history"]) >= 2:

    trend_df = pd.DataFrame(st.session_state["scan_history"])

    chart_df = trend_df.set_index("Scan Number")[["Risk Score"]]

    st.line_chart(chart_df)

    first_score = int(trend_df.iloc[0]["Risk Score"])
    latest_score = int(trend_df.iloc[-1]["Risk Score"])
    difference = latest_score - first_score

    if difference < 0:
        st.success(
            f"Risk score decreased by {abs(difference)} points "
            "compared with the first recorded scan."
        )
    elif difference > 0:
        st.warning(
            f"Risk score increased by {difference} points "
            "compared with the first recorded scan."
        )
    else:
        st.info("The risk score is unchanged from the first recorded scan.")

else:
    st.info(
        "Complete at least two scans to see how the risk score changes."
    )


# ============================================================
# BEFORE VS AFTER COMPARISON
# ============================================================

st.divider()
st.header("🔄 Before vs After Security Scan")

previous_results = st.session_state["previous_scan_results"]

if previous_results is not None:

    previous_findings = combine_findings(previous_results)
    current_findings = all_findings

    previous_high = count_severity(previous_findings, "High")
    current_high = count_severity(current_findings, "High")

    previous_medium = count_severity(previous_findings, "Medium")
    current_medium = count_severity(current_findings, "Medium")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📌 Before")
        st.metric("Total Findings", len(previous_findings))
        st.metric("High Severity", previous_high)
        st.metric("Medium Severity", previous_medium)
        st.metric(
            "Risk Score",
            f"{calculate_risk_score(previous_findings)}/100"
        )

    with col2:
        st.subheader("✅ Latest Scan")
        st.metric(
            "Total Findings",
            len(current_findings),
            delta=len(current_findings) - len(previous_findings),
            delta_color="inverse"
        )
        st.metric(
            "High Severity",
            current_high,
            delta=current_high - previous_high,
            delta_color="inverse"
        )
        st.metric(
            "Medium Severity",
            current_medium,
            delta=current_medium - previous_medium,
            delta_color="inverse"
        )
        st.metric(
            "Risk Score",
            f"{calculate_risk_score(current_findings)}/100",
            delta=(
                calculate_risk_score(current_findings)
                - calculate_risk_score(previous_findings)
            ),
            delta_color="inverse"
        )

    finding_difference = len(current_findings) - len(previous_findings)

    if finding_difference < 0:
        st.success(
            f"Findings decreased by {abs(finding_difference)} "
            "compared with the previous scan."
        )
    elif finding_difference > 0:
        st.warning(
            f"Findings increased by {finding_difference} "
            "compared with the previous scan."
        )
    else:
        st.info(
            "The total number of findings has not changed. "
            "Compare severity and risk score for further details."
        )

else:
    st.info(
        "Run another scan after changing the sample configuration "
        "to compare it with the previous scan."
    )


# ============================================================
# FILTER SECURITY FINDINGS
# ============================================================

# ---------------- FILTER SECURITY FINDINGS ----------------

st.divider()
st.header("🔎 Filter Security Findings")

# Combine findings from all three services
scan_results = st.session_state.get("scan_results", {})

all_findings = (
    scan_results.get("s3", [])
    + scan_results.get("iam", [])
    + scan_results.get("cloudtrail", [])
)

all_findings = [
    finding for finding in all_findings
    if isinstance(finding, dict)
    and any(
        value is not None and str(value).strip()
        for value in finding.values()
    )
]

# Remove empty or invalid findings
all_findings = [
    finding for finding in all_findings
    if isinstance(finding, dict)
    and any(
        value is not None and str(value).strip()
        for value in finding.values()
    )
]

if all_findings:
    findings_df = pd.DataFrame(all_findings)

    # Remove rows that are completely empty
    findings_df = findings_df.dropna(how="all")

    # Remove rows where every cell is empty or whitespace
    findings_df = findings_df[
        findings_df.apply(
            lambda row: any(
                str(value).strip()
                for value in row
                if pd.notna(value)
            ),
            axis=1
        )
    ]

    col1, col2 = st.columns(2)

    with col1:
        severity_options = ["All"] + sorted(
            findings_df["severity"].dropna().unique().tolist()
        )
        selected_severity = st.selectbox(
            "Filter by Severity",
            severity_options,
            key="filter_severity"
        )

    with col2:
        service_options = ["All"] + sorted(
            findings_df["service"].dropna().unique().tolist()
        )
        selected_service = st.selectbox(
            "Filter by Service",
            service_options,
            key="filter_service"
        )

    # Apply selected filters
    filtered_df = findings_df.copy()

    if selected_severity != "All":
        filtered_df = filtered_df[
            filtered_df["severity"] == selected_severity
        ]

    if selected_service != "All":
        filtered_df = filtered_df[
            filtered_df["service"] == selected_service
        ]

    st.caption(
        f"Showing {len(filtered_df)} of {len(findings_df)} findings."
    )

    # Display only actual findings
    st.dataframe(
        filtered_df.reset_index(drop=True),
        use_container_width=True,
        hide_index=True
    )

else:
    st.success("No security findings to display.")

# ============================================================
# INDIVIDUAL SERVICE FINDINGS
# ============================================================

st.divider()
st.header("🪣 S3 Security Findings")
st.write("Checks public access protection and default encryption.")

st.dataframe(
    make_findings_dataframe(results["s3"]),
    use_container_width=True,
    hide_index=True
)

st.divider()
st.header("🔑 IAM Permission Findings")
st.write("Checks sample IAM policies for potentially broad permissions.")

st.dataframe(
    make_findings_dataframe(results["iam"]),
    use_container_width=True,
    hide_index=True
)

st.divider()
st.header("📜 CloudTrail Logging Findings")
st.write("Checks sample activity logging and trail configuration.")

st.dataframe(
    make_findings_dataframe(results["cloudtrail"]),
    use_container_width=True,
    hide_index=True
)


# ============================================================
# RECOMMENDED ACTIONS
# ============================================================

st.divider()
st.header("🛠️ Recommended Actions")

if not all_findings:
    st.success("No findings were returned by the configured checks.")

else:
    for index, finding in enumerate(all_findings, start=1):

        service = finding.get("service", "Cloud")
        severity = finding.get("severity", "Info")
        title = finding.get("finding", "Security finding")
        recommendation = finding.get(
            "recommendation",
            "Review the configuration and follow security best practices."
        )

        with st.container(border=True):

            st.subheader(f"{index}. {title}")

            col1, col2 = st.columns(2)

            with col1:
                st.write(f"**Service:** {service}")

            with col2:
                st.write(f"**Severity:** {severity}")

            st.write(f"**Recommendation:** {recommendation}")

            if service == "S3":
                with st.expander("🔧 View Step-by-Step Remediation"):
                    st.markdown(
                        """
                        1. Review S3 Block Public Access settings.
                        2. Enable the four public access protection controls
                           where appropriate.
                        3. Enable default server-side encryption.
                        4. Review bucket policies and ACLs.
                        5. Verify access requirements before applying changes.
                        """
                    )

            elif service == "IAM":
                with st.expander("🔧 View Step-by-Step Remediation"):
                    st.markdown(
                        """
                        1. Review the IAM policy's Effect, Action, and Resource.
                        2. Replace unnecessary wildcard permissions.
                        3. Grant only the actions required for the task.
                        4. Restrict resources to specific ARNs where supported.
                        5. Test the least-privilege policy before deployment.
                        """
                    )

            elif service == "CloudTrail":
                with st.expander("🔧 View Step-by-Step Remediation"):
                    st.markdown(
                        """
                        1. Enable CloudTrail logging.
                        2. Enable log file integrity validation.
                        3. Review whether a multi-region trail is required.
                        4. Secure log storage and limit access to logs.
                        5. Monitor logging status and retention.
                        """
                    )


# ============================================================
# DOWNLOAD SECURITY REPORT
# ============================================================

st.divider()
st.header("📥 Export Security Report")

report_df = findings_df.copy()

if not report_df.empty:

    csv_data = report_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Audit Report (CSV)",
        data=csv_data,
        file_name="cloudsentry_security_report.csv",
        mime="text/csv",
        use_container_width=True
    )

    summary_report = pd.DataFrame(
        [
            {"Metric": "Scan Number", "Value": st.session_state["scan_number"]},
            {"Metric": "Services Audited", "Value": 3},
            {"Metric": "Total Findings", "Value": len(all_findings)},
            {"Metric": "High Severity", "Value": high_count},
            {"Metric": "Medium Severity", "Value": medium_count},
            {"Metric": "Low Severity", "Value": low_count},
            {"Metric": "Risk Score", "Value": risk_score},
            {"Metric": "Risk Classification", "Value": risk_classification}
        ]
    )

    summary_csv = summary_report.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📊 Download Security Summary (CSV)",
        data=summary_csv,
        file_name="cloudsentry_security_summary.csv",
        mime="text/csv",
        use_container_width=True
    )

    st.caption(
        "Reports contain results from the latest completed scan. "
        "They are generated from sample configurations in demo mode."
    )

else:
    st.success("No security findings to export.")


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CloudSentry | Educational Cloud Security Prototype | "
    "Demo mode only — no live AWS resources are scanned or modified."
)
