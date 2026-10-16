
import streamlit as st
import pandas as pd

from s3_auditor import audit_s3_configuration
from iam_auditor import audit_iam_policy
from cloudTrail_auditor import audit_cloudtrail_configuration


st.set_page_config(
    page_title="CloudSentry",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CloudSentry")
st.subheader("AWS Cloud Security Assessment Dashboard")

st.write(
    "Identify potential cloud security risks, understand their impact, "
    "and review recommended security improvements."
)

st.info(
    "Demo mode: Findings are generated from sample configurations. "
    "No live AWS account is being scanned."
)

# ---------------- SCAN CONFIGURATION FORM ----------------

with st.form("security_scan_form"):

    st.header("⚙️ Security Scan Configuration")

    # S3 settings
    st.subheader("🪣 S3 Security Settings")

    block_public_acls = st.checkbox(
        "Block public ACLs", value=True
    )

    ignore_public_acls = st.checkbox(
        "Ignore public ACLs", value=True
    )

    block_public_policy = st.checkbox(
        "Block public bucket policies", value=False
    )

    restrict_public_buckets = st.checkbox(
        "Restrict public buckets", value=True
    )

    encryption_enabled = st.checkbox(
        "Enable default bucket encryption", value=False
    )

    st.divider()

    # IAM settings
    st.subheader("🔑 IAM Permission Settings")

    allow_all_actions = st.checkbox(
        "Allow all actions (*)", value=True
    )

    allow_all_resources = st.checkbox(
        "Apply permissions to all resources (*)", value=True
    )

    st.divider()

    # CloudTrail settings
    st.subheader("📜 CloudTrail Logging Settings")

    logging_enabled = st.checkbox(
        "CloudTrail logging enabled", value=False
    )

    log_validation_enabled = st.checkbox(
        "Log file integrity validation enabled", value=False
    )

    multi_region_enabled = st.checkbox(
        "Multi-region trail enabled", value=True
    )

    scan_clicked = st.form_submit_button(
        "🔍 Scan Configuration",
        type="primary",
        use_container_width=True
    )


# ---------------- RUN AND SAVE SCAN ----------------

# Run once on first page load, or when the user submits the form.
if scan_clicked or "scan_results" not in st.session_state:

    sample_bucket = {
        "block_public_access": {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets
        },
        "encryption_enabled": encryption_enabled
    }

    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": (
                    "*" if allow_all_actions else ["s3:GetObject"]
                ),
                "Resource": (
                    "*" if allow_all_resources
                    else ["arn:aws:s3:::example-bucket/*"]
                )
            }
        ]
    }

    sample_trail = {
        "logging_enabled": logging_enabled,
        "log_validation_enabled": log_validation_enabled,
        "multi_region_enabled": multi_region_enabled
    }

    # Run all three auditors
    s3_findings = audit_s3_configuration(sample_bucket)
    iam_findings = audit_iam_policy(sample_policy)
    cloudtrail_findings = audit_cloudtrail_configuration(sample_trail)

    # Save the previous scan before updating the results
    st.session_state["previous_scan_results"] = (
        st.session_state.get("scan_results")
    )

    # Save the current results as the previous scan before updating
    if "scan_results" in st.session_state:
        st.session_state["previous_scan_results"] = (
            st.session_state["scan_results"].copy()
        )

    # Store the newly completed scan
    st.session_state["scan_results"] = {
        "s3": s3_findings,
        "iam": iam_findings,
        "cloudtrail": cloudtrail_findings
    }

# Retrieve the most recent scan
results = st.session_state["scan_results"]

s3_findings = results["s3"]
iam_findings = results["iam"]
cloudtrail_findings = results["cloudtrail"]

all_findings = s3_findings + iam_findings + cloudtrail_findings

# ---------------- RISK SCORING ----------------

severity_points = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0
}

total_risk_points = sum(
    severity_points.get(finding["severity"], 0)
    for finding in all_findings
)

max_possible_points = len(all_findings) * 10

risk_score = (
    round((total_risk_points / max_possible_points) * 100)
    if max_possible_points > 0
    else 0
)

if risk_score >= 70:
    risk_status = "High Risk"
elif risk_score >= 35:
    risk_status = "Moderate Risk"
else:
    risk_status = "Low Risk"


# Record scan history
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

st.session_state["scan_history"].append({
    "Scan Number": len(st.session_state["scan_history"]) + 1,
    "Total Findings": (
        len(s3_findings)
        + len(iam_findings)
        + len(cloudtrail_findings)
    ),
    "High Severity": sum(
        1 for finding in (
            s3_findings + iam_findings + cloudtrail_findings
        )
        if finding["severity"] == "High"
    ),
    "Medium Severity": sum(
        1 for finding in (
            s3_findings + iam_findings + cloudtrail_findings
        )
        if finding["severity"] == "Medium"
    ),
    "Risk Score": risk_score
})

# ---------------- RISK SCORE HISTORY ----------------

if "risk_history" not in st.session_state:
    st.session_state["risk_history"] = []

if scan_clicked:
    st.session_state["risk_history"].append({
        "Scan": len(st.session_state["risk_history"]) + 1,
        "Risk Score": risk_score
    })


# ---------------- SCAN HISTORY ----------------

st.divider()
st.header("🕒 Scan History")

if st.session_state.get("scan_history"):
    history_df = pd.DataFrame(st.session_state["scan_history"])
    st.dataframe(history_df, use_container_width=True)
else:
    st.info("No scan history available yet.")

# ---------------- DASHBOARD METRICS ----------------

high_count = sum(
    finding["severity"] == "High"
    for finding in all_findings
)

medium_count = sum(
    finding["severity"] == "Medium"
    for finding in all_findings
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Services Audited", 3)
col2.metric("Total Findings", len(all_findings))
col3.metric("High Severity", high_count)
col4.metric("Medium Severity", medium_count)

# ---------------- RISK IMPROVEMENT CHART ----------------

st.divider()
st.header("📈 Security Risk Trend")

risk_history = st.session_state.get("risk_history", [])

if risk_history:
    risk_df = pd.DataFrame(risk_history)

    st.line_chart(
        risk_df,
        x="Scan",
        y="Risk Score"
    )

    first_score = risk_history[0]["Risk Score"]
    latest_score = risk_history[-1]["Risk Score"]

    improvement = first_score - latest_score

    if improvement > 0:
        st.success(
            f"Risk score decreased by {improvement} points "
            "compared with the first recorded scan."
        )
    elif improvement < 0:
        st.warning(
            f"Risk score increased by {abs(improvement)} points "
            "compared with the first recorded scan."
        )
    else:
        st.info("The risk score is unchanged from the first recorded scan.")
else:
    st.info("Run a scan to begin tracking your security risk trend.")

# ---------------- BEFORE VS AFTER COMPARISON ----------------

st.divider()
st.header("🔄 Before vs After Security Scan")

previous_results = st.session_state.get("previous_scan_results")

if previous_results:
    previous_findings = (
        previous_results["s3"]
        + previous_results["iam"]
        + previous_results["cloudtrail"]
    )

    current_findings = (
        st.session_state["scan_results"]["s3"]
        + st.session_state["scan_results"]["iam"]
        + st.session_state["scan_results"]["cloudtrail"]
    )

    previous_high = sum(
        1 for finding in previous_findings
        if finding.get("severity") == "High"
    )

    current_high = sum(
        1 for finding in current_findings
        if finding.get("severity") == "High"
    )

    previous_medium = sum(
        1 for finding in previous_findings
        if finding.get("severity") == "Medium"
    )

    current_medium = sum(
        1 for finding in current_findings
        if finding.get("severity") == "Medium"
    )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📌 Before")
        st.metric("Total Findings", len(previous_findings))
        st.metric("High Severity", previous_high)
        st.metric("Medium Severity", previous_medium)

    with col2:
        st.subheader("✅ Latest Scan")
        st.metric("Total Findings", len(current_findings))
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

    if len(current_findings) < len(previous_findings):
        st.success("Security findings have decreased since the previous scan!")
    elif len(current_findings) > len(previous_findings):
        st.warning("New security findings have appeared. Review the latest scan.")
    else:
        st.info("The total number of findings has not changed.")
else:
    st.info(
        "Run another scan after changing configuration settings "
        "to compare it with the previous scan."
    )

# ---------------- SECURITY POSTURE ----------------

st.divider()
st.header("📊 Security Posture Summary")

score_col, status_col = st.columns(2)

score_col.metric(
    "Overall Risk Score",
    f"{risk_score}/100"
)

status_col.metric(
    "Risk Classification",
    risk_status
)

st.progress(risk_score / 100)

st.caption(
    "Prototype score based on detected findings. "
    "Higher scores indicate greater potential risk."
)


# ---------------- S3 RESULTS ----------------

st.divider()
st.header("🪣 S3 Security Findings")
st.write("Checks public access protection and default encryption.")

st.dataframe(
    pd.DataFrame(s3_findings),
    use_container_width=True,
    hide_index=True
)


# ---------------- IAM RESULTS ----------------

st.divider()
st.header("🔑 IAM Permission Findings")
st.write("Checks sample IAM policies for potentially broad permissions.")

st.dataframe(
    pd.DataFrame(iam_findings),
    use_container_width=True,
    hide_index=True
)


# ---------------- CLOUDTRAIL RESULTS ----------------

st.divider()
st.header("📜 CloudTrail Logging Findings")
st.write("Checks sample activity logging and trail configuration.")

st.dataframe(
    pd.DataFrame(cloudtrail_findings),
    use_container_width=True,
    hide_index=True
)


# ---------------- REMEDIATION GUIDANCE ----------------

remediation_guidance = {
    "S3": {
        "public": [
            "Open the AWS S3 console and select the affected bucket.",
            "Go to Permissions → Block public access.",
            "Enable all four Block Public Access settings.",
            "Review the bucket policy and access control lists."
        ],
        "encryption": [
            "Open the bucket's Properties tab.",
            "Find Default encryption and enable server-side encryption.",
            "Choose SSE-S3 or SSE-KMS according to your security requirements."
        ]
    },
    "IAM": {
        "wildcard": [
            "Open the AWS IAM console and locate the affected policy.",
            "Replace Action: '*' with only the required actions.",
            "Replace Resource: '*' with specific resource ARNs wherever possible.",
            "Follow the principle of least privilege and review permissions regularly."
        ]
    },
    "CloudTrail": {
        "logging": [
            "Open the AWS CloudTrail console.",
            "Create or select a trail and enable logging.",
            "Configure an S3 destination for log delivery.",
            "Verify that new events are being recorded."
        ],
        "validation": [
            "Open the trail's configuration.",
            "Enable log file validation to help detect changes to delivered log files."
        ],
        "region": [
            "Configure a multi-Region trail to record supported events across AWS Regions."
        ]
    }
}


# ---------------- RECOMMENDATIONS ----------------

st.divider()
st.header("🛠️ Recommended Actions")

for finding in all_findings:
    with st.container(border=True):
        st.subheader(finding["finding"])
        st.write(f"**Service:** {finding['service']}")
        st.write(f"**Severity:** {finding['severity']}")
        st.write(f"**Recommendation:** {finding['recommendation']}")

        finding_text = finding["finding"].lower()
        service = finding["service"].lower()

        steps = []

        if service == "s3":
            if "public" in finding_text:
                steps = remediation_guidance["S3"]["public"]
            elif "encrypt" in finding_text:
                steps = remediation_guidance["S3"]["encryption"]

        elif service == "iam" and (
            "wildcard" in finding_text
            or "broad" in finding_text
            or "permission" in finding_text
        ):
            steps = remediation_guidance["IAM"]["wildcard"]

        elif service == "cloudtrail":
            if "logging" in finding_text or "disabled" in finding_text:
                steps = remediation_guidance["CloudTrail"]["logging"]
            elif "validation" in finding_text:
                steps = remediation_guidance["CloudTrail"]["validation"]
            elif "region" in finding_text:
                steps = remediation_guidance["CloudTrail"]["region"]

        if steps:
            with st.expander("🔧 View Step-by-Step Remediation"):
                for step_number, step in enumerate(steps, start=1):
                    st.write(f"{step_number}. {step}")

# ---------------- DOWNLOAD SECURITY REPORT ----------------

st.divider()
st.header("📥 Export Security Report")

report_df = pd.DataFrame(all_findings)

if not report_df.empty:
    csv_data = report_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Audit Report (CSV)",
        data=csv_data,
        file_name="cloudsentry_security_report.csv",
        mime="text/csv",
        use_container_width=True
    )

    st.caption(
        "The report contains findings from the most recently completed scan."
    )
else:
    st.success("No security findings to export.")

st.caption(
    "CloudSentry prototype | Sample data only | "
    "No live AWS resources are modified."
)
