
import streamlit as st
import pandas as pd

from s3_auditor import audit_s3_configuration
from iam_auditor import audit_iam_policy

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

# ---------------- S3 AUDIT ----------------

sample_bucket = {
    "block_public_access": {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True
    },
    "encryption_enabled": False
}

s3_findings = audit_s3_configuration(sample_bucket)

# ---------------- IAM AUDIT ----------------

sample_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}

iam_findings = audit_iam_policy(sample_policy)

# Combine findings from both modules
all_findings = s3_findings + iam_findings

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

col1.metric("Services Audited", 2)
col2.metric("Total Findings", len(all_findings))
col3.metric("High Severity", high_count)
col4.metric("Medium Severity", medium_count)

st.divider()

# ---------------- S3 RESULTS ----------------

st.header("🪣 S3 Security Findings")
st.write("Checks for public access protection and default encryption.")

st.dataframe(
    pd.DataFrame(s3_findings),
    use_container_width=True,
    hide_index=True
)

st.divider()

# ---------------- IAM RESULTS ----------------

st.header("🔑 IAM Permission Findings")
st.write("Checks sample IAM policies for potentially broad permissions.")

st.dataframe(
    pd.DataFrame(iam_findings),
    use_container_width=True,
    hide_index=True
)

st.divider()

# ---------------- RECOMMENDATIONS ----------------

st.header("🛠️ Recommended Actions")

for finding in all_findings:
    with st.container(border=True):
        st.subheader(finding["finding"])
        st.write(f"**Service:** {finding['service']}")
        st.write(f"**Severity:** {finding['severity']}")
        st.write(f"**Recommendation:** {finding['recommendation']}")

st.divider()

st.caption(
    "CloudSentry prototype | Sample data only | "
    "Live AWS assessment will be added in a later phase."
)
