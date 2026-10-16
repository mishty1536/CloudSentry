
import streamlit as st

# Page configuration
st.set_page_config(
    page_title="CloudSentry | Cloud Security Auditor",
    page_icon="🛡️",
    layout="wide"
)

# Dashboard heading
st.title("🛡️ CloudSentry")
st.subheader("AWS Cloud Security Assessment Dashboard")

st.write(
    "CloudSentry identifies potentially insecure cloud configurations, "
    "explains their risks, and recommends ways to fix them."
)

st.info(
    "Demo mode is active. We are using sample data, "
    "so no AWS connection is required yet."
)

# Summary metrics
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Resources Scanned", "5")

with col2:
    st.metric("Security Findings", "3")

with col3:
    st.metric("High-Risk Findings", "1")

st.divider()

# Sample findings
st.header("Security Findings")

findings = [
    {
        "resource": "demo-bucket-public",
        "service": "Amazon S3",
        "severity": "High",
        "issue": "Public access protection is disabled",
        "recommendation": (
            "Review the bucket's intended access. Enable S3 Block Public Access "
            "unless public access is explicitly required and approved."
        )
    },
    {
        "resource": "DemoDeveloperPolicy",
        "service": "AWS IAM",
        "severity": "Medium",
        "issue": "Policy contains wildcard permissions",
        "recommendation": (
            "Review wildcard actions and resources. Replace broad permissions "
            "with only the actions and resources required."
        )
    },
    {
        "resource": "demo-trail",
        "service": "AWS CloudTrail",
        "severity": "Low",
        "issue": "Logging status needs verification",
        "recommendation": (
            "Verify that the trail is configured correctly and logging is enabled."
        )
    }
]

for finding in findings:
    with st.container(border=True):
        st.subheader(finding["resource"])

        st.write(f"**Service:** {finding['service']}")
        st.write(f"**Severity:** {finding['severity']}")
        st.write(f"**Issue:** {finding['issue']}")
        st.write(f"**Recommendation:** {finding['recommendation']}")

st.caption(
    "CloudSentry student prototype | Sample findings only — "
    "not a live AWS security assessment."
)
