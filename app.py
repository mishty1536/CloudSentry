
import streamlit as st
import pandas as pd
from datetime import datetime
from pathlib import Path
import re
import os

from botocore.exceptions import BotoCoreError

from s3_auditor import audit_s3_configuration
from iam_auditor import audit_iam_policy
from cloudTrail_auditor import audit_cloudtrail_configuration
from aws_auditor import audit_aws_account, create_aws_clients
from dashboard_helpers import (
    assessment_status,
    calculate_risk_score,
    classify_risk,
    combine_findings,
    count_severity,
    make_findings_dataframe,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CloudSentry | Cloud Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- CloudSentry Appearance ---
if "theme_mode" not in st.session_state:
    st.session_state.theme_mode = "Dark"

st.sidebar.subheader("🎨 Appearance")

st.sidebar.radio(
    "Choose theme",
    options=["Dark", "Light"],
    key="theme_mode",
    format_func=lambda mode: "🌙 Dark Mode" if mode == "Dark" else "☀️ Light Mode",
)

theme_css = Path(__file__).parent / "theme.css"
css = theme_css.read_text(encoding="utf-8")

# Apply the selected palette directly to CSS variables so the toggle works reliably.
if st.session_state.theme_mode == "Dark":
    active_palette = {
        "bg": "#080D18", "surface": "#0E1728", "surface_raised": "#121F33",
        "surface_alt": "#16263D", "text": "#EAF1FB", "muted": "#9BAFC9",
        "border": "#263A56", "accent": "#60A5FA", "accent_hover": "#93C5FD",
        "cyan": "#5BE0E6", "success": "#50D6A4", "warning": "#F5C46B",
        "danger": "#FF8198", "input": "#101C2F", "shadow": "rgba(0,0,0,.24)"
    }
else:
    active_palette = {
        "bg": "#F3F6FC", "surface": "#FFFFFF", "surface_raised": "#FFFFFF",
        "surface_alt": "#EAF0FA", "text": "#17263D", "muted": "#60718A",
        "border": "#D5E0EF", "accent": "#1D4ED8", "accent_hover": "#1E40AF",
        "cyan": "#087E99", "success": "#087F5B", "warning": "#946200",
        "danger": "#B42352", "input": "#FFFFFF", "shadow": "rgba(30,55,90,.08)"
    }

palette_css = ":root, .stApp, [data-testid=\"stAppViewContainer\"], section[data-testid=\"stSidebar\"] {\n" + "\n".join(
    f"  --cs-{key.replace('_', '-')}: {value};" for key, value in active_palette.items()
) + "\n  color-scheme: " + ("dark" if st.session_state.theme_mode == "Dark" else "light") + ";\n}"
st.markdown(f"<style>{css}\n{palette_css}</style>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="cs-hero">
        <div class="cs-eyebrow">CLOUD SECURITY • THREAT MONITORING</div>
        <h1 class="cs-hero-title">🛡️ CloudSentry</h1>
        <p class="cs-hero-subtitle">AWS Misconfiguration Detection &amp; Risk Assessment</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.header("AWS Cloud Security Assessment Dashboard")

st.write(
    "Identify potential cloud security risks, understand their impact, "
    "and review recommended security improvements."
)

aws_scan_enabled = os.environ.get("CLOUDSENTRY_ENABLE_AWS_SCAN", "").strip().lower() in {
    "1", "true", "yes"
}
mode_options = ["Demo", "AWS (read-only)"] if aws_scan_enabled else ["Demo"]
if st.session_state.get("operating_mode") not in mode_options:
    st.session_state["operating_mode"] = "Demo"

operating_mode = st.sidebar.radio(
    "Operating mode",
    options=mode_options,
    key="operating_mode",
)

if operating_mode == "Demo":
    st.info(
        "Demo mode: Findings use sample configurations. "
        "No AWS clients or AWS API calls are used."
    )
    if not aws_scan_enabled:
        st.caption("AWS scanning is disabled in this Demo-only deployment.")
else:
    st.info(
        "AWS mode performs read-only checks only after you press Start AWS scan. "
        "Credentials come from Boto3's standard provider chain."
    )


# ============================================================
# DISPLAY HELPERS
# ============================================================

def display_dataframe(df, *, hide_index=True):
    """Render dataframes using the active CloudSentry palette."""
    if df is None:
        df = pd.DataFrame()

    dark_mode = st.session_state.get("theme_mode", "Dark") == "Dark"
    if dark_mode:
        background = "#0E1728"
        alternate = "#121F33"
        header = "#1B3150"
        text = "#EAF1FB"
        border = "#263A56"
    else:
        background = "#FFFFFF"
        alternate = "#F3F6FC"
        header = "#E5EDF9"
        text = "#17263D"
        border = "#D5E0EF"

    styler = df.style.set_table_styles([
        {"selector": "th", "props": [
            ("background-color", header), ("color", text),
            ("border", f"1px solid {border}"), ("font-weight", "700"),
            ("padding", "10px")
        ]},
        {"selector": "td", "props": [
            ("color", text), ("border", f"1px solid {border}"),
            ("padding", "9px")
        ]},
        {"selector": "table", "props": [
            ("border-collapse", "collapse"), ("border-radius", "10px"),
            ("overflow", "hidden"), ("width", "100%")
        ]},
    ]).set_properties(**{"background-color": background, "color": text})

    # Alternate rows and tint severity text without changing the underlying data.
    def row_style(row):
        row_number = row.name if isinstance(row.name, int) else 0
        base = background if row_number % 2 == 0 else alternate
        styles = [f"background-color: {base}; color: {text};"] * len(row)
        if "severity" in row.index:
            severity = str(row.get("severity", "")).strip().lower()
            color = {
                "high": "#FF8198" if dark_mode else "#B42352",
                "medium": "#F5C46B" if dark_mode else "#946200",
                "low": "#5BE0E6" if dark_mode else "#087E99",
                "info": "#50D6A4" if dark_mode else "#087F5B",
            }.get(severity)
            if color:
                styles[row.index.get_loc("severity")] = (
                    f"background-color: {base}; color: {color}; font-weight: 700;"
                )
        return styles

    if not df.empty:
        styler = styler.apply(row_style, axis=1)

    st.dataframe(styler, use_container_width=True, hide_index=hide_index)


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
        "block_public_access": {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets
        },
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
# MODE-SPECIFIC SCAN CONFIGURATION
# ============================================================

if operating_mode == "Demo":
    st.divider()
    st.header("⚙️ Security Scan Configuration")

    with st.form("security_scan_form"):
        st.subheader("🪣 S3 Security Settings")
        col1, col2 = st.columns(2)

        with col1:
            block_public_acls = st.checkbox("Block public ACLs", value=True)
            ignore_public_acls = st.checkbox("Ignore public ACLs", value=True)
            block_public_policy = st.checkbox("Block public bucket policies", value=True)

        with col2:
            restrict_public_buckets = st.checkbox("Restrict public buckets", value=True)
            encryption_enabled = st.checkbox("Enable default bucket encryption", value=True)

        st.divider()
        st.subheader("🔑 IAM Permission Settings")
        col1, col2 = st.columns(2)

        with col1:
            allow_all_actions = st.checkbox("Allow all actions (*)", value=False)
        with col2:
            allow_all_resources = st.checkbox("Apply permissions to all resources (*)", value=False)

        st.caption(
            "Uncheck wildcard permissions to simulate a more restrictive "
            "sample IAM policy."
        )

        st.divider()
        st.subheader("📜 CloudTrail Logging Settings")
        col1, col2, col3 = st.columns(3)

        with col1:
            logging_enabled = st.checkbox("CloudTrail logging enabled", value=True)
        with col2:
            log_validation_enabled = st.checkbox(
                "Log file integrity validation enabled", value=True
            )
        with col3:
            multi_region_enabled = st.checkbox("Multi-region trail enabled", value=True)

        scan_clicked = st.form_submit_button(
            "🔍 Scan Configuration",
            type="primary",
            use_container_width=True,
        )
    selected_region = None
else:
    st.divider()
    st.header("🔐 AWS Read-only Scan")
    with st.form("aws_scan_form"):
        selected_region = st.text_input(
            "AWS region",
            value=st.session_state.get("aws_region", "us-east-1"),
            help="CloudTrail checks apply to this region. Other regions are not scanned.",
        ).strip()
        scan_clicked = st.form_submit_button(
            "Start AWS scan",
            type="primary",
            use_container_width=True,
        )
    if selected_region:
        st.session_state["aws_region"] = selected_region

# ============================================================
# EXECUTE SCAN AND STORE RESULTS
# ============================================================

if scan_clicked:
    new_results = None
    if operating_mode == "Demo":
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
            multi_region_enabled,
        )
    elif operating_mode == "AWS (read-only)" and not aws_scan_enabled:
        st.error("AWS scanning is disabled in this deployment.")
    elif not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", selected_region or ""):
        st.error("Enter a valid AWS region name, such as us-east-1.")
    else:
        try:
            s3_client, iam_client, cloudtrail_client = create_aws_clients(selected_region)
            new_results = audit_aws_account(
                s3_client, iam_client, cloudtrail_client, selected_region
            )
        except (BotoCoreError, ValueError):
            st.error(
                "AWS clients could not be initialized. Check the region and "
                "local AWS credential provider configuration; no credentials "
                "are displayed or stored."
            )

    if new_results is not None:
        previous_mode = st.session_state.get("scan_mode")
        if (
            st.session_state["scan_results"] is not None
            and previous_mode == operating_mode
        ):
            st.session_state["previous_scan_results"] = st.session_state["scan_results"]
        else:
            st.session_state["previous_scan_results"] = None

        st.session_state["scan_results"] = new_results
        st.session_state["scan_mode"] = operating_mode
        st.session_state["scan_region"] = selected_region
        st.session_state["scan_number"] += 1

        all_new_findings = combine_findings(new_results)
        new_risk_score = calculate_risk_score(all_new_findings)
        history_record = {
            "Scan Number": st.session_state["scan_number"],
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Mode": operating_mode,
            "Region": selected_region or "Demo",
            "Total Findings": len(all_new_findings),
            "High Severity": count_severity(all_new_findings, "High"),
            "Medium Severity": count_severity(all_new_findings, "Medium"),
            "Unknown / Unverified": count_severity(all_new_findings, "Unknown"),
            "Assessment Status": assessment_status(all_new_findings),
            "Risk Score": new_risk_score,
        }
        st.session_state["scan_history"].append(history_record)
        st.session_state["scan_history"] = st.session_state["scan_history"][-20:]
        st.success("Security scan completed. Review any Unknown findings as unverified.")


# ============================================================
# DISPLAY RESULTS
# ============================================================

results = st.session_state["scan_results"]

if results is None or st.session_state.get("scan_mode") != operating_mode:
    if results is None:
        st.info("Choose an operating mode and explicitly start a scan to view results.")
    else:
        st.info(f"No {operating_mode} results are available yet. Start a scan in this mode.")
    st.stop()

if not isinstance(results, dict):
    results = {"unexpected_results": results}

if operating_mode == "AWS (read-only)":
    st.info(
        f"AWS read-only scan region: {st.session_state.get('scan_region', 'Unknown')}. "
        "S3 checks cover bucket-level public access and encryption settings only; "
        "they do not establish effective account-wide or organization-wide public access. "
        "CloudTrail status is regional and does not verify every AWS region. "
        "IAM results inspect returned identity policy documents and do not calculate effective permissions."
    )


all_findings = combine_findings(results)
findings_df = make_findings_dataframe(all_findings)

high_count = count_severity(all_findings, "High")
medium_count = count_severity(all_findings, "Medium")
low_count = count_severity(all_findings, "Low")
unknown_count = count_severity(all_findings, "Unknown")
current_assessment_status = assessment_status(all_findings)

risk_score = calculate_risk_score(all_findings)
risk_classification = classify_risk(risk_score)


# ============================================================
# SCAN HISTORY
# ============================================================

st.divider()
st.header("🕒 Scan History")

history_df = pd.DataFrame(st.session_state["scan_history"])

if not history_df.empty:
    display_dataframe(history_df, hide_index=True)
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

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Overall Risk Score", f"{risk_score}/100")

with col2:
    st.metric("Risk Classification", risk_classification)

with col3:
    st.metric("Unknown / Unverified", unknown_count)

with col4:
    st.metric("Assessment Status", current_assessment_status)

if current_assessment_status == "Incomplete":
    st.warning(
        f"Assessment incomplete: {unknown_count} finding(s) are Unknown / unverified. "
        "The risk score is not proof that the configuration is secure."
    )

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

mode_history = [
    record for record in st.session_state["scan_history"]
    if record.get("Mode", "Demo") == operating_mode
]

if len(mode_history) >= 2:

    trend_df = pd.DataFrame(mode_history)

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

# Combine and normalize findings while retaining unexpected entries/fields.
scan_results = st.session_state.get("scan_results", {})
all_findings = combine_findings(scan_results)

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
    display_dataframe(filtered_df.reset_index(drop=True), hide_index=True)

else:
    st.success("No security findings to display.")

# ============================================================
# INDIVIDUAL SERVICE FINDINGS
# ============================================================

st.divider()
st.header("🪣 S3 Security Findings")
st.write("Checks public access protection and default encryption.")

display_dataframe(
    make_findings_dataframe(combine_findings({"s3": results.get("s3", [])})),
    hide_index=True,
)

st.divider()
st.header("🔑 IAM Permission Findings")
st.write("Checks sample IAM policies for potentially broad permissions.")

display_dataframe(
    make_findings_dataframe(combine_findings({"iam": results.get("iam", [])})),
    hide_index=True,
)

st.divider()
st.header("📜 CloudTrail Logging Findings")
st.write("Checks sample activity logging and trail configuration.")

display_dataframe(
    make_findings_dataframe(combine_findings({"cloudtrail": results.get("cloudtrail", [])})),
    hide_index=True,
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
            {"Metric": "Mode", "Value": operating_mode},
            {"Metric": "Region", "Value": st.session_state.get("scan_region") or "Demo"},
            {"Metric": "Services Audited", "Value": 3},
            {"Metric": "Total Findings", "Value": len(all_findings)},
            {"Metric": "High Severity", "Value": high_count},
            {"Metric": "Medium Severity", "Value": medium_count},
            {"Metric": "Low Severity", "Value": low_count},
            {"Metric": "Unknown / Unverified Findings", "Value": unknown_count},
            {"Metric": "Assessment Status", "Value": current_assessment_status},
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

    if operating_mode == "Demo":
        st.caption("Reports contain results from the latest demo scan using sample configurations.")
    else:
        st.caption(
            "Reports contain results from the latest read-only AWS scan. "
            "Unknown findings mean a check could not be verified."
        )

else:
    st.success("No security findings to export.")


# ============================================================
# FOOTER
# ============================================================

st.divider()

if operating_mode == "Demo":
    st.caption("CloudSentry | Educational Cloud Security Prototype | Demo mode uses sample data only.")
else:
    st.caption("CloudSentry | AWS mode is read-only and limited to the documented scan coverage.")
