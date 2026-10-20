import inspect
import logging
import math
import os
import re
import traceback
from pathlib import Path

import pandas as pd
import streamlit as st
from botocore.exceptions import BotoCoreError, ClientError
from s3_auditor import audit_s3_configuration
from iam_auditor import audit_iam_policy
from cloudTrail_auditor import audit_cloudtrail_configuration
from aws_auditor import audit_aws_account, create_aws_clients_with_session
from dashboard_helpers import (
    calculate_risk_score,
    classify_risk,
    combine_findings,
    count_severity,
    make_findings_dataframe,
    prepare_dataframe_for_display,
)
from scan_history import (
    ScanHistoryError,
    ScanHistoryStore,
    compare_scans,
    scan_assessment_status,
)
from pdf_reports import generate_pdf_report
from s3_remediation import PROTECTED_BUCKET_NAME, remediate_s3_default_encryption

aws_scan_logger = logging.getLogger("cloudsentry.aws_scan")


def log_aws_scan_exception(error, *, phase, region):
    """Log traceback frames without exception text or local variable values."""
    stack = "".join(traceback.format_tb(error.__traceback__))
    aws_scan_logger.error(
        "Unexpected AWS scan failure: phase=%s region=%s exception_type=%s\n%s",
        phase,
        region,
        type(error).__name__,
        stack,
    )


def combine_scan_findings(results):
    """Combine findings while keeping account-wide coverage metadata separate."""
    if isinstance(results, dict) and "cloudtrail_account_coverage" in results:
        results = {
            key: value for key, value in results.items()
            if key != "cloudtrail_account_coverage"
        }
    return combine_findings(results)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CloudSentry | Cloud Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# --- CloudSentry Appearance ---
if "theme_mode" not in st.session_state:
    st.session_state.theme_mode = "Dark"

st.sidebar.subheader("Appearance")

st.sidebar.radio(
    "Choose theme",
    options=["Dark", "Light"],
    key="theme_mode",
    format_func=lambda mode: f"{mode} Mode",
)

theme_css = Path(__file__).parent / "theme.css"
css = theme_css.read_text(encoding="utf-8") if theme_css.exists() else ""

# Apply the selected palette directly to CSS variables so the toggle works reliably.
if st.session_state.theme_mode == "Dark":
    active_palette = {
        "bg": "#080D18", "surface": "#0E1728", "surface_raised": "#121F33",
        "surface_alt": "#16263D", "text": "#EAF1FB", "muted": "#9BAFC9",
        "border": "#263A56", "accent": "#60A5FA", "accent_hover": "#93C5FD",
        "cyan": "#5BE0E6", "success": "#50D6A4", "warning": "#F5C46B",
        "danger": "#FF8198", "input": "#101C2F", "shadow": "rgba(0,0,0,.24)",
    }
else:
    active_palette = {
        "bg": "#F3F6FC", "surface": "#FFFFFF", "surface_raised": "#FFFFFF",
        "surface_alt": "#EAF0FA", "text": "#17263D", "muted": "#60718A",
        "border": "#D5E0EF", "accent": "#1D4ED8", "accent_hover": "#1E40AF",
        "cyan": "#087E99", "success": "#087F5B", "warning": "#946200",
        "danger": "#B42352", "input": "#FFFFFF", "shadow": "rgba(30,55,90,.08)",
    }

palette_css = (
    ':root, .stApp, [data-testid="stAppViewContainer"], section[data-testid="stSidebar"] {\n'
    + "\n".join(
        f"  --cs-{key.replace('_', '-')}: {value};" for key, value in active_palette.items()
    )
    + "\n  color-scheme: "
    + ("dark" if st.session_state.theme_mode == "Dark" else "light")
    + ";\n}"
)
st.markdown(f"<style>{css}\n{palette_css}</style>", unsafe_allow_html=True)

st.markdown(
    """
    <div class="cs-hero">
        <div class="cs-eyebrow">CLOUD SECURITY • THREAT MONITORING</div>
        <h1 class="cs-hero-title">CloudSentry</h1>
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
s3_remediation_enabled = os.environ.get(
    "CLOUDSENTRY_ENABLE_S3_REMEDIATION", ""
).strip().lower() in {"1", "true", "yes"}
s3_remediation_bucket = os.environ.get("CLOUDSENTRY_S3_REMEDIATION_BUCKET", "").strip()
s3_remediation_region = os.environ.get("CLOUDSENTRY_S3_REMEDIATION_REGION", "").strip()
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
        "Credentials can come from an attached EC2 IAM Role, local AWS profile, "
        "environment variables, or optional credentials."
    )

remediation_clicked = False
remediation_confirmation = ""


# ============================================================
# CONSTANTS AND HELPERS
# ============================================================

PAGE_SIZE_OPTIONS = [10, 25, 50]

REMEDIATION_STEPS = {
    "S3": [
        "Review S3 Block Public Access settings.",
        "Enable the four public access protection controls where appropriate.",
        "Enable default server-side encryption.",
        "Review bucket policies and ACLs.",
        "Verify access requirements before applying changes.",
    ],
    "IAM": [
        "Review the IAM policy's Effect, Action, and Resource.",
        "Replace unnecessary wildcard permissions.",
        "Grant only the actions required for the task.",
        "Restrict resources to specific ARNs where supported.",
        "Test the least-privilege policy before deployment.",
    ],
    "CloudTrail": [
        "Enable CloudTrail logging.",
        "Enable log file integrity validation.",
        "Review whether a multi-region trail is required.",
        "Secure log storage and limit access to logs.",
        "Monitor logging status and retention.",
    ],
}


def stretch_kwargs(widget):
    """Return the full-width argument supported by the installed Streamlit version."""
    try:
        if "width" in inspect.signature(widget).parameters:
            return {"width": "stretch"}
    except (TypeError, ValueError):
        pass
    return {"use_container_width": True}


def has_content(value):
    """True if a cell holds something other than empty/NaN/whitespace."""
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return bool(str(value).strip())


def clean_findings_dataframe(df):
    """Drop rows that are completely empty. Never mutates the input."""
    if df is None or df.empty:
        return pd.DataFrame()
    df = df.dropna(how="all")
    if df.empty:
        return pd.DataFrame()
    mask = pd.Series(
        [any(has_content(value) for value in row) for row in df.itertuples(index=False)],
        index=df.index,
    )
    return df.loc[mask].reset_index(drop=True)


def display_dataframe(df, *, hide_index=True):
    """Render dataframes using the active CloudSentry palette."""
    if df is None:
        df = pd.DataFrame()
    else:
        df = df.copy().reset_index(drop=True)
        df = df.astype(object).where(pd.notna(df), "—")

    df, has_shortened_values = prepare_dataframe_for_display(df)
    if has_shortened_values:
        st.caption("Long resource and recommendation cells are shortened in this table; PDF exports retain the full values.")

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
            ("padding", "10px"),
        ]},
        {"selector": "td", "props": [
            ("color", text), ("border", f"1px solid {border}"),
            ("padding", "9px"),
        ]},
        {"selector": "table", "props": [
            ("border-collapse", "collapse"), ("border-radius", "10px"),
            ("overflow", "hidden"), ("width", "100%"),
        ]},
    ]).set_properties(**{"background-color": background, "color": text})

    severity_colors = {
        "high": "#FF8198" if dark_mode else "#B42352",
        "medium": "#F5C46B" if dark_mode else "#946200",
        "low": "#5BE0E6" if dark_mode else "#087E99",
        "info": "#50D6A4" if dark_mode else "#087F5B",
    }

    # Alternate rows and tint severity text without changing the underlying data.
    def row_style(row):
        base = background if int(row.name) % 2 == 0 else alternate
        styles = [f"background-color: {base}; color: {text};"] * len(row)
        if "severity" in row.index:
            severity = str(row.get("severity", "")).strip().lower()
            color = severity_colors.get(severity)
            if color:
                styles[row.index.get_loc("severity")] = (
                    f"background-color: {base}; color: {color}; font-weight: 700;"
                )
        return styles

    if not df.empty:
        styler = styler.apply(row_style, axis=1)

    try:
        st.dataframe(styler, width="stretch", hide_index=hide_index)
    except Exception:
        # Older Streamlit versions do not accept width="stretch".
        st.dataframe(styler, use_container_width=True, hide_index=hide_index)


def render_scan_history_section(history_store, operating_mode, selected_region):
    """Render persisted history and compare only compatible snapshots."""
    st.divider()
    st.header("Scan History")
    if history_store is None:
        st.warning(
            "Persistent scan history is unavailable. Completed scans can still be viewed, "
            "but this run cannot save or compare history."
        )
        return []

    history_mode = "AWS" if operating_mode == "AWS (read-only)" else "Demo"
    try:
        summaries = history_store.list_scans(mode=history_mode)
    except ScanHistoryError as error:
        st.warning(
            f"Persistent scan history could not be read ({type(error).__name__}). "
            "Current scan results remain available."
        )
        return []

    if history_mode == "AWS":
        regions = sorted({item["region"] for item in summaries if item.get("region")})
        if not regions:
            st.info("No saved AWS scans are available yet.")
            return []
        region_key = "history_region_filter_aws"
        if st.session_state.get(region_key) not in regions:
            st.session_state[region_key] = (
                selected_region if selected_region in regions else summaries[0]["region"]
            )
        chosen_region = st.selectbox("AWS history region", regions, key=region_key)
        summaries = [item for item in summaries if item.get("region") == chosen_region]

    if not summaries:
        st.info(f"No saved {history_mode} scans are available yet.")
        return []

    history_table = [
        {
            "Scan": item["scan_number"],
            "Scan ID": item["scan_id"][:12],
            "Timestamp (UTC)": item["scanned_at"],
            "Mode": item["mode"],
            "Region": item["region"] or "—",
            "Findings": item["total_findings"],
            "High": item["severity_counts"].get("High", 0),
            "Medium": item["severity_counts"].get("Medium", 0),
            "Low": item["severity_counts"].get("Low", 0),
            "Info": item["severity_counts"].get("Info", 0),
            "Unknown": item["severity_counts"].get("Unknown", 0),
            "Risk Score": item["risk_score"],
            "Status": item["assessment_status"],
        }
        for item in summaries
    ]
    st.dataframe(pd.DataFrame(history_table), hide_index=True, **stretch_kwargs(st.dataframe))

    if len(summaries) < 2:
        st.info("Save at least two compatible scans to compare before and after results.")
        return summaries

    scan_ids = [item["scan_id"] for item in summaries]
    labels = {
        item["scan_id"]: (
            f"Scan {item['scan_number']} · {item['scanned_at']} · "
            f"{item['total_findings']} findings · risk {item['risk_score']}"
        )
        for item in summaries
    }
    after_key = f"history_after_scan_{history_mode.lower()}"
    before_key = f"history_before_scan_{history_mode.lower()}"
    if st.session_state.get(after_key) not in scan_ids:
        st.session_state[after_key] = scan_ids[0]
    if st.session_state.get(before_key) not in scan_ids:
        st.session_state[before_key] = scan_ids[1]

    st.subheader("Before-and-after comparison")
    before_col, after_col = st.columns(2)
    with before_col:
        before_id = st.selectbox(
            "Before scan", scan_ids, format_func=labels.get, key=before_key
        )
    with after_col:
        after_id = st.selectbox(
            "After scan", scan_ids, format_func=labels.get, key=after_key
        )

    try:
        before = history_store.get_scan(before_id)
        after = history_store.get_scan(after_id)
        if before is None or after is None:
            st.warning("A selected scan is no longer available in persistent history.")
            return summaries
        comparison = compare_scans(before, after)
    except (ScanHistoryError, ValueError) as error:
        st.warning(f"These scans cannot be compared ({type(error).__name__}).")
        return summaries

    if comparison["identical"]:
        st.info("The selected scans are identical in findings, severity counts, score, and coverage.")
    if not comparison["before_complete"] or not comparison["after_complete"]:
        st.warning(
            "At least one assessment is incomplete. Findings absent from an incomplete scan "
            "are unverified and are not counted as resolved or newly detected."
        )

    score_rows = [
        {
            "Measure": "Total findings",
            "Before": comparison["before_total"],
            "After": comparison["after_total"],
        },
        *[
            {"Measure": severity, **values}
            for severity, values in comparison["severity"].items()
        ],
        {
            "Measure": "Risk score",
            "Before": comparison["before_risk_score"],
            "After": comparison["after_risk_score"],
        },
    ]
    st.dataframe(pd.DataFrame(score_rows), hide_index=True, **stretch_kwargs(st.dataframe))
    st.caption(
        f"Resolved: {len(comparison['resolved'])} · Remaining: {len(comparison['remaining'])} · "
        f"Newly detected: {len(comparison['newly_detected'])}"
    )
    if comparison["unverified_before"] or comparison["unverified_after"]:
        st.caption(
            "Unverified comparison records: "
            f"{len(comparison['unverified_before'])} before, "
            f"{len(comparison['unverified_after'])} after."
        )
    for label, key in (
        ("Resolved findings", "resolved"),
        ("Remaining findings", "remaining"),
        ("Newly detected findings", "newly_detected"),
    ):
        records = comparison[key]
        with st.expander(f"{label} ({len(records)})"):
            if records:
                st.dataframe(
                    pd.DataFrame(records), hide_index=True, **stretch_kwargs(st.dataframe)
                )
            else:
                st.caption("None")
    return summaries


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
    multi_region_enabled,
):
    """Run the three local demo auditors."""

    s3_config = {
        "block_public_access": {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets,
        },
        "encryption_enabled": encryption_enabled,
    }

    iam_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*" if allow_all_actions else ["s3:GetObject"],
                "Resource": (
                    "*" if allow_all_resources
                    else ["arn:aws:s3:::example-bucket/*"]
                ),
            }
        ],
    }

    cloudtrail_config = {
        "logging_enabled": logging_enabled,
        "log_validation_enabled": log_validation_enabled,
        "multi_region_enabled": multi_region_enabled,
    }

    return {
        "s3": audit_s3_configuration(s3_config),
        "iam": audit_iam_policy(iam_policy),
        "cloudtrail": audit_cloudtrail_configuration(cloudtrail_config),
    }


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None

if "scan_number" not in st.session_state:
    st.session_state["scan_number"] = 0

try:
    history_store = ScanHistoryStore()
except ScanHistoryError as error:
    history_store = None
    logging.getLogger("cloudsentry.scan_history").error(
        "Persistent scan history initialization failed: %s", type(error).__name__
    )


# ============================================================
# MODE-SPECIFIC SCAN CONFIGURATION
# ============================================================

selected_region = None
aws_access_key = ""
aws_secret_key = ""
aws_session_token = ""

if operating_mode == "Demo":
    st.divider()
    st.header("Security Scan Configuration")

    with st.container(border=True):
        st.subheader("S3 Security Settings")
        col1, col2 = st.columns(2)

        with col1:
            block_public_acls = st.checkbox("Block public ACLs", value=True)
            ignore_public_acls = st.checkbox("Ignore public ACLs", value=True)
            block_public_policy = st.checkbox("Block public bucket policies", value=True)

        with col2:
            restrict_public_buckets = st.checkbox("Restrict public buckets", value=True)
            encryption_enabled = st.checkbox("Enable default bucket encryption", value=True)

        st.divider()
        st.subheader("IAM Permission Settings")
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
        st.subheader("CloudTrail Logging Settings")
        col1, col2, col3 = st.columns(3)

        with col1:
            logging_enabled = st.checkbox("CloudTrail logging enabled", value=True)
        with col2:
            log_validation_enabled = st.checkbox(
                "Log file integrity validation enabled", value=True
            )
        with col3:
            multi_region_enabled = st.checkbox("Multi-region trail enabled", value=True)

        scan_clicked = st.button(
            "Scan Configuration",
            type="primary",
            key="demo_scan_submit",
            **stretch_kwargs(st.button),
        )
else:
    st.divider()
    st.header("AWS Read-only Scan")
    with st.container(border=True):
        selected_region = st.text_input(
            "AWS region",
            value=st.session_state.get("aws_region", "us-east-1"),
            help=(
                "CloudTrail checks apply to this region. S3 bucket listing and "
                "IAM checks inspect account-level resources."
            ),
        ).strip()

        with st.expander("AWS Credentials (Optional)", expanded=False):
            st.caption(
                "Leave blank to use the attached EC2 IAM Role (recommended on AWS), "
                "local AWS credentials file (~/.aws/credentials), or environment variables."
            )
            aws_access_key = st.text_input(
                "AWS Access Key ID",
                type="password",
                help="Optional. Leave blank to use instance profile / default credentials.",
                key="aws_access_key_input",
            ).strip()
            aws_secret_key = st.text_input(
                "AWS Secret Access Key",
                type="password",
                help="Optional. Leave blank to use instance profile / default credentials.",
                key="aws_secret_key_input",
            ).strip()
            aws_session_token = st.text_input(
                "AWS Session Token (Optional)",
                type="password",
                help="Optional. Required only for temporary session credentials.",
                key="aws_session_token_input",
            ).strip()

        scan_clicked = st.button(
            "Start AWS scan",
            type="primary",
            key="aws_scan_submit",
            **stretch_kwargs(st.button),
        )
    if selected_region:
        st.session_state["aws_region"] = selected_region

    if s3_remediation_enabled:
        st.divider()
        st.subheader("Optional S3 default-encryption remediation")
        st.warning(
            "This action writes a bucket encryption configuration. It is never run during a scan. "
            "Only the separately configured dedicated test bucket is eligible."
        )
        if not s3_remediation_bucket:
            st.info("Remediation is unavailable until a dedicated test bucket is configured.")
        elif s3_remediation_bucket == PROTECTED_BUCKET_NAME:
            st.error("Remediation is hard-disabled for the protected CloudSentry test bucket.")
        elif not s3_remediation_region:
            st.info("Remediation is unavailable until the dedicated bucket's AWS region is configured.")
        else:
            st.caption(
                f"Configured dedicated bucket: {s3_remediation_bucket} "
                f"(region {s3_remediation_region})."
            )
            remediation_confirmation = st.text_input(
                f"Type {s3_remediation_bucket} to confirm",
                key="s3_remediation_confirmation",
            )
            if selected_region != s3_remediation_region:
                st.warning(
                    "Select the configured test bucket region before the remediation action is available."
                )
            remediation_clicked = st.button(
                "Apply SSE-S3 encryption to dedicated test bucket",
                type="secondary",
                key="s3_remediation_submit",
                disabled=selected_region != s3_remediation_region,
                **stretch_kwargs(st.button),
            )


# ============================================================
# EXECUTE SCAN AND STORE RESULTS
# ============================================================

if remediation_clicked:
    if remediation_confirmation != s3_remediation_bucket:
        st.error("Bucket name confirmation did not match exactly. No AWS client was created.")
    elif s3_remediation_bucket == PROTECTED_BUCKET_NAME:
        st.error("Remediation is blocked for the protected CloudSentry test bucket.")
    elif selected_region != s3_remediation_region:
        st.error("The selected AWS region does not match the configured test bucket region.")
    else:
        try:
            with st.spinner("Checking and applying S3 SSE-S3 only for the confirmed test bucket..."):
                _, (s3_client, _, _) = create_aws_clients_with_session(
                    selected_region,
                    aws_access_key_id=aws_access_key or None,
                    aws_secret_access_key=aws_secret_key or None,
                    aws_session_token=aws_session_token or None,
                )
                remediation_result = remediate_s3_default_encryption(
                    s3_client,
                    remediation_confirmation,
                    allowed_bucket_name=s3_remediation_bucket,
                )
            if remediation_result["success"]:
                st.success(remediation_result["message"])
            else:
                st.error(remediation_result["message"])
        except (BotoCoreError, ClientError, ValueError) as error:
            st.error(
                f"S3 remediation could not be completed ({type(error).__name__}). "
                "No success is reported. Check service logs; credentials are not displayed."
            )

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
    elif not aws_scan_enabled:
        st.error("AWS scanning is disabled in this deployment.")
    elif not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", selected_region or ""):
        st.error("Enter a valid AWS region name, such as us-east-1.")
    else:
        scan_phase = "AWS client initialization"
        try:
            with st.spinner(f"Running read-only AWS security scan in {selected_region}..."):
                session, (s3_client, iam_client, cloudtrail_client) = create_aws_clients_with_session(
                    selected_region,
                    aws_access_key_id=aws_access_key or None,
                    aws_secret_access_key=aws_secret_key or None,
                    aws_session_token=aws_session_token or None,
                )
                scan_phase = "S3, IAM, and CloudTrail audit operations"
                new_results = audit_aws_account(
                    s3_client,
                    iam_client,
                    cloudtrail_client,
                    selected_region,
                    regions_client_factory=lambda: session.client(
                        "ec2", region_name=selected_region
                    ),
                    cloudtrail_client_factory=lambda region: session.client(
                        "cloudtrail", region_name=region
                    ),
                )
        except (BotoCoreError, ClientError, ValueError) as error:
            st.error(
                f"AWS scan failed: {error}. "
                "Check the region, network connection, and AWS credentials; no credentials "
                "are displayed or stored."
            )
        except Exception as error:  # noqa: BLE001 - keep the dashboard alive on any failure
            log_aws_scan_exception(
                error, phase=scan_phase, region=selected_region
            )
            st.error(
                f"AWS scan failed unexpectedly ({type(error).__name__}). "
                "Check the service logs for details; no credentials are displayed or stored."
            )

    if new_results is not None:
        st.session_state["scan_results"] = new_results
        st.session_state["scan_mode"] = operating_mode
        st.session_state["scan_region"] = selected_region

        all_new_findings = combine_scan_findings(new_results)
        new_risk_score = calculate_risk_score(all_new_findings)
        coverage = (
            new_results.get("cloudtrail_account_coverage")
            if isinstance(new_results, dict) else None
        )
        new_assessment_status = scan_assessment_status(
            all_new_findings, coverage, mode=operating_mode
        )
        if history_store is not None:
            try:
                saved_scan = history_store.save_scan(
                    mode=operating_mode,
                    region=selected_region,
                    findings=all_new_findings,
                    risk_score=new_risk_score,
                    assessment_status=new_assessment_status,
                    coverage=coverage if isinstance(coverage, dict) else None,
                )
                st.session_state["scan_number"] = saved_scan["scan_number"]
                mode_key = "aws" if operating_mode == "AWS (read-only)" else "demo"
                st.session_state[f"history_after_scan_{mode_key}"] = saved_scan["scan_id"]
                if mode_key == "aws":
                    st.session_state["history_region_filter_aws"] = selected_region
            except ScanHistoryError as error:
                st.session_state["scan_number"] += 1
                st.warning(
                    f"Scan completed, but persistent history could not be saved "
                    f"({type(error).__name__}). This scan may be lost after a restart."
                )
        else:
            st.session_state["scan_number"] += 1
            st.warning(
                "Scan completed, but persistent history is unavailable; "
                "this scan will not survive an application restart."
            )
        st.success("Security scan completed. Review any Unknown findings as unverified.")


# Show stored snapshots even in a fresh browser session with no active scan.
persistent_history = render_scan_history_section(
    history_store, operating_mode, selected_region
)


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
        "IAM results inspect returned identity policy documents and do not calculate "
        "effective permissions."
    )

# Findings are computed once and reused by every section below.
all_findings = combine_scan_findings(results)
findings_df = clean_findings_dataframe(pd.DataFrame(all_findings))

high_count = count_severity(all_findings, "High")
medium_count = count_severity(all_findings, "Medium")
low_count = count_severity(all_findings, "Low")
unknown_count = count_severity(all_findings, "Unknown")
scan_coverage = results.get("cloudtrail_account_coverage")
current_assessment_status = scan_assessment_status(
    all_findings, scan_coverage, mode=operating_mode
)

risk_score = calculate_risk_score(all_findings)
risk_classification = classify_risk(risk_score)


# ============================================================
# DASHBOARD METRICS
# ============================================================

st.divider()
st.header("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Services Audited", 3)
col2.metric("Total Findings", len(all_findings))
col3.metric("High Severity", high_count)
col4.metric("Medium Severity", medium_count)

st.divider()
st.header("Security Posture Summary")

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
        f"Assessment incomplete: {unknown_count} finding(s) are Unknown / unverified "
        "or coverage is incomplete. The risk score is not proof that the configuration is secure."
    )

# st.progress only accepts values between 0 and 1.
st.progress(min(max(float(risk_score), 0.0), 100.0) / 100)

st.caption(
    "Prototype score based on the average severity of detected findings. "
    "Higher scores indicate greater potential risk; this is not an "
    "official AWS security score."
)


# ============================================================
# SECURITY RISK TREND
# ============================================================

st.divider()
st.header("Security Risk Trend")

mode_history = list(reversed(persistent_history))

if len(mode_history) >= 2:
    trend_df = pd.DataFrame(mode_history)
    chart_df = trend_df.set_index("scan_number")[["risk_score"]]

    st.line_chart(chart_df)

    first_score = int(trend_df.iloc[0]["risk_score"])
    latest_score = int(trend_df.iloc[-1]["risk_score"])
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
    st.info("Complete at least two scans to see how the risk score changes.")


# ============================================================
# FILTER SECURITY FINDINGS
# ============================================================

st.divider()
st.header("Filter Security Findings")

if not findings_df.empty:
    col1, col2 = st.columns(2)

    with col1:
        if "severity" in findings_df.columns:
            severity_values = findings_df["severity"].dropna().astype(str).unique().tolist()
        else:
            severity_values = []
        selected_severity = st.selectbox(
            "Filter by Severity",
            ["All"] + sorted(severity_values),
            key="filter_severity",
        )

    with col2:
        if "service" in findings_df.columns:
            service_values = findings_df["service"].dropna().astype(str).unique().tolist()
        else:
            service_values = []
        selected_service = st.selectbox(
            "Filter by Service",
            ["All"] + sorted(service_values),
            key="filter_service",
        )

    filtered_df = findings_df.copy()

    if selected_severity != "All" and "severity" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["severity"].astype(str) == selected_severity]

    if selected_service != "All" and "service" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["service"].astype(str) == selected_service]

    st.caption(f"Showing {len(filtered_df)} of {len(findings_df)} findings.")

    # The original findings stay unchanged for filtering and reporting;
    # display_dataframe() only swaps missing values for a readable placeholder.
    display_dataframe(filtered_df, hide_index=True)
else:
    st.success("No security findings to display.")


# ============================================================
# INDIVIDUAL SERVICE FINDINGS
# ============================================================

st.divider()
st.header("S3 Security Findings")
st.write("Checks public access protection and default encryption.")

display_dataframe(
    make_findings_dataframe(combine_findings({"s3": results.get("s3", [])})),
    hide_index=True,
)

st.divider()
st.header("IAM Permission Findings")
st.write("Checks sample IAM policies for potentially broad permissions.")

display_dataframe(
    make_findings_dataframe(combine_findings({"iam": results.get("iam", [])})),
    hide_index=True,
)

st.divider()
st.header("CloudTrail Logging Findings")
st.write("Checks selected-region logging status and trail configuration.")

display_dataframe(
    make_findings_dataframe(combine_findings({"cloudtrail": results.get("cloudtrail", [])})),
    hide_index=True,
)

account_coverage = results.get("cloudtrail_account_coverage")
if operating_mode == "AWS (read-only)" and isinstance(account_coverage, dict):
    st.subheader("Account-wide CloudTrail configured coverage")
    coverage_status = account_coverage.get("coverage_status", "unknown")
    if coverage_status == "complete":
        st.info("Regional inventory and CloudTrail configuration checks completed for all enabled regions.")
    else:
        st.warning("Account-wide coverage is partial or unverified. Unknown regions are not treated as uncovered.")
    st.caption(
        "This assessment checks configured trail scope. It does not verify logging delivery status in every region; "
        "GetTrailStatus is checked only in the selected region. Multi-region and organization trail metadata "
        "is deduplicated by trail ARN. Regions that are not opted in are listed separately."
    )
    coverage_rows = []
    for region in account_coverage.get("enabled_regions", []):
        if region in account_coverage.get("unverified_region_names", []):
            state = "Unverified"
        elif region in account_coverage.get("covered_regions", []):
            state = "Configured coverage confirmed"
        elif region in account_coverage.get("uncovered_regions", []):
            state = "No trail returned"
        else:
            state = "Unverified"
        coverage_rows.append({"Region": region, "Assessment": state})
    for region in account_coverage.get("not_enabled_regions", []):
        coverage_rows.append({"Region": region, "Assessment": "Not opted in; not assessed"})
    if coverage_rows:
        st.dataframe(pd.DataFrame(coverage_rows), hide_index=True, use_container_width=True)
    if account_coverage.get("unverified_regions"):
        st.write("Unverified operations")
        st.dataframe(pd.DataFrame(account_coverage["unverified_regions"]), hide_index=True, use_container_width=True)
    if account_coverage.get("trails"):
        st.write("Distinct trails returned")
        st.dataframe(pd.DataFrame(account_coverage["trails"]), hide_index=True, use_container_width=True)


# ============================================================
# RECOMMENDED ACTIONS (PAGINATED)
# ============================================================

st.divider()
st.header("Recommended Actions")

if not all_findings:
    st.success("No findings were returned by the configured checks.")
else:
    available_severities = ["All"] + [
        sev for sev in ["High", "Medium", "Low", "Unknown", "Info"]
        if any(f.get("severity") == sev for f in all_findings)
    ]

    ctrl_filter, ctrl_size, ctrl_page = st.columns([2, 1, 1])

    with ctrl_filter:
        rec_sev = st.selectbox(
            "Filter recommendations by severity",
            options=available_severities,
            key="rec_severity_filter",
        )

    recs_to_show = [
        f for f in all_findings
        if rec_sev == "All" or f.get("severity") == rec_sev
    ]
    total_recs = len(recs_to_show)

    with ctrl_size:
        page_size = st.selectbox(
            "Cards per page",
            PAGE_SIZE_OPTIONS,
            index=0,
            key="rec_page_size",
        )

    total_pages = max(1, math.ceil(total_recs / page_size))

    # The page widget is keyed by filter + page size, so changing either resets it.
    # If a re-scan produced fewer pages than the stored page number, reset it too.
    page_key = f"rec_page_{rec_sev}_{page_size}"
    if st.session_state.get(page_key, 1) > total_pages:
        del st.session_state[page_key]

    with ctrl_page:
        current_page = int(
            st.number_input(
                "Page",
                min_value=1,
                max_value=total_pages,
                value=1,
                step=1,
                key=page_key,
            )
        )

    start_idx = (current_page - 1) * page_size
    end_idx = min(start_idx + page_size, total_recs)

    if total_recs == 0:
        st.info(f"No recommendations found with severity '{rec_sev}'.")
    else:
        st.caption(
            f"Showing {start_idx + 1}–{end_idx} of {total_recs} recommendation(s) "
            f"· Page {current_page} of {total_pages} "
            f"(total findings across all severities: {len(all_findings)})."
        )

        for index, finding in enumerate(recs_to_show[start_idx:end_idx], start=start_idx + 1):
            service = finding.get("service", "Cloud")
            severity = finding.get("severity", "Info")
            title = finding.get("finding", "Security finding")
            recommendation = finding.get(
                "recommendation",
                "Review the configuration and follow security best practices.",
            )

            with st.container(border=True):
                st.subheader(f"{index}. {title}")

                info_col1, info_col2 = st.columns(2)
                with info_col1:
                    st.write(f"**Service:** {service}")
                with info_col2:
                    st.write(f"**Severity:** {severity}")

                st.write(f"**Recommendation:** {recommendation}")

                steps = REMEDIATION_STEPS.get(service)
                if steps:
                    with st.expander("View Step-by-Step Remediation"):
                        st.markdown(
                            "\n".join(f"{n}. {step}" for n, step in enumerate(steps, start=1))
                        )


# ============================================================
# DOWNLOAD SECURITY REPORT
# ============================================================

st.divider()
st.header("Export Security Report")

# The export always uses the full findings list, never just the current page.
report_df = findings_df.copy()

if not report_df.empty:
    report_region = st.session_state.get("scan_region") or "Demo"
    report_notes = [f"Assessment status: {current_assessment_status}."]
    if operating_mode == "AWS (read-only)":
        report_notes.append(f"Selected AWS region: {report_region}.")
        if isinstance(account_coverage, dict):
            coverage_status = account_coverage.get("coverage_status", "unknown")
            report_notes.append(f"Account-wide CloudTrail coverage status: {coverage_status}.")
            for label, key in (
                ("Covered regions", "covered_regions"),
                ("Uncovered regions", "uncovered_regions"),
                ("Unverified regions", "unverified_region_names"),
                ("Regions not enabled", "not_enabled_regions"),
            ):
                regions = account_coverage.get(key) or []
                if regions:
                    names = [
                        str(item.get("region", item)) if isinstance(item, dict) else str(item)
                        for item in regions
                    ]
                    report_notes.append(f"{label}: {', '.join(names)}.")
        else:
            report_notes.append(
                "Account-wide CloudTrail coverage metadata is unavailable; coverage is unverified."
            )
    else:
        report_notes.append("Demo results use sample configurations; no AWS account was inspected.")

    pdf_data = generate_pdf_report(
        "CloudSentry Security Audit Report",
        report_df,
        subtitle=(
            f"Mode: {operating_mode} | Region: {report_region} | "
            f"Total Findings: {len(report_df)}"
        ),
        landscape_mode=True,
        notes=report_notes,
    )

    st.download_button(
        label="Download Audit Report (PDF)",
        data=pdf_data,
        file_name="cloudsentry_security_report.pdf",
        mime="application/pdf",
        key="download_audit_report",
        **stretch_kwargs(st.download_button),
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
            {"Metric": "Risk Classification", "Value": risk_classification},
        ]
    )

    summary_pdf = generate_pdf_report(
        "CloudSentry Security Summary",
        summary_report,
        subtitle=f"Mode: {operating_mode} | Scan #{st.session_state['scan_number']}",
        landscape_mode=False,
        notes=report_notes,
    )

    st.download_button(
        label="Download Security Summary (PDF)",
        data=summary_pdf,
        file_name="cloudsentry_security_summary.pdf",
        mime="application/pdf",
        key="download_security_summary",
        **stretch_kwargs(st.download_button),
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
