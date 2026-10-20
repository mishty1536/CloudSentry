"""Transactional SQLite storage and comparison helpers for CloudSentry scans."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import uuid

from dashboard_helpers import normalize_findings


SEVERITIES = ("High", "Medium", "Low", "Info", "Unknown")
AWS_MODE = "AWS"
DEMO_MODE = "Demo"


class ScanHistoryError(RuntimeError):
    """Raised when persistent scan history cannot be read or written."""


def default_database_path():
    """Return a per-user persistent path, overridable for deployment and tests."""
    configured = os.environ.get("CLOUDSENTRY_HISTORY_DB", "").strip()
    if configured:
        return Path(configured).expanduser()

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cloudsentry" / "scan_history.db"


def _canonical_mode(mode):
    if mode == "AWS (read-only)":
        return AWS_MODE
    if mode in {AWS_MODE, DEMO_MODE}:
        return mode
    raise ValueError("mode must be Demo or AWS (read-only)")


def _json_default(value):
    try:
        return repr(value)
    except Exception:  # pragma: no cover - defensive for hostile custom objects
        return f"<{type(value).__name__}>"


def _finding_counts(findings):
    counts = Counter()
    for finding in findings:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        counts[severity if severity in SEVERITIES else "Unknown"] += 1
    return {severity: int(counts.get(severity, 0)) for severity in SEVERITIES}


def scan_assessment_status(findings, coverage=None, *, mode=None):
    """Keep incomplete API coverage explicit in the persisted scan status."""
    if any(
        not isinstance(finding, dict) or finding.get("severity") not in SEVERITIES[:-1]
        for finding in findings
    ):
        return "Incomplete"
    if mode in {AWS_MODE, "AWS (read-only)"} and not isinstance(coverage, dict):
        return "Incomplete"
    if isinstance(coverage, dict):
        if mode in {AWS_MODE, "AWS (read-only)"} and coverage.get("coverage_status") != "complete":
            return "Incomplete"
        if coverage.get("coverage_status") not in {None, "complete"}:
            return "Incomplete"
        if coverage.get("unverified_regions") or coverage.get("inventory_complete") is False:
            return "Incomplete"
    return "Complete"


def service_assessment_statuses(findings, coverage=None, *, mode=None, checked_services=()):
    """Report service check execution independently from overall coverage."""
    normalized = normalize_findings(findings)
    checked = {str(service).casefold() for service in checked_services}
    result = {}
    for service in ("S3", "IAM", "CloudTrail"):
        service_findings = [
            item for item in normalized
            if str(item.get("service", "")).casefold() == service.casefold()
        ]
        if not service_findings and service.casefold() not in checked:
            result[service] = "Unverified"
        elif any(item.get("severity") == "Unknown" for item in service_findings):
            result[service] = "Partial / Unverified"
        else:
            result[service] = "Verified"

    if mode in {AWS_MODE, "AWS (read-only)"} and (
        not isinstance(coverage, dict)
        or coverage.get("coverage_status") != "complete"
        or coverage.get("unverified_regions")
        or coverage.get("inventory_complete") is False
    ):
        result["CloudTrail"] = "Partial / Unverified"
    return result


def cloudtrail_describe_access_denied(coverage):
    """Return whether account-wide trail inventory contains a DescribeTrails denial."""
    if not isinstance(coverage, dict):
        return False
    entries = coverage.get("unverified_regions")
    if not isinstance(entries, list):
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("operation") == "DescribeTrails"
        and str(entry.get("error_code", "")).lower()
        in {"accessdenied", "accessdeniedexception", "403"}
        for entry in entries
    )


class ScanHistoryStore:
    """SQLite-backed scan history; each operation uses its own connection."""

    def __init__(self, path=None):
        self.path = Path(path).expanduser() if path is not None else default_database_path()
        self.initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def initialize(self):
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = self._connect()
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                with connection:
                    connection.execute(
                        """CREATE TABLE IF NOT EXISTS scans (
                            scan_number INTEGER PRIMARY KEY AUTOINCREMENT,
                            scan_id TEXT NOT NULL UNIQUE,
                            scanned_at TEXT NOT NULL,
                            mode TEXT NOT NULL CHECK (mode IN ('Demo', 'AWS')),
                            region TEXT,
                            total_findings INTEGER NOT NULL,
                            severity_counts_json TEXT NOT NULL,
                            risk_score INTEGER NOT NULL,
                            assessment_status TEXT NOT NULL CHECK (
                                assessment_status IN ('Complete', 'Incomplete')
                            ),
                            findings_json TEXT NOT NULL,
                            coverage_json TEXT NOT NULL
                        )"""
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS scans_mode_region_time "
                        "ON scans(mode, region, scanned_at DESC, scan_number DESC)"
                    )
            finally:
                connection.close()
            if os.name != "nt":
                self.path.chmod(0o600)
        except (OSError, sqlite3.Error) as error:
            raise ScanHistoryError("Could not initialize persistent scan history") from error

    @staticmethod
    def _summary_from_row(row):
        try:
            counts = json.loads(row["severity_counts_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise ScanHistoryError("Stored scan history contains malformed severity counts") from error
        if not isinstance(counts, dict):
            raise ScanHistoryError("Stored scan history contains malformed severity counts")
        try:
            findings = json.loads(row["findings_json"])
            coverage = json.loads(row["coverage_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise ScanHistoryError("Stored scan history contains malformed assessment data") from error
        if not isinstance(findings, list) or not isinstance(coverage, dict):
            raise ScanHistoryError("Stored scan history contains malformed assessment data")
        return {
            "scan_number": row["scan_number"],
            "scan_id": row["scan_id"],
            "scanned_at": row["scanned_at"],
            "mode": row["mode"],
            "region": row["region"],
            "total_findings": row["total_findings"],
            "severity_counts": counts,
            "risk_score": row["risk_score"],
            "assessment_status": row["assessment_status"],
            "service_statuses": service_assessment_statuses(
                findings, coverage, mode=row["mode"]
            ),
            "cloudtrail_describe_denied": cloudtrail_describe_access_denied(coverage),
        }

    def save_scan(
        self,
        *,
        mode,
        region,
        findings,
        risk_score,
        assessment_status=None,
        coverage=None,
        scanned_at=None,
    ):
        """Insert a completed scan atomically; incomplete scans retain that status."""
        mode = _canonical_mode(mode)
        if mode == AWS_MODE and (not isinstance(region, str) or not region.strip()):
            raise ValueError("AWS scans require a region")
        if mode == DEMO_MODE:
            region = None
        if not isinstance(findings, list):
            raise ValueError("findings must be a list")
        findings = normalize_findings(findings)

        counts = _finding_counts(findings)
        derived_status = scan_assessment_status(findings, coverage, mode=mode)
        if assessment_status not in {None, "Complete", "Incomplete"}:
            raise ValueError("assessment_status must be Complete or Incomplete")
        status = (
            "Incomplete"
            if derived_status == "Incomplete" or assessment_status == "Incomplete"
            else "Complete"
        )
        timestamp = scanned_at or datetime.now(timezone.utc).isoformat(timespec="microseconds")
        scan_id = uuid.uuid4().hex
        try:
            findings_json = json.dumps(findings, ensure_ascii=False, default=_json_default)
            coverage_json = json.dumps(coverage or {}, ensure_ascii=False, default=_json_default)
            connection = self._connect()
            try:
                with connection:
                    cursor = connection.execute(
                        """INSERT INTO scans (
                            scan_id, scanned_at, mode, region, total_findings,
                            severity_counts_json, risk_score, assessment_status,
                            findings_json, coverage_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id, timestamp, mode, region, len(findings),
                            json.dumps(counts, sort_keys=True), int(risk_score), status,
                            findings_json, coverage_json,
                        ),
                    )
                    scan_number = cursor.lastrowid
            finally:
                connection.close()
            return {
                "scan_number": scan_number,
                "scan_id": scan_id,
                "scanned_at": timestamp,
                "mode": mode,
                "region": region,
                "total_findings": len(findings),
                "severity_counts": counts,
                "risk_score": int(risk_score),
                "assessment_status": status,
                "findings": findings,
                "coverage": coverage or {},
            }
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            raise ScanHistoryError("Could not save the completed scan to persistent history") from error

    def list_scans(self, *, mode=None, region=None):
        """Return scan summaries newest first, with optional mode/region filtering."""
        clauses = []
        parameters = []
        if mode is not None:
            clauses.append("mode = ?")
            parameters.append(_canonical_mode(mode))
        if region is not None:
            clauses.append("region = ?")
            parameters.append(region)
        query = "SELECT * FROM scans"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY scanned_at DESC, scan_number DESC"
        try:
            connection = self._connect()
            try:
                rows = connection.execute(query, parameters).fetchall()
            finally:
                connection.close()
            return [self._summary_from_row(row) for row in rows]
        except (OSError, sqlite3.Error) as error:
            raise ScanHistoryError("Could not read persistent scan history") from error

    def get_scan(self, scan_id):
        """Return a full saved snapshot by its opaque scan ID."""
        try:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                return None
            record = self._summary_from_row(row)
            record["findings"] = json.loads(row["findings_json"])
            record["coverage"] = json.loads(row["coverage_json"])
            if not isinstance(record["findings"], list) or not isinstance(record["coverage"], dict):
                raise ScanHistoryError("Stored scan history contains malformed data")
            return record
        except (OSError, sqlite3.Error, TypeError, json.JSONDecodeError) as error:
            raise ScanHistoryError("Could not read the saved scan") from error


def finding_identity(finding):
    """Build a stable identity independent of finding order, severity, and advice."""
    if not isinstance(finding, dict):
        finding = {"finding": repr(finding)}

    def value(*keys):
        for key in keys:
            candidate = finding.get(key)
            if candidate is not None and str(candidate).strip():
                return str(candidate).strip()
        return ""

    return (
        value("service").casefold(),
        value("finding_type", "check_id", "finding_code", "operation").casefold(),
        value("finding", "finding_title", "title").casefold(),
        value("resource", "resource_id", "resource_arn", "bucket_name", "policy_arn"),
        value("policy_name").casefold(),
    )


def _difference(records, other_counts):
    difference = []
    remaining = Counter(other_counts)
    for finding in records:
        identity = finding_identity(finding)
        if remaining[identity]:
            remaining[identity] -= 1
        else:
            difference.append(finding)
    return difference


def _stable_value(value):
    """Canonicalize nested coverage data so API list ordering is immaterial."""
    if isinstance(value, dict):
        return tuple(sorted((str(key), _stable_value(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple, set)):
        return tuple(sorted((_stable_value(item) for item in value), key=repr))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def compare_scans(before, after):
    """Compare any compatible snapshots without treating incomplete absences as resolved."""
    before_mode = _canonical_mode(before.get("mode"))
    after_mode = _canonical_mode(after.get("mode"))
    if before_mode != after_mode:
        raise ValueError("Demo and AWS scans cannot be compared")
    if before_mode == AWS_MODE:
        before_region = before.get("region")
        after_region = after.get("region")
        if not isinstance(before_region, str) or not before_region.strip():
            raise ValueError("AWS scans require a known region to compare")
        if before_region != after_region:
            raise ValueError("AWS scans from different regions cannot be compared")

    before_findings = before.get("findings") or []
    after_findings = after.get("findings") or []
    before_known = [
        finding for finding in before_findings
        if isinstance(finding, dict) and finding.get("severity") in SEVERITIES[:-1]
    ]
    after_known = [
        finding for finding in after_findings
        if isinstance(finding, dict) and finding.get("severity") in SEVERITIES[:-1]
    ]
    before_unknown = [
        finding for finding in before_findings
        if not isinstance(finding, dict) or finding.get("severity") not in SEVERITIES[:-1]
    ]
    after_unknown = [
        finding for finding in after_findings
        if not isinstance(finding, dict) or finding.get("severity") not in SEVERITIES[:-1]
    ]
    before_keys = Counter(finding_identity(item) for item in before_known)
    after_keys = Counter(finding_identity(item) for item in after_known)
    unmatched_before = _difference(before_known, after_keys)
    unmatched_after = _difference(after_known, before_keys)
    before_complete = before.get("assessment_status") == "Complete"
    after_complete = after.get("assessment_status") == "Complete"

    resolved = unmatched_before if after_complete else []
    newly_detected = unmatched_after if before_complete else []
    unverified_before = list(before_unknown)
    unverified_after = list(after_unknown)
    if not after_complete:
        unverified_before.extend(unmatched_before)
    if not before_complete:
        unverified_after.extend(unmatched_after)

    remaining_counts = before_keys & after_keys
    remaining = []
    for finding in after_known:
        identity = finding_identity(finding)
        if remaining_counts[identity]:
            remaining.append(finding)
            remaining_counts[identity] -= 1

    before_counts = before.get("severity_counts") or _finding_counts(before_findings)
    after_counts = after.get("severity_counts") or _finding_counts(after_findings)
    severity = {
        key: {
            "before": int(before_counts.get(key, 0)),
            "after": int(after_counts.get(key, 0)),
            "delta": int(after_counts.get(key, 0)) - int(before_counts.get(key, 0)),
        }
        for key in ("High", "Medium", "Low", "Info")
    }
    identical = (
        Counter(finding_identity(item) for item in before_findings)
        == Counter(finding_identity(item) for item in after_findings)
        and before_counts == after_counts
        and before.get("risk_score") == after.get("risk_score")
        and before.get("assessment_status") == after.get("assessment_status")
        and _stable_value(before.get("coverage", {})) == _stable_value(after.get("coverage", {}))
    )

    return {
        "before_total": int(before.get("total_findings", len(before_findings))),
        "after_total": int(after.get("total_findings", len(after_findings))),
        "before_risk_score": before.get("risk_score", 0),
        "after_risk_score": after.get("risk_score", 0),
        "risk_score_delta": int(after.get("risk_score", 0)) - int(before.get("risk_score", 0)),
        "severity": severity,
        "resolved": resolved,
        "remaining": remaining,
        "newly_detected": newly_detected,
        "unverified_before": unverified_before,
        "unverified_after": unverified_after,
        "identical": identical,
        "before_complete": before_complete,
        "after_complete": after_complete,
    }
