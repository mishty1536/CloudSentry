"""Heuristic checks for a subset of IAM policy structures.

This offline demo auditor detects direct wildcard Action and Resource values.
It does not calculate effective IAM permissions, resolve policy variables,
evaluate Condition operators, or determine the scope of NotAction/NotResource.
Those constructs are surfaced for contextual review and are not treated as
vulnerabilities by themselves.
"""


def _finding(severity, title, recommendation):
    return {
        "service": "IAM",
        "severity": severity,
        "finding": title,
        "recommendation": recommendation,
    }


def _is_string_list(value):
    if isinstance(value, str):
        return bool(value.strip())
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def _contains_wildcard(value):
    values = [value] if isinstance(value, str) else value
    return any("*" in item or "?" in item for item in values)


def audit_iam_policy(policy_document):
    """Return heuristic findings for an IAM policy document.

    Invalid or incomplete input is reported as unverified rather than as a
    clean policy. NotAction, NotResource, and Condition are only noted for
    manual review; this function does not infer that they are unsafe.
    """
    if not isinstance(policy_document, dict):
        return [_finding(
            "Medium",
            "IAM policy input is missing or malformed",
            "Provide a policy object with a valid Statement before relying on this audit.",
        )]

    statements = policy_document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list) or not statements:
        return [_finding(
            "Medium",
            "IAM policy Statement is missing or malformed",
            "Provide one or more valid policy statements; this policy could not be assessed.",
        )]

    findings = []
    needs_contextual_review = False

    for statement in statements:
        if not isinstance(statement, dict):
            findings.append(_finding(
                "Medium",
                "IAM policy contains a malformed statement",
                "Review the statement structure; this part of the policy could not be assessed.",
            ))
            continue

        effect = statement.get("Effect")
        if effect not in ("Allow", "Deny"):
            findings.append(_finding(
                "Medium",
                "IAM statement has a missing or invalid Effect",
                "Use a valid Allow or Deny effect and review the statement manually.",
            ))
            continue
        if effect == "Deny":
            continue

        has_action = "Action" in statement
        has_not_action = "NotAction" in statement
        has_resource = "Resource" in statement
        has_not_resource = "NotResource" in statement

        if has_not_action or has_not_resource or "Condition" in statement:
            needs_contextual_review = True

        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            findings.append(_finding(
                "Medium",
                "IAM statement has a malformed Condition",
                "Review this condition structure; its effect could not be assessed.",
            ))
            continue

        if has_action == has_not_action:
            findings.append(_finding(
                "Medium",
                "IAM Allow statement must specify Action or NotAction, but not both",
                "Review this statement's permission scope; it could not be assessed reliably.",
            ))
            continue
        if has_resource == has_not_resource:
            findings.append(_finding(
                "Medium",
                "IAM Allow statement must specify Resource or NotResource, but not both",
                "Review this statement's resource scope; it could not be assessed reliably.",
            ))
            continue

        if has_not_action and not _is_string_list(statement["NotAction"]):
            findings.append(_finding(
                "Medium",
                "IAM statement has malformed NotAction values",
                "Use a non-empty string or list of strings and review the effective action scope manually.",
            ))
            continue
        if has_not_resource and not _is_string_list(statement["NotResource"]):
            findings.append(_finding(
                "Medium",
                "IAM statement has malformed NotResource values",
                "Use a non-empty string or list of strings and review the effective resource scope manually.",
            ))
            continue

        # The complement semantics of NotAction and NotResource require full
        # IAM evaluation. Do not label those constructs risky by themselves.
        if has_not_action or has_not_resource:
            continue

        actions = statement.get("Action")
        resources = statement.get("Resource")
        if not _is_string_list(actions) or not _is_string_list(resources):
            findings.append(_finding(
                "Medium",
                "IAM statement has malformed Action or Resource values",
                "Use a non-empty string or list of strings and review the policy manually.",
            ))
            continue

        wildcard_action = _contains_wildcard(actions)
        wildcard_resource = _contains_wildcard(resources)

        if wildcard_action and wildcard_resource:
            findings.append(_finding(
                "High",
                "Broad permissions across wildcard actions and resources",
                "Replace wildcard actions and resources with only the specific permissions and resources required.",
            ))
        elif wildcard_action or wildcard_resource:
            findings.append(_finding(
                "Medium",
                "Wildcard action or resource detected",
                "Review whether the wildcard is necessary and restrict permissions or resources where possible.",
            ))

    if needs_contextual_review:
        findings.append(_finding(
            "Info",
            "IAM policy uses constructs requiring contextual review",
            "NotAction, NotResource, and Condition semantics are not evaluated by this heuristic; review their effective scope in context.",
        ))

    if not findings:
        findings.append(_finding(
            "Info",
            "No direct wildcard Action or Resource detected",
            "This limited check does not evaluate effective permissions or all IAM policy features.",
        ))

    return findings


if __name__ == "__main__":
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    results = audit_iam_policy(sample_policy)
    print("CloudSentry IAM Audit Results")
    for finding in results:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")
        print(f"Recommendation: {finding['recommendation']}")
