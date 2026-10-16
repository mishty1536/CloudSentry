
import json


def audit_iam_policy(policy_document):
    """
    Analyze an IAM policy document and flag potentially risky permissions.
    This version works with sample policy data and does not connect to AWS.
    """
    findings = []

    statements = policy_document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        wildcard_action = "*" in actions or any(
            action.endswith(":*") for action in actions
        )
        wildcard_resource = "*" in resources

        if wildcard_action and wildcard_resource:
            findings.append({
                "service": "IAM",
                "severity": "High",
                "finding": "Broad permissions across all resources",
                "recommendation": (
                    "Replace wildcard actions and resources with only "
                    "the specific permissions and resources required."
                )
            })

        elif wildcard_action or wildcard_resource:
            findings.append({
                "service": "IAM",
                "severity": "Medium",
                "finding": "Wildcard action or resource detected",
                "recommendation": (
                    "Review whether the wildcard is necessary and restrict "
                    "permissions or resources where possible."
                )
            })

    if not findings:
        findings.append({
            "service": "IAM",
            "severity": "Info",
            "finding": "No broad wildcard permissions detected",
            "recommendation": (
                "Continue reviewing the policy using least-privilege "
                "principles."
            )
        })

    return findings


if __name__ == "__main__":
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

    results = audit_iam_policy(sample_policy)

    print("CloudSentry IAM Audit Results")

    for finding in results:
        print(f"\nSeverity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")
        print(f"Recommendation: {finding['recommendation']}")
