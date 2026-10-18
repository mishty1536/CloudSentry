# CloudSentry

CloudSentry is a Streamlit dashboard for sample cloud-security assessments and optional, explicitly started AWS read-only checks. Demo mode uses local sample data and does not create AWS clients or call AWS APIs.

## Run locally

Use Python 3.11. Install the pinned dependencies in your environment with `python -m pip install -r requirements.txt`, then run `python -m streamlit run app.py`.

Demo is the default and works without AWS credentials. For a non-public local environment only, AWS mode can be enabled by setting `CLOUDSENTRY_ENABLE_AWS_SCAN=true`; AWS calls still begin only after you press **Start AWS scan**. AWS mode uses Boto3's standard credential provider chain through `boto3.Session`. Use an approved provider such as IAM Identity Center/SSO or an attached role. Do not paste access keys into CloudSentry, source files, Streamlit secrets, or this README. CloudSentry does not print or save credentials.

## Public Streamlit Community Cloud Demo deployment

The public portfolio configuration is Demo-only. Leave `CLOUDSENTRY_ENABLE_AWS_SCAN` unset and do not add AWS credentials or secrets to the Community Cloud app. Without that explicit opt-in, the AWS mode selector is hidden and the app blocks AWS scan execution.

1. Push the reviewed project to a GitHub repository when you are ready to publish it. The repository must include `app.py`, `theme.css`, all auditor/helper modules, and `requirements.txt`.
2. Sign in to Streamlit Community Cloud with GitHub and create a new app from that repository and the intended branch.
3. Set the app's main file path to the root-level `app.py` and select Python 3.11.
4. Deploy the app and use its public URL for the portfolio. A public app can be visited by anyone; publish only code and sample data intended for public viewing.

`app.py` loads `theme.css` from its own directory, so keep `theme.css` beside it in the repository root. No Dockerfile or custom port configuration is needed for Community Cloud. Scan history and comparisons are held in Streamlit session state and are not persistent across sessions or app restarts. Community Cloud availability and resource limits can change; check the platform's current terms before publishing.

## Read-only IAM permissions

Attach a least-privilege policy like the following to the identity used by Boto3. The bucket-level S3 operations are scoped to bucket ARNs. Inventory and account-wide IAM operations require `Resource: "*"`; `DescribeTrails` also requires `Resource: "*"`, while trail status can be scoped to trail ARNs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListGeneralPurposeBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "ReadBucketSecurityConfiguration",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "ReadIamAccountAndPolicyDetails",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountAuthorizationDetails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DescribeRegionalCloudTrailTrails",
      "Effect": "Allow",
      "Action": "cloudtrail:DescribeTrails",
      "Resource": "*"
    },
    {
      "Sid": "ReadCloudTrailStatus",
      "Effect": "Allow",
      "Action": "cloudtrail:GetTrailStatus",
      "Resource": "arn:aws:cloudtrail:*:*:trail/*"
    }
  ]
}
```

CloudSentry does not request write permissions. It does not create, update, or delete AWS resources. If a required read permission is missing, throttled, or unavailable, the affected check is reported as **Unknown / unverified**.

## AWS check coverage and limits

### S3

- Lists general-purpose buckets with `ListBuckets` and checks each returned bucket's bucket-level `GetPublicAccessBlock` and default `GetBucketEncryption` configuration.
- These checks do not establish effective public access. Account-level and organization-level S3 Block Public Access controls are not queried. Bucket policies, ACLs, existing objects, and KMS key policies are not inspected.
- If an explicit encryption configuration is absent, CloudSentry reports the configuration as unverified; it does not claim that objects are unencrypted. Existing object encryption is not inspected.

### IAM

- `GetAccountSummary` checks the root account MFA indicator.
- `GetAccountAuthorizationDetails` is paginated and supplies IAM users, groups, roles, inline identity policies, policy attachments, and managed policy documents. CloudSentry audits inline identity policy documents and the default version documents for attached managed policies returned by AWS. A missing or malformed document is unverified.
- Role trust policies are not treated as identity permission policies. The checks do not evaluate permissions boundaries, session policies, SCPs/RCPs, resource-based policies, service control context, policy variables, or all condition semantics. They do not calculate effective permissions or replace IAM Access Analyzer or AWS policy evaluation.
- Wildcard, `NotAction`, `NotResource`, and `Condition` findings are heuristic. `NotAction`, `NotResource`, and `Condition` are surfaced for contextual review rather than automatically labeled vulnerabilities.

### CloudTrail

- In the selected region, `DescribeTrails` includes shadow trails; `GetTrailStatus` checks whether each returned trail is currently logging. Trail multi-region configuration and log file validation are also checked.
- CloudTrail status is regional. One scan does not verify logging status in every region. No trail returned in the selected region is reported as unverified for broader coverage.
- Event selectors, destination bucket policies, KMS key policies, organization-wide coverage, and delivery-error fields are not evaluated by these checks.

The selected region is shown with AWS results. S3 bucket listing and IAM are account-level APIs, while CloudTrail checks apply to the selected region. The dashboard's prototype risk score keeps its existing formula; Unknown severities contribute zero points and remain in the denominator, so unverified results can lower the score. Review Unknown findings separately.

## Offline tests

Run the complete test suite from the project root in the Windows virtual environment, without AWS credentials or network access:

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s checks -v
```

AWS integration tests use mocked clients and synthetic responses. They do not read credentials or call AWS.
