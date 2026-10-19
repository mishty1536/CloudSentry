# CloudSentry — Cloud Security Misconfiguration Auditor

CloudSentry is a Streamlit-based dashboard for assessing common cloud-security misconfigurations in Amazon Web Services (AWS). It provides security findings, recommendations, scan comparisons, and downloadable reports.

The project supports two modes:

- **Demo mode:** Uses sample configurations and local sample data. It does not create AWS clients or call AWS APIs.
- **AWS read-only mode:** Performs explicitly initiated checks against selected AWS security configurations when enabled in a suitable, controlled environment.

CloudSentry is an educational security-auditing prototype. Its findings are intended to assist security reviews and do not replace a comprehensive cloud security assessment.

## Live Demo

**Application URL:** http://3.26.214.34:8501

CloudSentry is deployed on an Amazon EC2 instance running Amazon Linux 2023. The current public deployment runs in Demo mode and uses sample configurations.

> **Security notice:** The demo is served over HTTP, and port 8501 is publicly accessible. Do not submit sensitive information to this deployment. AWS live scanning must remain disabled for this unauthenticated public demo.

The application is available while the EC2 instance and Streamlit process are running. Its public IP address may change if the instance is stopped and restarted.

## Features

- **S3 Security Auditing:** Checks selected bucket-level public-access-block and default encryption configurations.
- **IAM Security Auditing:** Reviews selected account-level IAM security indicators and identity-policy documents.
- **CloudTrail Auditing:** Checks selected trail logging and configuration indicators in a chosen AWS region.
- **Security Findings:** Displays findings with severity classifications and explanations.
- **Recommendations:** Provides suggestions to help address identified security issues.
- **Scan Comparison:** Compares scan results to help identify changes in security findings.
- **Risk Score:** Provides a prototype risk score based on the application's existing scoring formula.
- **Report Download:** Allows users to download a report of scan results.
- **Demo Mode:** Supports demonstrations without AWS credentials or live AWS API calls.
- **Read-only AWS Checks:** Uses Boto3 to retrieve selected configuration information without creating, updating, or deleting AWS resources.
- **Unknown / Unverified Results:** Represents checks that cannot be verified rather than automatically treating them as secure or vulnerable.

## Technology Stack

- **Language:** Python
- **Dashboard:** Streamlit
- **Data processing:** Pandas
- **AWS SDK:** Boto3
- **Cloud platform:** Amazon Web Services (AWS)
- **Compute and hosting:** Amazon EC2
- **Operating system:** Amazon Linux 2023
- **Version control:** Git and GitHub
- **Testing:** Python `unittest` with mocked AWS clients

## Architecture Overview

1. The user interacts with the Streamlit dashboard.
2. In Demo mode, the application evaluates sample configurations without making AWS API calls.
3. In AWS mode, when explicitly enabled and started, the relevant auditor modules use Boto3 to retrieve selected AWS configuration information.
4. The audit logic evaluates the available configuration data and generates findings.
5. The dashboard displays findings, recommendations, and the prototype risk score.
6. Users can compare scan results and download reports.

The application contains separate auditor modules for S3, IAM, and CloudTrail, alongside shared dashboard helpers and a dedicated test suite.

## Project Structure

```text
CloudSentry/
├── app.py
├── aws_auditor.py
├── s3_auditor.py
├── iam_auditor.py
├── cloudTrail_auditor.py
├── dashboard_helpers.py
├── theme.css
├── requirements.txt
├── checks/
└── README.md
```

The `checks/` directory contains the automated tests. The application loads `theme.css` from the project directory, so keep it alongside `app.py`.

## Run Locally

### Prerequisites

- Python 3.11
- Git
- Internet access to install Python dependencies

### Installation

Clone the repository:

```bash
git clone https://github.com/mishty1536/CloudSentry.git
cd CloudSentry
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS:**

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Install the pinned dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the dashboard:

```bash
python -m streamlit run app.py
```

Streamlit will display the local URL in the terminal, typically `http://localhost:8501`.

Demo mode is the default and works without AWS credentials.

## AWS EC2 Deployment

CloudSentry has been deployed to an Amazon EC2 instance using Amazon Linux 2023, Python 3.11, and Streamlit.

### Deployment Configuration

| Setting | Configuration |
|---|---|
| Cloud provider | AWS |
| Compute service | Amazon EC2 |
| Operating system | Amazon Linux 2023 |
| Python version | Python 3.11 |
| Application framework | Streamlit |
| Application port | TCP 8501 |
| Deployment mode | Public Demo mode |
| AWS scanning | Disabled for the public demo |

### Deployment Steps

Install the required system packages on the EC2 instance:

```bash
sudo dnf install git python3.11 python3.11-pip -y
```

Clone the repository:

```bash
git clone https://github.com/mishty1536/CloudSentry.git
cd CloudSentry
```

Create and activate the Python environment:

```bash
python3.11 -m venv .venv311
source .venv311/bin/activate
```

Install the dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start Streamlit:

```bash
python -m streamlit run app.py \
  --server.address 0.0.0.0 \
  --server.port 8501
```

Configure the EC2 security group's inbound rules to allow TCP traffic on port 8501 for public demo access. SSH access on port 22 should remain restricted to trusted IP addresses.

The Streamlit process must remain running for the application to be available. Automatic restart after an EC2 reboot has not been configured.

### Public Deployment Security

- Keep `CLOUDSENTRY_ENABLE_AWS_SCAN` unset on the public demo instance.
- Do not place AWS credentials, access keys, tokens, or secrets in the source code or public repository.
- Do not enable live AWS scanning on an unauthenticated public instance.
- The current demo uses HTTP rather than HTTPS.
- Public access to port 8501 allows anyone with network access to reach the application.
- Review AWS billing and resource usage regularly. EC2 compute, storage, and public IPv4 usage may incur charges or consume account credits.
- Stop the EC2 instance when the public demo is not required.

For a production deployment, introduce appropriate authentication, HTTPS, access restrictions, logging, and operational monitoring before enabling sensitive functionality.

## Enable AWS Read-only Scanning

AWS mode is intended for a controlled, non-public environment only.

To enable AWS mode, set the environment variable:

**Linux / macOS:**

```bash
export CLOUDSENTRY_ENABLE_AWS_SCAN=true
```

**Windows PowerShell:**

```powershell
$env:CLOUDSENTRY_ENABLE_AWS_SCAN = "true"
```

Then start the application. AWS mode should only be enabled in an environment with appropriate access controls. AWS API calls begin only after the user explicitly presses **Start AWS scan**.

Unexpected Python exceptions during an AWS scan are written to the application service log with the scan phase, selected region, exception type, and traceback frames. Exception messages and local variable values are omitted to avoid logging credentials or request data. On the EC2 systemd deployment, inspect recent diagnostics with:

```bash
sudo journalctl -u cloudsentry.service -n 100 --no-pager
```

CloudSentry uses Boto3's standard credential provider chain through `boto3.Session`. Use an approved credential provider, such as IAM Identity Center/SSO or an attached IAM role.

Never paste access keys into CloudSentry, source files, Streamlit secrets, or this README. Do not commit credentials to GitHub.

The application does not print or save AWS credentials.

## Read-only IAM Permissions

Attach a least-privilege policy like the following to the identity used by Boto3. Review and tailor the permissions to your environment before use.

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
      "Sid": "ListAvailableRegionsForCloudTrailCoverage",
      "Effect": "Allow",
      "Action": "ec2:DescribeRegions",
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

The policy grants read-only access to the listed configuration APIs. It does not grant permission to create, update, or delete AWS resources.

If a required read permission is missing, throttled, or unavailable, the affected check is reported as **Unknown / unverified**.

## AWS Check Coverage and Limitations

### S3 Auditing

- Lists general-purpose buckets with `ListBuckets`.
- Checks each returned bucket's bucket-level `GetPublicAccessBlock` configuration.
- Checks the bucket's default `GetBucketEncryption` configuration.
- Does not establish effective public access. Account-level and organization-level S3 Block Public Access controls are not queried.
- Does not inspect bucket policies, ACLs, existing objects, or KMS key policies.
- If an explicit encryption configuration is absent, the configuration is reported as unverified. The application does not claim that objects are unencrypted.
- Existing object encryption is not inspected.

### IAM Auditing

- Uses `GetAccountSummary` to check the root account MFA indicator.
- Uses paginated `GetAccountAuthorizationDetails` results to retrieve IAM users, groups, roles, inline identity policies, policy attachments, and managed policy documents.
- Audits inline identity policy documents and the default version documents for attached managed policies returned by AWS.
- Treats missing or malformed policy documents as unverified.
- Does not treat role trust policies as identity permission policies.
- Does not evaluate permissions boundaries, session policies, SCPs/RCPs, resource-based policies, service control context, policy variables, or all condition semantics.
- Does not calculate effective permissions or replace IAM Access Analyzer or AWS policy evaluation.
- Treats wildcard, `NotAction`, `NotResource`, and `Condition` findings as heuristic indicators. `NotAction`, `NotResource`, and `Condition` are surfaced for contextual review rather than automatically labeled vulnerabilities.

### CloudTrail Auditing

- Uses `DescribeTrails` in the selected region, including shadow trails.
- Uses `GetTrailStatus` to check whether each returned trail is currently logging.
- Checks trail multi-region configuration and log file validation.
- Separately enumerates AWS regions with `ec2:DescribeRegions` and checks enabled regions with `cloudtrail:DescribeTrails`, including shadow trails.
- Deduplicates trails by ARN and reports multi-region, home-region, and organization-trail metadata. Regional trails cover only their home region; a multi-region trail is treated as configured coverage for enabled regions.
- Access denied, authentication errors, unsupported regions, throttling, and malformed responses are reported as unverified. Unverified regions are never treated as confirmed gaps.
- The account-wide result assesses configured trail coverage only. `GetTrailStatus` still runs only in the selected region, so delivery/logging status is not verified account-wide.
- Regions marked `not-opted-in` are shown separately and are not scanned. If any enabled region cannot be checked, the account-wide result is partial and does not claim complete coverage or account-wide absence.
- The organization-trail flag is reported as returned metadata; the app does not independently verify organization membership or effective organization-wide coverage.
- Does not evaluate event selectors, destination bucket policies, KMS key policies, or delivery-error fields.

### Region and Risk Score

The selected AWS region is shown with AWS results. S3 bucket listing and IAM are account-level APIs. CloudTrail selected-region findings remain separate from the account-wide configured-coverage assessment. The latter requires `ec2:DescribeRegions` in addition to the CloudTrail read permissions above.

The dashboard's prototype risk score retains its existing formula. Unknown severities contribute zero points and remain in the denominator, so unverified results can lower the score. Review Unknown findings separately; a lower score does not necessarily mean that the environment is secure.

## Testing

Run the complete test suite from the project root in the Windows virtual environment:

```powershell
.venv\Scripts\python.exe -B -m unittest discover -s checks -v
```

The AWS integration tests use mocked clients, synthetic responses, and Botocore `Stubber` clients with dummy test credentials. They do not read AWS credentials or call AWS APIs.

Run tests after changing the audit logic, findings, or report-generation functionality.

## Limitations

CloudSentry is an educational prototype for selected AWS security configuration checks. It does not perform a complete cloud security assessment, penetration test, or formal compliance audit.

Findings are based on the configuration information available to the application and the implemented heuristic rules. A missing finding does not guarantee that an AWS resource is secure.

The tool should be used as an aid to security review, with results verified against AWS configuration and organizational security requirements.

## Future Improvements

Potential future enhancements include:

- Authentication and role-based access control.
- HTTPS and a custom domain for public deployments.
- Persistent scan history and report storage.
- Multi-region CloudTrail assessment.
- Broader S3 effective-public-access analysis.
- Expanded IAM policy evaluation and contextual findings.
- Improved automated deployment and monitoring.

These are possible enhancements and are not represented as completed features.

## Repository

GitHub: https://github.com/mishty1536/CloudSentry

## Author

Developed as a Cloud Computing & Security mini-project to explore AWS security misconfigurations, read-only auditing, and cloud application deployment.
