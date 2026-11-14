# ISO 27001 Evidence Report

> Example generated from fake data (moto and botocore Stubber), not a real account.

- **Framework:** ISO/IEC 27001:2022
- **Generated:** 2026-11-14 17:31 UTC
- **Scope:** aws:123456789012
- **Checks run:** 8 (PASS 3, FAIL 4, ERROR 0, N/A 1)

> Automated evidence supports, but does not replace, documented policies,
> procedures and records. See the notes under each control.

## Summary by control

| Control | Title | Status | Checks |
|---|---|---|---|
| A.5.15 | Access control | not automated yet | 0 |
| A.5.17 | Authentication information | **FAIL** | 2 |
| A.8.2 | Privileged access rights | **FAIL** | 1 |
| A.8.3 | Information access restriction | **FAIL** | 1 |
| A.8.5 | Secure authentication | **FAIL** | 2 |
| A.8.8 | Management of technical vulnerabilities | **FAIL** | 1 |
| A.8.9 | Configuration management | **FAIL** | 1 |
| A.8.13 | Information backup | not checked in this run | 0 |
| A.8.15 | Logging | **PASS** | 1 |
| A.8.16 | Monitoring activities | **FAIL** | 1 |
| A.8.20 | Networks security | not checked in this run | 0 |
| A.8.24 | Use of cryptography | **FAIL** | 2 |
| A.8.25 | Secure development life cycle | not automated yet | 0 |
| A.8.32 | Change management | not automated yet | 0 |

## Evidence detail

### A.5.17 Authentication information

- **PASS** `aws.iam.password_policy`: Password policy: min length 14, reuse prevention 24  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_
- **FAIL** `aws.iam.root_mfa`: Root account MFA is NOT enabled  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

**Also provide:** Password / authentication policy; process for issuing credentials.

### A.8.2 Privileged access rights

- **FAIL** `aws.iam.root_mfa`: Root account MFA is NOT enabled  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

**Also provide:** List of privileged roles and approval records.

### A.8.3 Information access restriction

- **FAIL** `aws.s3.bucket_protection`: 0 of 1 buckets encrypted with public access fully blocked  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

### A.8.5 Secure authentication

- **FAIL** `aws.iam.root_mfa`: Root account MFA is NOT enabled  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_
- **N/A** `aws.iam.console_users_mfa`: No IAM users with console access  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

### A.8.8 Management of technical vulnerabilities

- **FAIL** `aws.securityhub.findings_summary`: Security Hub is not enabled in eu-central-1  
  _collected 2026-11-14T17:31:09+00:00, scope aws:123456789012_

**Also provide:** Vulnerability management procedure and remediation tickets.

### A.8.9 Configuration management

- **FAIL** `aws.config.recorder_and_compliance`: AWS Config is not recording in eu-central-1  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

**Also provide:** Approved baseline configurations (e.g. CIS benchmark choice).

### A.8.15 Logging

- **PASS** `aws.cloudtrail.multi_region_logging`: 1 active multi-region CloudTrail trail(s)  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

**Also provide:** Logging policy, retention period, log review records.

### A.8.16 Monitoring activities

- **FAIL** `aws.securityhub.findings_summary`: Security Hub is not enabled in eu-central-1  
  _collected 2026-11-14T17:31:09+00:00, scope aws:123456789012_

### A.8.24 Use of cryptography

- **FAIL** `aws.s3.bucket_protection`: 0 of 1 buckets encrypted with public access fully blocked  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_
- **PASS** `aws.ec2.ebs_default_encryption`: EBS encryption by default is enabled in eu-central-1  
  _collected 2026-11-14T17:31:08+00:00, scope aws:123456789012_

**Also provide:** Cryptography policy and key management procedure.
