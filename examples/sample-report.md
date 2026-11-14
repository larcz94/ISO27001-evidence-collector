# ISO/IEC 27001:2022 Evidence Report

- **Framework:** ISO/IEC 27001:2022
- **Generated:** 2026-11-14 22:17 UTC
- **Scope:** aws:123456789012
- **Regions (1):** eu-central-1
- **Checks run:** 8 (PASS 3, FAIL 4, ERROR 0, N/A 1)

> Automated evidence supports, but does not replace, documented policies, procedures and records. See the notes under each control.

## Summary by control

| Control | Title | Status | Results |
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

## Findings to fix (4)

By severity: 1 critical, 2 high, 1 medium.

> Fix suggestions are general guidance. Review them against your own policies and test before you change a production system.

### 1. [CRITICAL] Root user should have MFA

- **Check:** `aws.iam.root_mfa`
- **Finding:** Root account MFA is NOT enabled
- **Controls:** A.5.17, A.8.2, A.8.5
- **How to fix:** Sign in as the root user, open Security credentials and assign an MFA device. Do not use the root user for daily work.

### 2. [HIGH] S3 buckets should be encrypted and not public

- **Check:** `aws.s3.bucket_protection`
- **Finding:** 0 of 1 buckets encrypted with public access fully blocked
- **Controls:** A.8.3, A.8.24
- **Affected (non compliant):**
  - bucket: trail-logs; encrypted: False; public access blocked: False
- **How to fix:** For each listed bucket turn on Block Public Access (all four settings) and default encryption. Block Public Access can also be set once for the whole account under S3 > Block Public Access settings for this account.

### 3. [HIGH] Security Hub should be on with no open critical or high findings (eu-central-1)

- **Check:** `aws.securityhub.findings_summary`
- **Finding:** Security Hub is not enabled in eu-central-1
- **Region:** eu-central-1
- **Controls:** A.8.8, A.8.16
- **How to fix:** If Security Hub is not enabled, enable it in this region. Otherwise review the open critical and high findings and fix them or record a decision for each.

### 4. [MEDIUM] AWS Config should be recording with compliant rules (eu-central-1)

- **Check:** `aws.config.recorder_and_compliance`
- **Finding:** AWS Config is not recording in eu-central-1
- **Region:** eu-central-1
- **Controls:** A.8.9
- **How to fix:** If AWS Config is not recording, turn on the configuration recorder in this region. Otherwise open each listed non-compliant rule and fix the resources it reports.

## Evidence detail

### A.5.17 Authentication information

- **PASS** IAM password policy should be strong (`aws.iam.password_policy`): Password policy: min length 14, reuse prevention 24  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_
- **FAIL** Root user should have MFA (`aws.iam.root_mfa`): Root account MFA is NOT enabled  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_

**Also provide:** Password / authentication policy; process for issuing credentials.

### A.8.2 Privileged access rights

- **FAIL** Root user should have MFA (`aws.iam.root_mfa`): Root account MFA is NOT enabled  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_

**Also provide:** List of privileged roles and approval records.

### A.8.3 Information access restriction

- **FAIL** S3 buckets should be encrypted and not public (`aws.s3.bucket_protection`): 0 of 1 buckets encrypted with public access fully blocked  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region global_

### A.8.5 Secure authentication

- **FAIL** Root user should have MFA (`aws.iam.root_mfa`): Root account MFA is NOT enabled  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_
- **N/A** IAM console users should have MFA (`aws.iam.console_users_mfa`): No IAM users with console access  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_

### A.8.8 Management of technical vulnerabilities

- **FAIL** Security Hub should be on with no open critical or high findings (`aws.securityhub.findings_summary`): Security Hub is not enabled in eu-central-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_

**Also provide:** Vulnerability management procedure and remediation tickets.

### A.8.9 Configuration management

- **FAIL** AWS Config should be recording with compliant rules (`aws.config.recorder_and_compliance`): AWS Config is not recording in eu-central-1  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region eu-central-1_

**Also provide:** Approved baseline configurations (e.g. CIS benchmark choice).

### A.8.15 Logging

- **PASS** CloudTrail should log all regions (`aws.cloudtrail.multi_region_logging`): 1 active multi-region CloudTrail trail(s)  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region global_

**Also provide:** Logging policy, retention period, log review records.

### A.8.16 Monitoring activities

- **FAIL** Security Hub should be on with no open critical or high findings (`aws.securityhub.findings_summary`): Security Hub is not enabled in eu-central-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_

### A.8.24 Use of cryptography

- **FAIL** S3 buckets should be encrypted and not public (`aws.s3.bucket_protection`): 0 of 1 buckets encrypted with public access fully blocked  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region global_
- **PASS** EBS volumes should be encrypted by default (`aws.ec2.ebs_default_encryption`): EBS encryption by default is enabled in eu-central-1  
  _collected 2026-11-14T22:17:37+00:00, scope aws:123456789012, region eu-central-1_

**Also provide:** Cryptography policy and key management procedure.

---
Generated by iso27001-evidence-collector 1.0.0
