# iso27001-evidence-collector

[![tests](https://github.com/larcz94/ISO27001-evidence-collector/actions/workflows/tests.yml/badge.svg)](https://github.com/larcz94/ISO27001-evidence-collector/actions/workflows/tests.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Automated evidence collection for **ISO/IEC 27001:2022 Annex A** controls
across enterprise environments - cloud, SaaS, DevOps and on-prem.

Instead of gathering screenshots and exports before every audit, collectors
pull configuration and security data from each system, map it to Annex A
control IDs, and generate an audit-ready evidence report.

See example reports for [AWS](examples/sample-report.md) and [Lightsail](examples/sample-report-lightsail.md). Both use fake data.

## Supported sources

| Source | Example evidence | Annex A examples | Status |
|---|---|---|---|
| **AWS** (IAM, CloudTrail, S3, EC2, Config, Security Hub) | Logging enabled, encryption, IAM MFA | A.5.17, A.8.5, A.8.15, A.8.24 | Available |
| **Amazon Lightsail** (instances, buckets, databases, load balancers, certificates) | Snapshots, open SSH/RDP, public buckets, HTTPS | A.8.3, A.8.13, A.8.20, A.8.24 | Available |
| **Microsoft 365 / Entra ID** (Graph API) | MFA status, conditional access, admin roles | A.5.15, A.5.17, A.8.2 | Planned |
| **Azure** (Policy, Defender for Cloud) | Policy compliance, secure score | A.8.9, A.8.8 | Planned |
| **GitLab / GitHub** | Branch protection, MR approvals, CI scans | A.8.25, A.8.28, A.8.32 | Planned |
| **Linux servers** (SSH) | Patch level, SSH hardening, log forwarding | A.8.8, A.8.9, A.8.15 | Planned |

## Quick start (AWS)

```bash
git clone https://github.com/larcz94/ISO27001-evidence-collector.git
cd ISO27001-evidence-collector
pip install -e .

# uses your normal AWS credentials (profile, SSO, env vars)
iso27001-evidence list-checks --source aws
iso27001-evidence collect --source aws --region eu-central-1
```

Output: a Markdown report and a JSON file in `reports/` (git-ignored).

## Quick start (Amazon Lightsail)

Small setups often run on Lightsail instead of EC2. The Lightsail collector
checks backups, open admin ports, public buckets, databases, HTTPS and
certificate expiry. Lightsail is regional, so run it once per region you use.

```bash
iso27001-evidence collect --source lightsail --region eu-central-1
```

Attach [`policies/lightsail-readonly-policy.json`](policies/lightsail-readonly-policy.json)
to the user or role that runs it. It only allows `lightsail:Get*` calls for the listed resources.

| Check ID | What it verifies | Annex A |
|---|---|---|
| `lightsail.instance.auto_snapshots` | Every instance has automatic snapshots on | A.8.13 |
| `lightsail.instance.admin_ports_restricted` | SSH (22) and RDP (3389) are not open to `0.0.0.0/0` or `::/0` | A.8.20 |
| `lightsail.bucket.public_access` | Buckets are private and do not allow public object overrides | A.8.3 |
| `lightsail.database.backup_and_exposure` | Managed databases keep backups and are not publicly accessible | A.8.3, A.8.13, A.8.20 |
| `lightsail.loadbalancer.https_only` | Load balancers serve HTTPS and redirect HTTP to HTTPS | A.8.24 |
| `lightsail.certificate.expiry` | No issued certificate expires within 30 days | A.8.24 |

**Permissions:** read-only. Attach [`policies/aws-readonly-policy.json`](policies/aws-readonly-policy.json)
to the user or role that runs the collector. The tool never changes anything.

### AWS checks in v0.1

| Check ID | What it verifies | Annex A |
|---|---|---|
| `aws.iam.root_mfa` | Root account has MFA | A.5.17, A.8.2, A.8.5 |
| `aws.iam.console_users_mfa` | Every IAM user with console access has MFA | A.8.5 |
| `aws.iam.password_policy` | Min. length 14 or more and password reuse prevention | A.5.17 |
| `aws.cloudtrail.multi_region_logging` | An active multi-region CloudTrail trail exists | A.8.15 |
| `aws.s3.bucket_protection` | Buckets are encrypted and block public access | A.8.3, A.8.24 |
| `aws.ec2.ebs_default_encryption` | EBS encryption by default is on | A.8.24 |
| `aws.securityhub.findings_summary` | Security Hub enabled; open critical/high findings | A.8.8, A.8.16 |
| `aws.config.recorder_and_compliance` | AWS Config recording; non-compliant rules | A.8.9 |

## How it works

1. **Collectors** - one module per source, read-only credentials ([`collectors/`](src/iso27001_evidence/collectors))
2. **Control mapping** - [`annex_a.yaml`](src/iso27001_evidence/mappings/annex_a.yaml) links each check to Annex A control IDs
3. **Report** - Markdown + JSON evidence report per control, with timestamps
4. **Scheduling** - [GitHub Actions workflow](.github/workflows/collect-evidence.yml) with OIDC (no stored keys); GitLab CI planned

> Automated evidence **supports** a control - it doesn't prove it on its own.
> Policies, procedures and records are still needed; the report lists what
> else to provide for each control.

## Running tests

Tests use [moto](https://github.com/getmoto/moto) to simulate AWS. moto does not cover Lightsail,
so those tests use botocore's `Stubber` with fixed API responses. No AWS account is needed:

```bash
pip install -e ".[dev]"
pytest -q
```

## Roadmap

- [x] Collector framework and Annex A mapping
- [x] AWS collector (8 checks)
- [x] Markdown / JSON report
- [x] GitHub Actions scheduled run (OIDC)
- [x] Amazon Lightsail collector (6 checks)
- [ ] HTML report
- [ ] Microsoft 365 / Entra ID collector
- [ ] GitLab CI template
- [ ] Linux server collector

## Why

As an ISMS process holder, I found that most audit effort goes into collecting
evidence, not fixing gaps. This project automates the collection part.

## Security

Please do not open a public issue for a security problem. Use **Report a vulnerability**
under the Security tab of this repository.

## Contributing

New collectors and checks are welcome. Collectors must stay read-only, every new
API call goes into the matching file in `policies/`, and every check needs a test.
Open an issue first for larger changes.

## License

MIT
