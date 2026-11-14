# iso27001-evidence-collector

Automated evidence collection for **ISO/IEC 27001:2022 Annex A** controls
across enterprise environments - cloud, SaaS, DevOps and on-prem.

Instead of gathering screenshots and exports before every audit, collectors
pull configuration and security data from each system, map it to Annex A
control IDs, and generate an audit-ready evidence report.

## Supported sources (planned)

| Source | Example evidence | Annex A examples | Status |
|---|---|---|---|
| **AWS** (Config, Security Hub, CloudTrail) | Logging enabled, encryption, IAM MFA | A.8.15, A.8.24, A.5.17 |  Planned |
| **Microsoft 365 / Entra ID** (Graph API) | MFA status, conditional access, admin roles | A.5.15, A.5.17, A.8.2 |  Planned |
| **Azure** (Policy, Defender for Cloud) | Policy compliance, secure score | A.8.9, A.8.8 |  Planned |
| **GitLab / GitHub** | Branch protection, MR approvals, CI scans | A.8.25, A.8.28, A.8.32 |  Planned |
| **Linux servers** (SSH) | Patch level, SSH hardening, log forwarding | A.8.8, A.8.9, A.8.15 |  Planned |

## How it works
1. **Collectors** - one module per source, read-only credentials
2. **Control mapping** - YAML file linking each check to Annex A control IDs
3. **Report** - Markdown / HTML evidence report per control, with timestamps
4. **Scheduling** - GitHub Actions or GitLab CI for continuous evidence

## Status
🚧 Work in progress - AWS collector first release planned for December 2026.

## Why
As an ISMS process holder, I found that most audit effort goes into collecting
evidence, not fixing gaps. This project automates the collection part.

## License
MIT
