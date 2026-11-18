# iso27001-evidence-collector

[![tests](https://github.com/larcz94/ISO27001-evidence-collector/actions/workflows/tests.yml/badge.svg)](https://github.com/larcz94/ISO27001-evidence-collector/actions/workflows/tests.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)

Automated, read-only evidence collection for **ISO/IEC 27001:2022 Annex A**
controls on AWS and Amazon Lightsail.

Instead of taking screenshots before every audit, the tool reads security
settings through the AWS APIs, maps each result to Annex A control IDs, and
writes an audit-ready report in Markdown, HTML and JSON.

```console
$ iso27001-evidence collect --source lightsail --region eu-central-1
FAIL  lightsail.bucket.access_logging            1 of 2 buckets have access logging enabled
FAIL  lightsail.bucket.public_access             1 of 2 buckets are private with no public object overrides
PASS  lightsail.certificate.expiry               None of the 1 issued certificates expire within 30 days
PASS  lightsail.database.backup_and_exposure     1 of 1 databases have backups on and are not publicly accessible
PASS  lightsail.disk.auto_snapshots              1 of 1 block storage disks have automatic snapshots enabled
FAIL  lightsail.instance.admin_ports_restricted  1 admin port(s) open to the internet across 2 instance(s)
FAIL  lightsail.instance.auto_snapshots          1 of 2 instances have automatic snapshots enabled
FAIL  lightsail.instance.blueprint_supported     1 of 2 instances run a retired blueprint (OS image)
FAIL  lightsail.instance.imdsv2_required         1 of 2 instances require IMDSv2
PASS  lightsail.loadbalancer.https_only          1 of 1 load balancers serve HTTPS and redirect HTTP to HTTPS

6 finding(s) to fix. The report lists the affected resources and how to fix each one.

Markdown: reports/iso27001-evidence_lightsail_2026-11-14_172900Z.md
HTML:     reports/iso27001-evidence_lightsail_2026-11-14_172900Z.html
JSON:     reports/iso27001-evidence_lightsail_2026-11-14_172900Z.json
```

## The report

![HTML evidence report with summary tiles and findings sorted by severity](docs/report-preview.png)

The screenshot and the output above come from fake data. Full sample reports:
[AWS](examples/sample-report.md), [Lightsail](examples/sample-report-lightsail.md)
and a combined [HTML report](examples/sample-report-all.html) (download and open it in a browser).

- **One file, no dependencies.** The HTML report has inline styles, no scripts
  and no external files. Open it offline, attach it to an audit ticket or
  print it to PDF. It follows the light or dark setting of your system.
- **File names you can sort and find.** `iso27001-evidence_<source>_<date>_<time>Z`
  says what the file is, what was checked and when (UTC).
- **Summary first.** Counts, a results bar and the number of controls with gaps.

## Findings and fixes

A FAIL is only useful if you know what failed and what to do about it. Every
check has a plain-English title and a severity (critical, high, medium or
low). Findings are sorted worst first, and each one names the affected
resources, the Annex A controls and a fix suggestion:

```markdown
### 2. [HIGH] SSH and RDP should not be open to the internet (eu-central-1)

- **Check:** `lightsail.instance.admin_ports_restricted`
- **Finding:** 1 admin port(s) open to the internet across 2 instance(s)
- **Region:** eu-central-1
- **Controls:** A.8.20
- **Affected (exposed admin ports):**
  - instance: worker-1; port: 22; service: SSH; open to: 0.0.0.0/0
- **How to fix:** In the Lightsail console open the instance, go to the
  Networking tab and edit the SSH (22) or RDP (3389) rule in the IPv4 firewall:
  restrict it to your own IP addresses, or allow only Lightsail browser SSH/RDP.
  Do the same in the IPv6 firewall, or turn IPv6 off if you do not use it.
```

Fix suggestions are general guidance. Review them against your own policies
before you change a production system. Severity is a default rating, not a
risk assessment of your environment. The same data is in the JSON file
(`title`, `severity`, `region`, `details` and `remediation` fields) if you
want to create tickets from it.

## Accepted risks

ISO 27001 does not ask for zero findings. It asks that every risk is either
fixed or accepted on purpose, with a reason and an owner (clause 6.1.3, risk
treatment). Write those decisions in a small YAML file and pass it to the tool:

```yaml
accepted_risks:
  - check: lightsail.instance.auto_snapshots
    region: eu-central-1          # optional, default: any region
    resources: [worker-1]         # optional, default: every resource
    reason: Stateless worker. It is rebuilt from code, so a snapshot adds no value.
    approved_by: Jane Doe (ISMS lead)
    expires: 2027-05-31           # last day the acceptance is valid
    ticket: RISK-12               # optional
```

```bash
iso27001-evidence collect --source lightsail --all-regions --accepted-risks accepted-risks.yaml
```

- **The status stays FAIL.** The gap is real, so the evidence says so. The
  finding moves from "Findings to fix" to an "Accepted risks" section that
  shows the reason, the approver and the expiry date.
- **New resources are not hidden.** When `resources` is set and another
  resource fails the same check, the finding stays open and the report names
  the resource the acceptance does not cover.
- **Acceptances expire.** After the `expires` date the finding is open again,
  with a note, so every exception gets reviewed.
- **`--fail-on-gap` ignores accepted risks**, so a CI run fails only on gaps
  nobody has decided about.
- **Mistakes stop the run.** An unknown check ID, a missing field or a bad
  date is reported before any AWS call. An entry that matches no failed check
  is reported too, so fixed gaps can be removed from the file.

A full example is in [`examples/accepted-risks.yaml`](examples/accepted-risks.yaml).
In the JSON output each accepted result carries an `accepted_risk` field.

## How it works

```mermaid
flowchart LR
    subgraph account["Your AWS account (read-only)"]
        A["IAM, CloudTrail, S3, EC2,<br>Security Hub, Config"]
        L["Lightsail instances, disks,<br>buckets, databases,<br>load balancers, certificates"]
    end
    A --> C1["aws collector<br>8 checks"]
    L --> C2["lightsail collector<br>10 checks"]
    C1 --> E["Evidence records<br>PASS / FAIL / N/A / ERROR"]
    C2 --> E
    M["annex_a.yaml<br>check to control mapping"] --> R
    E --> R["Report by Annex A control"]
    R --> O["Markdown, HTML, JSON"]
```

1. **Collectors** run read-only checks, one module per source
   ([`collectors/`](src/iso27001_evidence/collectors)). A failing API call becomes an
   ERROR result and never stops the run.
2. **Control mapping** in [`annex_a.yaml`](src/iso27001_evidence/mappings/annex_a.yaml)
   links each check to one or more Annex A controls.
3. **Reports** group the results by control, with a timestamp and the account
   they came from. Every failed check is listed under "Findings to fix" with
   the affected resources and a fix suggestion.
4. **Scheduling** with a [GitHub Actions workflow](.github/workflows/collect-evidence.yml)
   and OIDC, so no AWS keys are stored.

> Automated evidence **supports** a control. It does not prove it on its own.
> Policies, procedures and records are still needed. The report lists what
> else to provide for each control.

## Quick start

```bash
git clone https://github.com/larcz94/ISO27001-evidence-collector.git
cd ISO27001-evidence-collector
pip install -e .

# uses your normal AWS credentials (profile, SSO, env vars)
iso27001-evidence list-checks --source all
iso27001-evidence collect --source lightsail --region eu-central-1
iso27001-evidence collect --source aws --region eu-central-1
iso27001-evidence collect --source all --region eu-central-1   # one combined report
```

Reports are written to `reports/`, which is git-ignored because real reports
contain account details. Add `--fail-on-gap` to get exit code 1 when a check
fails, which is useful in CI.

### One region, several regions or all regions

```bash
iso27001-evidence collect --source lightsail --region eu-west-3                 # one region
iso27001-evidence collect --source lightsail --region eu-west-3 eu-central-1    # several
iso27001-evidence collect --source lightsail --all-regions                      # every region
```

All regions go into **one** report:

- Every result and finding shows its region.
- Account-wide checks (IAM, S3, CloudTrail) run once. Only regional checks
  (EBS encryption, Security Hub, AWS Config and all Lightsail checks) repeat
  per region.
- Regions with nothing to check are folded into one line, for example
  "Nothing to check in 14 regions: ...". That line is evidence too: it shows
  the regions were looked at and were empty.

`--all-regions` is the safer choice for an audit, because it also finds
resources that someone created in a region nobody looks at. It asks AWS for
the region list (`lightsail:GetRegions` or `ec2:DescribeRegions`, both in the
read-only policies) and takes longer, since every region is a separate set of
API calls.

### Permissions

The tool never changes anything. Give the user or role that runs it only the
policy for the sources you use:

| Source | Policy |
|---|---|
| `aws` | [`policies/aws-readonly-policy.json`](policies/aws-readonly-policy.json) |
| `lightsail` | [`policies/lightsail-readonly-policy.json`](policies/lightsail-readonly-policy.json) |

## Checks

### Amazon Lightsail (10 checks)

Small setups often run on Lightsail instead of EC2, and they are still in
scope for an ISMS. Lightsail is regional, so name the regions you use or
pass `--all-regions`.

| Check ID | What it verifies | Annex A |
|---|---|---|
| `lightsail.instance.auto_snapshots` | Every instance has automatic snapshots on | A.8.13 |
| `lightsail.disk.auto_snapshots` | Every block storage disk has automatic snapshots on | A.8.13 |
| `lightsail.instance.admin_ports_restricted` | SSH (22) and RDP (3389) are not open to `0.0.0.0/0` or `::/0` | A.8.20 |
| `lightsail.instance.imdsv2_required` | Instances require IMDSv2 for the metadata service | A.8.9 |
| `lightsail.instance.blueprint_supported` | The OS image (blueprint) is still offered by Lightsail, not retired | A.8.8 |
| `lightsail.bucket.public_access` | Buckets are private and do not allow public object overrides | A.8.3 |
| `lightsail.bucket.access_logging` | Buckets have access logging on | A.8.15 |
| `lightsail.database.backup_and_exposure` | Managed databases keep backups and are not publicly accessible | A.8.3, A.8.13, A.8.20 |
| `lightsail.loadbalancer.https_only` | Load balancers serve HTTPS and redirect HTTP to HTTPS | A.8.24 |
| `lightsail.certificate.expiry` | No issued certificate expires within 30 days | A.8.24 |

### AWS (8 checks)

| Check ID | What it verifies | Annex A |
|---|---|---|
| `aws.iam.root_mfa` | Root account has MFA | A.5.17, A.8.2, A.8.5 |
| `aws.iam.console_users_mfa` | Every IAM user with console access has MFA | A.8.5 |
| `aws.iam.password_policy` | Minimum length 14 or more and password reuse prevention | A.5.17 |
| `aws.cloudtrail.multi_region_logging` | An active multi-region CloudTrail trail exists | A.8.15 |
| `aws.s3.bucket_protection` | Buckets are encrypted and block public access | A.8.3, A.8.24 |
| `aws.ec2.ebs_default_encryption` | EBS encryption by default is on | A.8.24 |
| `aws.securityhub.findings_summary` | Security Hub is enabled, counts open critical and high findings | A.8.8, A.8.16 |
| `aws.config.recorder_and_compliance` | AWS Config is recording, lists non-compliant rules | A.8.9 |

## Run it every week with GitHub Actions (no stored keys)

The [collect-evidence workflow](.github/workflows/collect-evidence.yml) runs
every Monday. It uses GitHub OIDC to get short-lived credentials, so there are
no access keys to store or rotate.

1. Deploy [`infra/github-oidc-role.yaml`](infra/github-oidc-role.yaml) once with
   CloudFormation. It creates the GitHub OIDC provider and a read-only role
   that only this repository and branch can assume:

   ```bash
   aws cloudformation deploy \
     --stack-name iso27001-evidence-role \
     --template-file infra/github-oidc-role.yaml \
     --capabilities CAPABILITY_IAM \
     --parameter-overrides GitHubOwner=<your-github-user> EnableLightsailChecks=true
   ```

   IAM is free, so this stack has no cost. If your account already has a GitHub
   OIDC provider, add `CreateOIDCProvider=false`.
2. In the repository settings, add these **variables** (not secrets):
   `AWS_EVIDENCE_ROLE_ARN` (the stack output `RoleArn`) and `AWS_REGION`.
   Optional: `EVIDENCE_SOURCES` (for example `lightsail` or `aws lightsail`)
   and `EVIDENCE_REGIONS` (for example `eu-west-3 eu-central-1`, or `all`).
3. Run the workflow by hand once from the Actions tab to test it.

Reports are uploaded as private workflow artifacts and kept for 90 days. They
are never committed to the repository.

## Running tests

No AWS account is needed. AWS tests use [moto](https://github.com/getmoto/moto).
moto does not cover Lightsail, so those tests use botocore's `Stubber` with
fixed API responses.

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -q
```

## Roadmap

- [x] Collector framework and Annex A mapping
- [x] AWS collector (8 checks)
- [x] Amazon Lightsail collector (10 checks)
- [x] Markdown, HTML and JSON reports
- [x] Findings with affected resources and fix suggestions
- [x] GitHub Actions scheduled run with OIDC and a CloudFormation role template
- [x] Several regions or all regions in one run and one report
- [x] Accepted risk register with expiry dates
- [ ] Publish to PyPI
- [ ] GitLab / GitHub collector (branch protection, reviews)
- [ ] Microsoft 365 / Entra ID collector
- [ ] Linux server collector

## Why

As an ISMS lead and DevOps engineer, I found that most audit effort goes into
collecting evidence, not fixing gaps. This project automates the collection part.

## How this compares to Prowler and AWS Audit Manager

This is a small tool with a narrow goal. Bigger tools exist, and for many
teams they are the better choice. Facts below were checked in November 2026,
so check the linked pages for the current state.

| | This tool | [Prowler](https://github.com/prowler-cloud/prowler) | [AWS Audit Manager](https://docs.aws.amazon.com/audit-manager/latest/userguide/iso-27001-2013.html) |
|---|---|---|---|
| What it is | Small open source CLI | Large open source security platform | Managed AWS service |
| Coverage | 18 checks: 8 AWS, 10 Lightsail | Hundreds of checks. Its ISO 27001:2022 framework for AWS maps 92 requirements to 316 checks | Prebuilt ISO/IEC 27001:2013 Annex A framework, most of its controls are manual |
| ISO 27001 version | 2022 | 2022 | 2013 |
| Cost | Free, read-only API calls | Free (open source), paid cloud version | Priced per resource assessment |
| Availability | Open source | Open source | AWS states it is no longer open to new customers |
| Written for | The person who prepares the audit | Security engineers | Audit and compliance teams |

**Use Prowler** when you want broad security coverage of a real AWS
environment: many services, many accounts, several frameworks. It is the
right tool for that job, and this project does not try to replace it.

**Use this tool** when:

- you run a small setup, often on Amazon Lightsail, and want a short report
  you can read in ten minutes,
- you prepare the audit yourself and want each result tied to an Annex A
  control, with a note on what else the auditor will ask for,
- you want code small enough to read and trust before you give it access to
  your account, or to learn from.

The two can also be used together: Prowler for depth, this tool for a short
evidence report per control.

## Development and releases

- `main` is protected. Every change comes in through a pull request and must
  pass lint and tests on Python 3.10, 3.12 and 3.13.
- GitHub Actions are pinned to full commit hashes and run with read-only
  permissions by default.
- A release is a version tag on `main`. The [release workflow](.github/workflows/release.yml)
  checks that the tag is on `main` and matches the package version, runs the
  tests again, then publishes the package with SHA-256 checksums.

Install a specific release:

```bash
pip install "git+https://github.com/larcz94/ISO27001-evidence-collector@v1.1.0"
```

## Security

Please do not open a public issue for a security problem. Use **Report a vulnerability**
under the Security tab of this repository.

## Contributing

New collectors and checks are welcome. Open an issue first for larger changes,
then send a pull request from a branch. Collectors must stay read-only, every
new API call goes into the matching file in `policies/` and into
`infra/github-oidc-role.yaml`, and every check needs a title, a severity, a
fix suggestion and a test. The pull request template has the full checklist.

## License

MIT
