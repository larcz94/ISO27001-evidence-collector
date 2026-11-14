# ISO 27001 Evidence Report

> Example generated from fake data (moto and botocore Stubber), not a real account.

- **Framework:** ISO/IEC 27001:2022
- **Generated:** 2026-11-14 21:36 UTC
- **Scope:** aws:123456789012/eu-central-1
- **Checks run:** 10 (PASS 4, FAIL 6, ERROR 0, N/A 0)

> Automated evidence supports, but does not replace, documented policies,
> procedures and records. See the notes under each control.

## Summary by control

| Control | Title | Status | Checks |
|---|---|---|---|
| A.5.15 | Access control | not automated yet | 0 |
| A.5.17 | Authentication information | not checked in this run | 0 |
| A.8.2 | Privileged access rights | not checked in this run | 0 |
| A.8.3 | Information access restriction | **FAIL** | 2 |
| A.8.5 | Secure authentication | not checked in this run | 0 |
| A.8.8 | Management of technical vulnerabilities | **FAIL** | 1 |
| A.8.9 | Configuration management | **FAIL** | 1 |
| A.8.13 | Information backup | **FAIL** | 3 |
| A.8.15 | Logging | **FAIL** | 1 |
| A.8.16 | Monitoring activities | not checked in this run | 0 |
| A.8.20 | Networks security | **FAIL** | 2 |
| A.8.24 | Use of cryptography | **PASS** | 2 |
| A.8.25 | Secure development life cycle | not automated yet | 0 |
| A.8.32 | Change management | not automated yet | 0 |

## Findings to fix (6)

> Fix suggestions are general guidance. Review them against your own policies and test before you change a production system.

### 1. lightsail.bucket.access_logging

- **Finding:** 1 of 2 buckets have access logging enabled
- **Controls:** A.8.15
- **Affected (buckets without access logs):**
  - static-site
- **How to fix:** In the Lightsail console open the bucket, go to the Logging tab, turn on access logging and choose a second, private bucket as the destination.

### 2. lightsail.bucket.public_access

- **Finding:** 1 of 2 buckets are private with no public object overrides
- **Controls:** A.8.3
- **Affected (non compliant):**
  - bucket: static-site; public read: True; allow public object overrides: False
- **How to fix:** In the Lightsail console open the bucket, go to the Permissions tab, set the bucket to private and turn off the option that lets individual objects be made public. If the bucket hosts a public website on purpose, record it as an accepted risk.

### 3. lightsail.instance.admin_ports_restricted

- **Finding:** 1 admin port(s) open to the internet across 2 instance(s)
- **Controls:** A.8.20
- **Affected (exposed admin ports):**
  - instance: worker-1; port: 22; service: SSH; open to: 0.0.0.0/0
- **How to fix:** In the Lightsail console open the instance, go to the Networking tab and edit the SSH (22) or RDP (3389) rule in the IPv4 firewall: restrict it to your own IP addresses, or allow only Lightsail browser SSH/RDP. Do the same in the IPv6 firewall, or turn IPv6 off if you do not use it.

### 4. lightsail.instance.auto_snapshots

- **Finding:** 1 of 2 instances have automatic snapshots enabled
- **Controls:** A.8.13
- **Affected (instances without auto snapshots):**
  - worker-1
- **How to fix:** In the Lightsail console open the instance, go to the Snapshots tab and turn on automatic snapshots. Snapshot storage is billed per GB. If the instance holds no data you need, record that as an accepted risk instead.

### 5. lightsail.instance.blueprint_supported

- **Finding:** 1 of 2 instances run a retired blueprint (OS image)
- **Controls:** A.8.8
- **Affected (retired blueprints):**
  - instance: worker-1; blueprint: ubuntu_18_04
- **How to fix:** The OS image is retired, which usually means the OS version is near or past end of life. Take a snapshot, create a new instance from a current blueprint, move the application and delete the old instance.

### 6. lightsail.instance.imdsv2_required

- **Finding:** 1 of 2 instances require IMDSv2
- **Controls:** A.8.9
- **Affected (instances allowing imdsv1):**
  - worker-1
- **How to fix:** Require IMDSv2 with the AWS CLI: aws lightsail update-instance-metadata-options --instance-name <name> --http-tokens required. Test the application afterwards, because very old SDKs may still use IMDSv1.

## Evidence detail

### A.8.3 Information access restriction

- **FAIL** `lightsail.bucket.public_access`: 1 of 2 buckets are private with no public object overrides  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

### A.8.8 Management of technical vulnerabilities

- **FAIL** `lightsail.instance.blueprint_supported`: 1 of 2 instances run a retired blueprint (OS image)  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Vulnerability management procedure and remediation tickets.

### A.8.9 Configuration management

- **FAIL** `lightsail.instance.imdsv2_required`: 1 of 2 instances require IMDSv2  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Approved baseline configurations (e.g. CIS benchmark choice).

### A.8.13 Information backup

- **FAIL** `lightsail.instance.auto_snapshots`: 1 of 2 instances have automatic snapshots enabled  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.disk.auto_snapshots`: 1 of 1 block storage disks have automatic snapshots enabled  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Backup policy, retention period and records of restore tests.

### A.8.15 Logging

- **FAIL** `lightsail.bucket.access_logging`: 1 of 2 buckets have access logging enabled  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Logging policy, retention period, log review records.

### A.8.20 Networks security

- **FAIL** `lightsail.instance.admin_ports_restricted`: 1 admin port(s) open to the internet across 2 instance(s)  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Network diagram and firewall rule review records.

### A.8.24 Use of cryptography

- **PASS** `lightsail.loadbalancer.https_only`: 1 of 1 load balancers serve HTTPS and redirect HTTP to HTTPS  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.certificate.expiry`: None of the 1 issued certificates expire within 30 days  
  _collected 2026-11-14T21:36:06+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Cryptography policy and key management procedure.
