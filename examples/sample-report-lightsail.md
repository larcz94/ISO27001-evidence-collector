# ISO/IEC 27001:2022 Evidence Report

- **Framework:** ISO/IEC 27001:2022
- **Generated:** 2026-11-14 22:17 UTC
- **Scope:** aws:123456789012
- **Regions (3):** eu-central-1, eu-west-3, us-east-1
- **Checks run:** 30 (PASS 4, FAIL 6, ERROR 0, N/A 20)

> Automated evidence supports, but does not replace, documented policies, procedures and records. See the notes under each control.

## Summary by control

| Control | Title | Status | Results |
|---|---|---|---|
| A.5.15 | Access control | not automated yet | 0 |
| A.5.17 | Authentication information | not checked in this run | 0 |
| A.8.2 | Privileged access rights | not checked in this run | 0 |
| A.8.3 | Information access restriction | **FAIL** | 6 |
| A.8.5 | Secure authentication | not checked in this run | 0 |
| A.8.8 | Management of technical vulnerabilities | **FAIL** | 3 |
| A.8.9 | Configuration management | **FAIL** | 3 |
| A.8.13 | Information backup | **FAIL** | 9 |
| A.8.15 | Logging | **FAIL** | 3 |
| A.8.16 | Monitoring activities | not checked in this run | 0 |
| A.8.20 | Networks security | **FAIL** | 6 |
| A.8.24 | Use of cryptography | **PASS** | 6 |
| A.8.25 | Secure development life cycle | not automated yet | 0 |
| A.8.32 | Change management | not automated yet | 0 |

## Findings to fix (6)

By severity: 2 high, 3 medium, 1 low.

> Fix suggestions are general guidance. Review them against your own policies and test before you change a production system.

### 1. [HIGH] Buckets should be private (eu-central-1)

- **Check:** `lightsail.bucket.public_access`
- **Finding:** 1 of 2 buckets are private with no public object overrides
- **Region:** eu-central-1
- **Controls:** A.8.3
- **Affected (non compliant):**
  - bucket: static-site; public read: True; allow public object overrides: False
- **How to fix:** In the Lightsail console open the bucket, go to the Permissions tab, set the bucket to private and turn off the option that lets individual objects be made public. If the bucket hosts a public website on purpose, record it as an accepted risk.

### 2. [HIGH] SSH and RDP should not be open to the internet (eu-central-1)

- **Check:** `lightsail.instance.admin_ports_restricted`
- **Finding:** 1 admin port(s) open to the internet across 2 instance(s)
- **Region:** eu-central-1
- **Controls:** A.8.20
- **Affected (exposed admin ports):**
  - instance: worker-1; port: 22; service: SSH; open to: 0.0.0.0/0
- **How to fix:** In the Lightsail console open the instance, go to the Networking tab and edit the SSH (22) or RDP (3389) rule in the IPv4 firewall: restrict it to your own IP addresses, or allow only Lightsail browser SSH/RDP. Do the same in the IPv6 firewall, or turn IPv6 off if you do not use it.

### 3. [MEDIUM] Instances should have automatic snapshots (eu-central-1)

- **Check:** `lightsail.instance.auto_snapshots`
- **Finding:** 1 of 2 instances have automatic snapshots enabled
- **Region:** eu-central-1
- **Controls:** A.8.13
- **Affected (instances without auto snapshots):**
  - worker-1
- **How to fix:** In the Lightsail console open the instance, go to the Snapshots tab and turn on automatic snapshots. Snapshot storage is billed per GB. If the instance holds no data you need, record that as an accepted risk instead.

### 4. [MEDIUM] Instances should run a supported OS image (eu-central-1)

- **Check:** `lightsail.instance.blueprint_supported`
- **Finding:** 1 of 2 instances run a retired blueprint (OS image)
- **Region:** eu-central-1
- **Controls:** A.8.8
- **Affected (retired blueprints):**
  - instance: worker-1; blueprint: ubuntu_18_04
- **How to fix:** The OS image is retired, which usually means the OS version is near or past end of life. Take a snapshot, create a new instance from a current blueprint, move the application and delete the old instance.

### 5. [MEDIUM] Instances should require IMDSv2 (eu-central-1)

- **Check:** `lightsail.instance.imdsv2_required`
- **Finding:** 1 of 2 instances require IMDSv2
- **Region:** eu-central-1
- **Controls:** A.8.9
- **Affected (instances allowing imdsv1):**
  - worker-1
- **How to fix:** Require IMDSv2 with the AWS CLI: aws lightsail update-instance-metadata-options --instance-name <name> --http-tokens required. Test the application afterwards, because very old SDKs may still use IMDSv1.

### 6. [LOW] Buckets should have access logging (eu-central-1)

- **Check:** `lightsail.bucket.access_logging`
- **Finding:** 1 of 2 buckets have access logging enabled
- **Region:** eu-central-1
- **Controls:** A.8.15
- **Affected (buckets without access logs):**
  - static-site
- **How to fix:** In the Lightsail console open the bucket, go to the Logging tab, turn on access logging and choose a second, private bucket as the destination.

## Evidence detail

### A.8.3 Information access restriction

- **FAIL** Buckets should be private (`lightsail.bucket.public_access`): 1 of 2 buckets are private with no public object overrides  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Buckets should be private (`lightsail.bucket.public_access`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_
- **PASS** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

### A.8.8 Management of technical vulnerabilities

- **FAIL** Instances should run a supported OS image (`lightsail.instance.blueprint_supported`): 1 of 2 instances run a retired blueprint (OS image)  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Instances should run a supported OS image (`lightsail.instance.blueprint_supported`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Vulnerability management procedure and remediation tickets.

### A.8.9 Configuration management

- **FAIL** Instances should require IMDSv2 (`lightsail.instance.imdsv2_required`): 1 of 2 instances require IMDSv2  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Instances should require IMDSv2 (`lightsail.instance.imdsv2_required`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Approved baseline configurations (e.g. CIS benchmark choice).

### A.8.13 Information backup

- **FAIL** Instances should have automatic snapshots (`lightsail.instance.auto_snapshots`): 1 of 2 instances have automatic snapshots enabled  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Instances should have automatic snapshots (`lightsail.instance.auto_snapshots`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_
- **PASS** Block storage disks should have automatic snapshots (`lightsail.disk.auto_snapshots`): 1 of 1 block storage disks have automatic snapshots enabled  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Block storage disks should have automatic snapshots (`lightsail.disk.auto_snapshots`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_
- **PASS** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Backup policy, retention period and records of restore tests.

### A.8.15 Logging

- **FAIL** Buckets should have access logging (`lightsail.bucket.access_logging`): 1 of 2 buckets have access logging enabled  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Buckets should have access logging (`lightsail.bucket.access_logging`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Logging policy, retention period, log review records.

### A.8.20 Networks security

- **FAIL** SSH and RDP should not be open to the internet (`lightsail.instance.admin_ports_restricted`): 1 admin port(s) open to the internet across 2 instance(s)  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** SSH and RDP should not be open to the internet (`lightsail.instance.admin_ports_restricted`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_
- **PASS** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Databases should be backed up and not public (`lightsail.database.backup_and_exposure`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Network diagram and firewall rule review records.

### A.8.24 Use of cryptography

- **PASS** Load balancers should enforce HTTPS (`lightsail.loadbalancer.https_only`): 1 of 1 load balancers serve HTTPS and redirect HTTP to HTTPS  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Load balancers should enforce HTTPS (`lightsail.loadbalancer.https_only`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_
- **PASS** Certificates should not be about to expire (`lightsail.certificate.expiry`): None of the 1 issued certificates expire within 30 days  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012, region eu-central-1_
- **N/A** Certificates should not be about to expire (`lightsail.certificate.expiry`): Nothing to check in 2 regions: eu-west-3, us-east-1  
  _collected 2026-11-14T22:17:38+00:00, scope aws:123456789012_

**Also provide:** Cryptography policy and key management procedure.

---
Generated by iso27001-evidence-collector 1.0.0
