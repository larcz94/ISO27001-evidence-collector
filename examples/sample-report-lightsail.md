# ISO 27001 Evidence Report

> Example generated from **fake** Lightsail API responses (botocore Stubber), not real data.

- **Framework:** ISO/IEC 27001:2022
- **Generated:** 2026-11-14 16:27 UTC
- **Scope:** aws:123456789012/eu-central-1
- **Checks run:** 6 (PASS 3, FAIL 3, ERROR 0, N/A 0)

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
| A.8.8 | Management of technical vulnerabilities | not checked in this run | 0 |
| A.8.9 | Configuration management | not checked in this run | 0 |
| A.8.13 | Information backup | **FAIL** | 2 |
| A.8.15 | Logging | not checked in this run | 0 |
| A.8.16 | Monitoring activities | not checked in this run | 0 |
| A.8.20 | Networks security | **FAIL** | 2 |
| A.8.24 | Use of cryptography | **PASS** | 2 |
| A.8.25 | Secure development life cycle | not automated yet | 0 |
| A.8.32 | Change management | not automated yet | 0 |

## Evidence detail

### A.8.3 Information access restriction

- **FAIL** `lightsail.bucket.public_access`: 1 of 2 buckets are private with no public object overrides  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_

### A.8.13 Information backup

- **FAIL** `lightsail.instance.auto_snapshots`: 1 of 2 instances have automatic snapshots enabled  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Backup policy, retention period and records of restore tests.

### A.8.20 Networks security

- **FAIL** `lightsail.instance.admin_ports_restricted`: 1 admin port(s) open to the internet across 2 instance(s)  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.database.backup_and_exposure`: 1 of 1 databases have backups on and are not publicly accessible  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Network diagram and firewall rule review records.

### A.8.24 Use of cryptography

- **PASS** `lightsail.loadbalancer.https_only`: 1 of 1 load balancers serve HTTPS and redirect HTTP to HTTPS  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_
- **PASS** `lightsail.certificate.expiry`: 0 of 1 certificates expire within 30 days  
  _collected 2026-11-14T16:27:29+00:00, scope aws:123456789012/eu-central-1_

**Also provide:** Cryptography policy and key management procedure.
