"""AWS collector: read-only checks against IAM, CloudTrail, S3, EC2,
Security Hub and AWS Config.

Credentials come from the standard boto3 chain (env vars, profile, SSO,
or an OIDC-assumed role in CI). Use the read-only policy in
policies/aws-readonly-policy.json.
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ..models import Evidence, Status
from .base import BaseCollector, check

REMEDIATION = {
    "aws.iam.root_mfa":
        "Sign in as the root user, open Security credentials and assign an MFA device. "
        "Do not use the root user for daily work.",
    "aws.iam.console_users_mfa":
        "For each listed user: IAM > Users > Security credentials > assign an MFA device. "
        "Better, move people to IAM Identity Center and remove IAM console passwords.",
    "aws.iam.password_policy":
        "IAM > Account settings > edit the password policy: minimum length 14 or more and "
        "prevent password reuse.",
    "aws.cloudtrail.multi_region_logging":
        "CloudTrail > Trails > create a trail that applies to all regions, and make sure "
        "logging is turned on. Turn on log file validation as well.",
    "aws.s3.bucket_protection":
        "For each listed bucket turn on Block Public Access (all four settings) and "
        "default encryption. Block Public Access can also be set once for the whole "
        "account under S3 > Block Public Access settings for this account.",
    "aws.ec2.ebs_default_encryption":
        "EC2 console > Settings > EBS encryption > turn on encryption by default. This is "
        "a per-region setting, so repeat it in every region you use.",
    "aws.securityhub.findings_summary":
        "If Security Hub is not enabled, enable it in this region. Otherwise review the "
        "open critical and high findings and fix them or record a decision for each.",
    "aws.config.recorder_and_compliance":
        "If AWS Config is not recording, turn on the configuration recorder in this "
        "region. Otherwise open each listed non-compliant rule and fix the resources it "
        "reports.",
}


class AWSCollector(BaseCollector):
    source = "aws"
    remediation = REMEDIATION

    def __init__(self, session: boto3.Session | None = None, region: str | None = None) -> None:
        super().__init__()
        self.session = session or boto3.Session(region_name=region)
        self.region = self.session.region_name or "eu-central-1"
        self.scope = self._account_id()

    # ---------- helpers ----------
    def _client(self, name: str):
        return self.session.client(name, region_name=self.region)

    def _account_id(self) -> str:
        try:
            return "aws:" + self._client("sts").get_caller_identity()["Account"]
        except Exception:  # noqa: BLE001
            return "aws:unknown"

    def _ev(self, check_id: str, status: Status, summary: str, **details) -> Evidence:
        return Evidence(check_id=check_id, source=self.source, status=status,
                        summary=summary, details=details)

    # ---------- identity & authentication ----------
    @check("aws.iam.root_mfa")
    def root_mfa(self) -> Evidence:
        summary = self._client("iam").get_account_summary()["SummaryMap"]
        enabled = summary.get("AccountMFAEnabled", 0) == 1
        return self._ev(
            "aws.iam.root_mfa",
            Status.PASS if enabled else Status.FAIL,
            "Root account MFA is enabled" if enabled else "Root account MFA is NOT enabled",
            account_mfa_enabled=enabled,
        )

    @check("aws.iam.console_users_mfa")
    def console_users_mfa(self) -> Evidence:
        iam = self._client("iam")
        without_mfa, console_users = [], []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        continue  # no console password -> not a console user
                    raise
                console_users.append(name)
                if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                    without_mfa.append(name)
        if not console_users:
            return self._ev("aws.iam.console_users_mfa", Status.NOT_APPLICABLE,
                            "No IAM users with console access", console_users=0)
        return self._ev(
            "aws.iam.console_users_mfa",
            Status.FAIL if without_mfa else Status.PASS,
            f"{len(without_mfa)} of {len(console_users)} console users have no MFA device",
            console_users=len(console_users),
            users_without_mfa=without_mfa,
        )

    @check("aws.iam.password_policy")
    def password_policy(self) -> Evidence:
        try:
            policy = self._client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return self._ev("aws.iam.password_policy", Status.FAIL,
                                "No IAM account password policy is set")
            raise
        min_len = policy.get("MinimumPasswordLength", 0)
        ok = min_len >= 14 and bool(policy.get("PasswordReusePrevention"))
        return self._ev(
            "aws.iam.password_policy",
            Status.PASS if ok else Status.FAIL,
            f"Password policy: min length {min_len}, reuse prevention "
            f"{policy.get('PasswordReusePrevention', 'off')}",
            policy=policy,
        )

    # ---------- logging & monitoring ----------
    @check("aws.cloudtrail.multi_region_logging")
    def cloudtrail_logging(self) -> Evidence:
        ct = self._client("cloudtrail")
        # Include shadow trails: a multi-region trail created in another
        # region only shows up here as a shadow copy. The ARN lets us read
        # its status from this region.
        trails = {t["TrailARN"]: t for t in
                  ct.describe_trails(includeShadowTrails=True)["trailList"]}
        active = []
        for t in trails.values():
            if not t.get("IsMultiRegionTrail"):
                continue
            status = ct.get_trail_status(Name=t["TrailARN"])
            if status.get("IsLogging"):
                active.append({
                    "name": t["Name"],
                    "home_region": t.get("HomeRegion"),
                    "log_file_validation": t.get("LogFileValidationEnabled", False),
                    "kms_encrypted": bool(t.get("KmsKeyId")),
                })
        return self._ev(
            "aws.cloudtrail.multi_region_logging",
            Status.PASS if active else Status.FAIL,
            f"{len(active)} active multi-region CloudTrail trail(s)" if active
            else "No active multi-region CloudTrail trail",
            trails_total=len(trails),
            active_multi_region_trails=active,
        )

    # ---------- cryptography & data protection ----------
    @check("aws.s3.bucket_protection")
    def s3_bucket_protection(self) -> Evidence:
        s3 = self._client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            return self._ev("aws.s3.bucket_protection", Status.NOT_APPLICABLE, "No S3 buckets")
        issues = []
        for b in buckets:
            name = b["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
                encrypted = True
            except ClientError:
                encrypted = False
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(cfg.values())
            except ClientError:
                blocked = False
            if not (encrypted and blocked):
                issues.append({"bucket": name, "encrypted": encrypted,
                               "public_access_blocked": blocked})
        return self._ev(
            "aws.s3.bucket_protection",
            Status.FAIL if issues else Status.PASS,
            f"{len(buckets) - len(issues)} of {len(buckets)} buckets encrypted "
            f"with public access fully blocked",
            buckets_total=len(buckets),
            non_compliant=issues,
        )

    @check("aws.ec2.ebs_default_encryption")
    def ebs_default_encryption(self) -> Evidence:
        enabled = self._client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        return self._ev(
            "aws.ec2.ebs_default_encryption",
            Status.PASS if enabled else Status.FAIL,
            f"EBS encryption by default is {'enabled' if enabled else 'disabled'} "
            f"in {self.region}",
            region=self.region,
        )

    # ---------- vulnerability & configuration management ----------
    @check("aws.securityhub.findings_summary")
    def securityhub_summary(self) -> Evidence:
        sh = self._client("securityhub")
        try:
            sh.describe_hub()
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidAccessException",
                                               "ResourceNotFoundException"):
                return self._ev("aws.securityhub.findings_summary", Status.FAIL,
                                f"Security Hub is not enabled in {self.region}")
            raise
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                               {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
        }
        for page in sh.get_paginator("get_findings").paginate(Filters=filters):
            for f in page["Findings"]:
                label = f.get("Severity", {}).get("Label")
                if label in counts:
                    counts[label] += 1
        open_crit_high = counts["CRITICAL"] + counts["HIGH"]
        return self._ev(
            "aws.securityhub.findings_summary",
            Status.FAIL if open_crit_high else Status.PASS,
            f"Security Hub active findings - critical: {counts['CRITICAL']}, "
            f"high: {counts['HIGH']}, medium: {counts['MEDIUM']}, low: {counts['LOW']}",
            open_findings_by_severity=counts,
        )

    @check("aws.config.recorder_and_compliance")
    def config_compliance(self) -> Evidence:
        cfg = self._client("config")
        recorders = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", [])
        recording = any(r.get("recording") for r in recorders)
        if not recording:
            return self._ev("aws.config.recorder_and_compliance", Status.FAIL,
                            f"AWS Config is not recording in {self.region}")
        non_compliant = []
        paginator = cfg.get_paginator("describe_compliance_by_config_rule")
        for page in paginator.paginate():
            for r in page["ComplianceByConfigRules"]:
                if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT":
                    non_compliant.append(r["ConfigRuleName"])
        return self._ev(
            "aws.config.recorder_and_compliance",
            Status.FAIL if non_compliant else Status.PASS,
            f"AWS Config recording; {len(non_compliant)} non-compliant rule(s)",
            non_compliant_rules=non_compliant,
        )
