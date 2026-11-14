"""Keep the CloudFormation template in sync with the policy files.

The same permissions live in two places: policies/*.json (for people who
attach them by hand) and infra/github-oidc-role.yaml (for the OIDC role).
These tests fail if one is changed without the other.
"""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = yaml.safe_load((ROOT / "infra" / "github-oidc-role.yaml").read_text(encoding="utf-8"))
IDENTITY = {"sts:GetCallerIdentity"}


def policy_file_actions(name: str) -> set[str]:
    doc = json.loads((ROOT / "policies" / name).read_text(encoding="utf-8"))
    return {a for st in doc["Statement"] for a in st["Action"]}


def template_actions(resource: str) -> set[str]:
    doc = TEMPLATE["Resources"][resource]["Properties"]["PolicyDocument"]
    return {a for st in doc["Statement"] for a in st["Action"]}


def test_lightsail_permissions_match_policy_file():
    assert template_actions("LightsailReadOnlyPolicy") | IDENTITY == \
        policy_file_actions("lightsail-readonly-policy.json")


def test_aws_permissions_match_policy_file():
    assert template_actions("AwsReadOnlyPolicy") | IDENTITY == \
        policy_file_actions("aws-readonly-policy.json")


def test_role_only_allows_read_actions():
    read_prefixes = ("Get", "List", "Describe")
    for resource in ("AwsReadOnlyPolicy", "LightsailReadOnlyPolicy"):
        for action in template_actions(resource):
            assert action.split(":")[1].startswith(read_prefixes), action


def test_trust_policy_is_limited_to_one_repo_and_branch():
    stmt = TEMPLATE["Resources"]["EvidenceRole"]["Properties"][
        "AssumeRolePolicyDocument"]["Statement"][0]
    cond = stmt["Condition"]
    # StringEquals (not StringLike): no wildcards in the subject claim.
    assert set(cond) == {"StringEquals"}
    sub = cond["StringEquals"]["token.actions.githubusercontent.com:sub"]["Fn::Sub"]
    assert sub == "repo:${GitHubOwner}/${GitHubRepo}:ref:refs/heads/${GitHubBranch}"
    assert cond["StringEquals"]["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
