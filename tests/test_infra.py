"""Keep the CloudFormation template in sync with the policy files.

The same permissions live in two places: policies/*.json (for people who
attach them by hand) and infra/github-oidc-role.yaml (for the OIDC role).
These tests fail if one is changed without the other.
"""

import json
import re
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


def test_workflow_actions_are_pinned_to_a_commit_hash():
    # A tag such as @v7 can be moved to different code. A full commit hash cannot.
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows
    for path in workflows:
        for used in re.findall(r"uses:\s*(\S+)", path.read_text(encoding="utf-8")):
            assert re.search(r"@[0-9a-f]{40}$", used), f"{path.name}: {used} is not pinned"


def test_workflows_do_not_grant_write_access_by_default():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        top = workflow.get("permissions", {})
        assert top.get("contents") == "read", f"{path.name}: top-level contents must be read"
