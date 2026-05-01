"""
IAM misconfiguration checks.

Checks for:
- Customer-managed policies with wildcard actions (Action: * or *:*)
- Root account MFA not enabled

I'm only checking customer-managed policies here — AWS managed policies
sometimes contain wildcards by design (AdministratorAccess being the obvious
one), and flagging those would just be noise. If you want to include them,
pass include_aws_managed=True to run().
"""

import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from scanner.checks import Finding

logger = logging.getLogger(__name__)


def run(session: boto3.Session, include_aws_managed: bool = False) -> List[Finding]:
    """Run all IAM checks and return a list of findings."""
    iam = session.client("iam")
    findings: List[Finding] = []

    findings.extend(_check_wildcard_policies(iam, include_aws_managed))
    findings.extend(_check_root_mfa(iam))

    return findings


def _check_wildcard_policies(client, include_aws_managed: bool) -> List[Finding]:
    """Find IAM policies that grant wildcard actions."""
    findings: List[Finding] = []
    scope = "All" if include_aws_managed else "Local"

    paginator = client.get_paginator("list_policies")
    for page in paginator.paginate(Scope=scope):
        for policy in page["Policies"]:
            name = policy["PolicyName"]
            arn = policy["Arn"]
            version_id = policy["DefaultVersionId"]

            try:
                doc = client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                statements = doc["PolicyVersion"]["Document"].get("Statement", [])
            except ClientError as e:
                logger.warning("Couldn't fetch policy document for %s: %s", name, e)
                continue

            for stmt in statements:
                action = stmt.get("Action", [])
                effect = stmt.get("Effect", "")

                if effect != "Allow":
                    continue

                # Action can be a string or a list
                actions = [action] if isinstance(action, str) else action
                wildcard_actions = [a for a in actions if a == "*" or a.endswith(":*")]

                if wildcard_actions:
                    findings.append(Finding(
                        service="IAM",
                        resource=name,
                        status="FAIL",
                        message=f"wildcard action in policy: {wildcard_actions}",
                        detail={"policy_arn": arn, "wildcard_actions": wildcard_actions},
                    ))
                    break  # one finding per policy is enough

    return findings


def _check_root_mfa(client) -> List[Finding]:
    """Check whether MFA is enabled on the root account."""
    try:
        summary = client.get_account_summary()["SummaryMap"]
    except ClientError as e:
        logger.warning("Couldn't get account summary: %s", e)
        return []

    # AccountMFAEnabled is 1 if enabled, 0 if not
    mfa_enabled = summary.get("AccountMFAEnabled", 0)
    if not mfa_enabled:
        return [Finding(
            service="IAM",
            resource="root account",
            status="WARN",
            message="MFA is not enabled on the root account — this should be sorted ASAP",
        )]

    return [Finding(
        service="IAM",
        resource="root account",
        status="PASS",
        message="root MFA enabled",
    )]
