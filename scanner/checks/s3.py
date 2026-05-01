"""
S3 misconfiguration checks.

Checks for:
- Public access not blocked at the bucket level
- Bucket policies that allow public reads
- Buckets without default server-side encryption

The PublicAccessBlock API is the easiest way to catch this — if any of the
four block settings are False, that's worth flagging. Bucket policies are
trickier because you'd need to parse the policy document properly; for now
I'm checking for the obvious "Principal: *" case.
"""

import json
import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from scanner.checks import Finding

logger = logging.getLogger(__name__)


def run(session: boto3.Session) -> List[Finding]:
    """Run all S3 checks and return a list of findings."""
    s3 = session.client("s3")
    findings: List[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        logger.warning("Couldn't list S3 buckets: %s", e)
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_bucket_policy(s3, name))
        findings.extend(_check_bucket_encryption(s3, name))

    return findings


def _check_public_access_block(client, bucket_name: str) -> List[Finding]:
    """Check whether the bucket has all four public access block settings enabled."""
    try:
        config = client.get_public_access_block(Bucket=bucket_name)
        block = config["PublicAccessBlockConfiguration"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            # No block config at all — that's a fail
            return [Finding(
                service="S3",
                resource=bucket_name,
                status="FAIL",
                message="no public access block configuration found",
            )]
        logger.warning("Skipping public access block check for %s: %s", bucket_name, e)
        return []

    # All four settings should be True
    not_blocked = [k for k, v in block.items() if not v]
    if not_blocked:
        return [Finding(
            service="S3",
            resource=bucket_name,
            status="FAIL",
            message=f"public access not fully blocked — settings off: {', '.join(not_blocked)}",
            detail=block,
        )]

    return [Finding(service="S3", resource=bucket_name, status="PASS", message="public access blocked")]


def _check_bucket_policy(client, bucket_name: str) -> List[Finding]:
    """Look for bucket policies that grant access to everyone (Principal: *)."""
    try:
        policy_str = client.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return []  # no policy is fine
        logger.warning("Couldn't read bucket policy for %s: %s", bucket_name, e)
        return []

    try:
        policy = json.loads(policy_str)
    except json.JSONDecodeError:
        logger.warning("Couldn't parse bucket policy for %s", bucket_name)
        return []

    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", {})
        effect = statement.get("Effect", "")
        # Principal: "*" or Principal: {"AWS": "*"} with Effect: Allow = public
        if effect == "Allow" and (principal == "*" or principal.get("AWS") == "*"):
            return [Finding(
                service="S3",
                resource=bucket_name,
                status="FAIL",
                message="bucket policy grants public access (Principal: *)",
                detail={"statement": statement},
            )]

    return []


def _check_bucket_encryption(client, bucket_name: str) -> List[Finding]:
    """Check whether the bucket has default server-side encryption enabled."""
    try:
        response = client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            return [Finding(
                service="S3",
                resource=bucket_name,
                status="FAIL",
                message="default encryption is not enabled",
            )]
        logger.warning("Couldn't read bucket encryption for %s: %s", bucket_name, e)
        return []

    rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    algorithms = [
        rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
        for rule in rules
    ]
    enabled_algorithms = [algorithm for algorithm in algorithms if algorithm]

    if not enabled_algorithms:
        return [Finding(
            service="S3",
            resource=bucket_name,
            status="FAIL",
            message="default encryption config exists but no algorithm is set",
            detail=response.get("ServerSideEncryptionConfiguration"),
        )]

    return [Finding(
        service="S3",
        resource=bucket_name,
        status="PASS",
        message=f"default encryption enabled ({', '.join(enabled_algorithms)})",
    )]
