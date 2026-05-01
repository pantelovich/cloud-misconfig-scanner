"""
CloudTrail misconfiguration checks.

Just checks whether there's an active trail in the target region.
A trail that exists but is set to IsLogging=False counts as a fail —
it's the same as having no trail from an audit perspective.
"""

import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from scanner.checks import Finding

logger = logging.getLogger(__name__)


def run(session: boto3.Session) -> List[Finding]:
    """Check whether CloudTrail is active in the current region."""
    ct = session.client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except ClientError as e:
        logger.warning("Couldn't describe CloudTrail trails: %s", e)
        return []

    if not trails:
        return [Finding(
            service="CloudTrail",
            resource="(none)",
            status="FAIL",
            message="no CloudTrail trail found in this region",
        )]

    findings: List[Finding] = []
    for trail in trails:
        name = trail["Name"]
        arn = trail["TrailARN"]
        try:
            status = ct.get_trail_status(Name=arn)
            is_logging = status.get("IsLogging", False)
        except ClientError as e:
            logger.warning("Couldn't get status for trail %s: %s", name, e)
            continue

        if not is_logging:
            findings.append(Finding(
                service="CloudTrail",
                resource=name,
                status="FAIL",
                message="trail exists but IsLogging is False — nothing is being recorded",
                detail={"trail_arn": arn},
            ))
        else:
            findings.append(Finding(
                service="CloudTrail",
                resource=name,
                status="PASS",
                message="trail is active and logging",
            ))

    return findings
