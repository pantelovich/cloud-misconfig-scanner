"""
EC2 misconfiguration checks.

Checks for:
- Security groups with inbound rules allowing 0.0.0.0/0 or ::/0 on sensitive ports
- EBS volumes that aren't encrypted at rest

Sensitive ports I'm flagging by default — these are the ones that tend to
cause real incidents when left open to the internet:
  22   — SSH
  3389 — RDP
  5432 — Postgres
  3306 — MySQL
  27017 — MongoDB
  6379 — Redis
  9200 — Elasticsearch
  445  — SMB (WannaCry vibes)

-1 means "all traffic", so that's an automatic fail.
"""

import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from scanner.checks import Finding

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {22, 3389, 5432, 3306, 27017, 6379, 9200, 445}
ANY_IP = {"0.0.0.0/0", "::/0"}


def run(session: boto3.Session) -> List[Finding]:
    """Run all EC2 checks and return a list of findings."""
    ec2 = session.client("ec2")
    findings: List[Finding] = []

    findings.extend(_check_security_groups(ec2))
    findings.extend(_check_ebs_encryption(ec2))

    return findings


def _check_security_groups(client) -> List[Finding]:
    """Flag security groups with inbound rules open to the world on risky ports."""
    findings: List[Finding] = []

    try:
        paginator = client.get_paginator("describe_security_groups")
        pages = paginator.paginate()
    except ClientError as e:
        logger.warning("Couldn't list security groups: %s", e)
        return findings

    for page in pages:
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            label = f"{sg_id} ({sg_name})"

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", -1)
                to_port = rule.get("ToPort", -1)
                protocol = rule.get("IpProtocol", "")

                open_to_world = (
                    any(r["CidrIp"] in ANY_IP for r in rule.get("IpRanges", []))
                    or any(r["CidrIpv6"] in ANY_IP for r in rule.get("Ipv6Ranges", []))
                )

                if not open_to_world:
                    continue

                # Protocol -1 means all traffic — instant fail
                if protocol == "-1":
                    findings.append(Finding(
                        service="EC2/SG",
                        resource=label,
                        status="FAIL",
                        message="all traffic allowed inbound from 0.0.0.0/0",
                        detail={"rule": rule},
                    ))
                    continue

                # Check if any sensitive port falls within the rule's port range
                port_range = range(from_port, to_port + 1) if from_port != -1 else range(0, 65536)
                exposed = SENSITIVE_PORTS & set(port_range)

                if exposed:
                    findings.append(Finding(
                        service="EC2/SG",
                        resource=label,
                        status="FAIL",
                        message=f"port(s) {sorted(exposed)} open to 0.0.0.0/0",
                        detail={"exposed_ports": sorted(exposed), "rule": rule},
                    ))

    # If we found at least one failing SG, don't add a blanket PASS
    if not any(f.service == "EC2/SG" for f in findings):
        findings.append(Finding(
            service="EC2/SG",
            resource="all security groups",
            status="PASS",
            message="no sensitive ports open to the world",
        ))

    return findings


def _check_ebs_encryption(client) -> List[Finding]:
    """List any EBS volumes that aren't encrypted."""
    findings: List[Finding] = []

    try:
        paginator = client.get_paginator("describe_volumes")
        pages = paginator.paginate()
    except ClientError as e:
        logger.warning("Couldn't list EBS volumes: %s", e)
        return findings

    unencrypted = []
    for page in pages:
        for vol in page["Volumes"]:
            if not vol.get("Encrypted", False):
                unencrypted.append(vol["VolumeId"])

    if unencrypted:
        for vol_id in unencrypted:
            findings.append(Finding(
                service="EBS",
                resource=vol_id,
                status="FAIL",
                message="volume is not encrypted at rest",
            ))
    else:
        findings.append(Finding(
            service="EBS",
            resource="all volumes",
            status="PASS",
            message="all EBS volumes are encrypted",
        ))

    return findings
