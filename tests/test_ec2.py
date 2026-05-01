"""
Tests for the EC2 checks (security groups + EBS encryption).
"""

from unittest.mock import MagicMock

from scanner.checks.ec2 import _check_security_groups, _check_ebs_encryption


def _make_paginator(pages):
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


class TestSecurityGroups:
    def test_fail_on_ssh_open_to_world(self):
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "SecurityGroups": [{
                "GroupId": "sg-001",
                "GroupName": "web-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }])
        findings = _check_security_groups(client)
        fails = [f for f in findings if f.status == "FAIL"]
        assert len(fails) == 1
        assert "22" in fails[0].message

    def test_fail_on_all_traffic_rule(self):
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "SecurityGroups": [{
                "GroupId": "sg-002",
                "GroupName": "bad-sg",
                "IpPermissions": [{
                    "IpProtocol": "-1",  # all traffic
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }])
        findings = _check_security_groups(client)
        fails = [f for f in findings if f.status == "FAIL"]
        assert len(fails) == 1
        assert "all traffic" in fails[0].message

    def test_pass_on_restricted_sg(self):
        client = MagicMock()
        # Port 22 open but only to a specific IP, not the world
        client.get_paginator.return_value = _make_paginator([{
            "SecurityGroups": [{
                "GroupId": "sg-003",
                "GroupName": "restricted-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.1/32"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }])
        findings = _check_security_groups(client)
        assert all(f.status != "FAIL" for f in findings)

    def test_pass_on_non_sensitive_port_open(self):
        """Port 80 open to the world is fine — it's a web server."""
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "SecurityGroups": [{
                "GroupId": "sg-004",
                "GroupName": "web-public",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }])
        findings = _check_security_groups(client)
        assert all(f.status != "FAIL" for f in findings)


class TestEBSEncryption:
    def test_fail_on_unencrypted_volume(self):
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "Volumes": [{"VolumeId": "vol-abc123", "Encrypted": False}]
        }])
        findings = _check_ebs_encryption(client)
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].resource == "vol-abc123"

    def test_pass_when_all_encrypted(self):
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "Volumes": [
                {"VolumeId": "vol-111", "Encrypted": True},
                {"VolumeId": "vol-222", "Encrypted": True},
            ]
        }])
        findings = _check_ebs_encryption(client)
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_mixed_volumes(self):
        client = MagicMock()
        client.get_paginator.return_value = _make_paginator([{
            "Volumes": [
                {"VolumeId": "vol-good", "Encrypted": True},
                {"VolumeId": "vol-bad", "Encrypted": False},
            ]
        }])
        findings = _check_ebs_encryption(client)
        fails = [f for f in findings if f.status == "FAIL"]
        assert len(fails) == 1
        assert fails[0].resource == "vol-bad"
