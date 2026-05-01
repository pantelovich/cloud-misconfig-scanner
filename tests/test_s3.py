"""
Tests for the S3 checks.

Using moto to mock AWS — no real credentials needed.
"""

from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from scanner.checks.s3 import run, _check_public_access_block, _check_bucket_policy


def _make_client_error(code: str, message: str = "test error") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "operation",
    )


class TestPublicAccessBlock:
    def test_pass_when_all_blocked(self):
        client = MagicMock()
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        findings = _check_public_access_block(client, "my-private-bucket")
        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_fail_when_block_missing(self):
        client = MagicMock()
        client.get_public_access_block.side_effect = _make_client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        findings = _check_public_access_block(client, "my-public-bucket")
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "no public access block" in findings[0].message

    def test_fail_when_some_settings_off(self):
        client = MagicMock()
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,  # this one is off
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,  # this one too
            }
        }
        findings = _check_public_access_block(client, "partially-blocked-bucket")
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "IgnorePublicAcls" in findings[0].message


class TestBucketPolicy:
    def test_no_policy_returns_no_findings(self):
        client = MagicMock()
        client.get_bucket_policy.side_effect = _make_client_error("NoSuchBucketPolicy")
        findings = _check_bucket_policy(client, "no-policy-bucket")
        assert findings == []

    def test_fail_on_public_principal(self):
        import json
        client = MagicMock()
        client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*",
                }]
            })
        }
        findings = _check_bucket_policy(client, "public-bucket")
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Principal: *" in findings[0].message

    def test_pass_on_restricted_policy(self):
        import json
        client = MagicMock()
        client.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::private-bucket/*",
                }]
            })
        }
        findings = _check_bucket_policy(client, "private-bucket")
        assert findings == []


class TestRunFunction:
    def test_run_returns_findings_for_each_bucket(self):
        session = MagicMock()
        mock_s3 = MagicMock()
        session.client.return_value = mock_s3

        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]
        }
        # All buckets fully blocked, no policies
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_policy.side_effect = _make_client_error("NoSuchBucketPolicy")

        findings = run(session)
        # 2 buckets × 1 PASS finding each from public access block check
        assert len(findings) == 2
        assert all(f.status == "PASS" for f in findings)
