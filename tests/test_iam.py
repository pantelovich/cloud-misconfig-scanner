"""
Tests for the IAM checks.
"""

from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from scanner.checks.iam import _check_wildcard_policies, _check_root_mfa


def _make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "test"}}, "op")


class TestWildcardPolicies:
    def _make_paginator(self, policies):
        """Helper to build a mock paginator that yields one page."""
        paginator = MagicMock()
        paginator.paginate.return_value = iter([{"Policies": policies}])
        return paginator

    def test_fail_on_star_action(self):
        client = MagicMock()
        client.get_paginator.return_value = self._make_paginator([
            {"PolicyName": "DangerousPolicy", "Arn": "arn:aws:iam::123:policy/DangerousPolicy", "DefaultVersionId": "v1"},
        ])
        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }
        findings = _check_wildcard_policies(client, include_aws_managed=False)
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "DangerousPolicy" == findings[0].resource

    def test_fail_on_service_wildcard(self):
        client = MagicMock()
        client.get_paginator.return_value = self._make_paginator([
            {"PolicyName": "S3FullPolicy", "Arn": "arn:aws:iam::123:policy/S3FullPolicy", "DefaultVersionId": "v1"},
        ])
        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                }
            }
        }
        findings = _check_wildcard_policies(client, include_aws_managed=False)
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_pass_on_scoped_actions(self):
        client = MagicMock()
        client.get_paginator.return_value = self._make_paginator([
            {"PolicyName": "ReadOnlyS3", "Arn": "arn:aws:iam::123:policy/ReadOnlyS3", "DefaultVersionId": "v1"},
        ])
        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]
                }
            }
        }
        findings = _check_wildcard_policies(client, include_aws_managed=False)
        assert findings == []

    def test_deny_wildcard_not_flagged(self):
        """Deny statements with wildcards shouldn't be flagged — that's actually fine."""
        client = MagicMock()
        client.get_paginator.return_value = self._make_paginator([
            {"PolicyName": "DenyAll", "Arn": "arn:aws:iam::123:policy/DenyAll", "DefaultVersionId": "v1"},
        ])
        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
                }
            }
        }
        findings = _check_wildcard_policies(client, include_aws_managed=False)
        assert findings == []


class TestRootMFA:
    def test_fail_when_mfa_disabled(self):
        client = MagicMock()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        findings = _check_root_mfa(client)
        assert len(findings) == 1
        assert findings[0].status == "WARN"
        assert "root" in findings[0].resource

    def test_pass_when_mfa_enabled(self):
        client = MagicMock()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        findings = _check_root_mfa(client)
        assert len(findings) == 1
        assert findings[0].status == "PASS"
