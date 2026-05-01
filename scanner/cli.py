"""
Entry point for the scanner.

Usage:
    python -m scanner.cli
    python -m scanner.cli --profile my-profile --region eu-west-2
    python -m scanner.cli --profile my-profile --region eu-west-2 --output report.json
"""

import argparse
import logging
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from scanner import __version__
from scanner.checks import cloudtrail, ec2, iam, s3
from scanner.reporter import print_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cloud-misconfig-scanner",
        description="Audit your AWS account for common security misconfigurations.",
    )
    parser.add_argument(
        "--profile",
        default="default",
        help="AWS profile to use (default: default)",
    )
    parser.add_argument(
        "--region",
        default="eu-west-2",
        help="AWS region to scan (default: eu-west-2)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path for the JSON report output (default: auto-generated filename)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show debug logs",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s  %(name)s — %(message)s",
    )

    # Set up the boto3 session
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        # Quick check that credentials are actually valid before we start
        session.client("sts").get_caller_identity()
    except ProfileNotFound:
        print(f"Error: AWS profile '{args.profile}' not found.", file=sys.stderr)
        return 1
    except NoCredentialsError:
        print("Error: no AWS credentials found. Configure them via ~/.aws/credentials or environment variables.", file=sys.stderr)
        return 1
    except ClientError as e:
        print(f"Error: couldn't authenticate with AWS — {e}", file=sys.stderr)
        return 1

    # Run all checks
    findings = []
    findings.extend(s3.run(session))
    findings.extend(iam.run(session))
    findings.extend(ec2.run(session))
    findings.extend(cloudtrail.run(session))

    # Output
    print_report(
        findings=findings,
        profile=args.profile,
        region=args.region,
        output_path=args.output,
    )

    # Exit 1 if there are any FAILs so CI pipelines can pick this up
    has_failures = any(f.status == "FAIL" for f in findings)
    return 1 if has_failures else 0


if __name__ == "__main__":
    sys.exit(main())
