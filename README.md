# cloud-misconfig-scanner

A CLI tool I built to audit AWS accounts for common security misconfigurations. After working through a few cloud security labs and reading way too many breach post-mortems, I kept seeing the same mistakes come up over and over — public S3 buckets, overly permissive IAM, security groups left wide open. So I wrote this to catch them automatically.

It outputs a colour-coded report straight to the terminal and saves a JSON file you can feed into other tooling if needed.

---

## What it checks

| Check | Description |
|-------|-------------|
| S3 public access | Flags buckets with public ACLs or overly permissive bucket policies |
| IAM wildcard policies | Finds attached policies that grant `*:*` or `Action: *` |
| Root MFA | Warns if the root account doesn't have MFA enabled |
| Open security groups | Finds SGs allowing `0.0.0.0/0` inbound on risky ports (22, 3389, etc.) |
| Unencrypted EBS volumes | Lists EBS volumes that aren't encrypted at rest |
| CloudTrail | Checks whether CloudTrail is active in the target region |

---

## Getting started

### Prerequisites

- Python 3.9+
- AWS credentials configured (via `~/.aws/credentials` or environment variables)
- At minimum, read-only access to S3, IAM, EC2, and CloudTrail

### Install

```bash
git clone https://github.com/Pantelovich/cloud-misconfig-scanner.git
cd cloud-misconfig-scanner
make install
```

### Run

```bash
# Scan using your default AWS profile
make run

# Or run directly with options
python -m scanner.cli --profile my-profile --region eu-west-2

# Save the JSON report to a specific path
python -m scanner.cli --profile my-profile --region eu-west-2 --output report.json
```

---

## Example output

```
╔══════════════════════════════════════════════╗
║        AWS Misconfiguration Scanner          ║
╚══════════════════════════════════════════════╝

Profile : default
Region  : eu-west-2

[S3]
  ✗ FAIL  my-public-bucket         — public access not blocked (ACL: public-read)
  ✓ PASS  my-private-bucket

[IAM]
  ✗ FAIL  AdminPolicy              — wildcard action found: {"Action": "*"}
  ✗ WARN  root account             — MFA not enabled on root

[EC2 — Security Groups]
  ✗ FAIL  sg-0abc1234 (web-sg)    — port 22 open to 0.0.0.0/0

[EBS]
  ✓ PASS  all volumes encrypted

[CloudTrail]
  ✓ PASS  trail active: management-events

Summary: 3 FAIL  1 WARN  2 PASS
Report saved → misconfig_report_20250501_140322.json
```

---

## Development

```bash
make install-dev   # installs dev dependencies (pytest, flake8, etc.)
make lint          # runs flake8
make test          # runs pytest
make run           # scans using default profile + eu-west-2
```

---

## Project structure

```
cloud-misconfig-scanner/
├── scanner/
│   ├── cli.py          # entry point, argument parsing
│   ├── checks/         # one module per AWS service
│   │   ├── s3.py
│   │   ├── iam.py
│   │   ├── ec2.py
│   │   └── cloudtrail.py
│   └── reporter.py     # terminal output + JSON serialisation
├── tests/
├── docs/
│   └── adr-001-architecture.md
├── .github/workflows/ci.yml
├── Makefile
└── requirements.txt
```

---

## Architecture decisions

See [`docs/adr-001-architecture.md`](docs/adr-001-architecture.md) for the reasoning behind the structure.

---

## Things I'd add next

- [ ] Support for more checks: unused IAM keys, public RDS snapshots, VPC flow logs disabled
- [ ] HTML report output
- [ ] Multi-region scanning in one run
- [ ] Severity scoring / risk weighting
- [ ] Slack/email alerting on critical findings

---

## Licence

MIT
