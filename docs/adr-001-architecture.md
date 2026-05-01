# ADR 001 — Overall Architecture

**Date:** 2025-05-01  
**Status:** Accepted

---

## Context

I wanted a simple, extensible way to structure the scanner so adding new checks later doesn't mean touching a load of unrelated files. The main decision was whether to go with a flat script or split things into proper modules.

## Decision

Split checks into separate modules under `scanner/checks/`, one per AWS service. Each check module exposes a single `run(session)` function that returns a list of `Finding` objects. The CLI wires everything together and the reporter handles presentation.

This means:
- Adding a new check = create a new file, return the same `Finding` type, wire into `cli.py`. Nothing else changes.
- Tests are isolated per service — mocking boto3 for S3 doesn't affect IAM tests.
- The reporter doesn't need to know anything about what the checks do.

## Consequences

Slightly more files than a single script approach, but worth it once you get past 2–3 checks. Each module can be tested and read in isolation, which makes the project easier to explain in an interview or code review.
