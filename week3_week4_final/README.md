# dockerscan

A lightweight static security scanner for **Dockerfiles** and **docker-compose files**.
It checks them against a YAML rule set mapped to CIS Docker Benchmark and OWASP guidance,
and reports each finding with a severity, a plain-language risk and a fix.

Built for the CyberFox Society Cybersecurity Research & Development Internship
(project area 5: Cloud & Infrastructure Security).

## Why it exists

Trivy, Checkov and Hadolint do not scan docker-compose files (Trivy's documentation lists Compose as
unsupported; in testing, none of the three produced a finding on any of 13 real compose files), and each
tool covers a different part of the Dockerfile problem. dockerscan checks both file types with one severity
model and readable explanations. It is a focused complement to those tools, not a replacement.

## Install and run

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python -m dockerscan samples/insecure                          # text report
    python -m dockerscan . --format json                           # JSON
    python -m dockerscan . --format html -o report.html            # HTML report
    python -m dockerscan . --min-severity high --fail-on critical  # filter and gate

| Option | Meaning |
|--------|---------|
| `--format text\|json\|html` | Output format (default text) |
| `-o FILE` | Write the report to a file |
| `--min-severity LEVEL` | Hide findings below this level (default: show all) |
| `--fail-on LEVEL\|never` | Exit 1 if a finding at or above this level exists (default high) |

Exit codes: 0 clean (or below threshold), 1 findings at or above the threshold, 2 usage or rule error.

## Rules (17)

| ID | Check | Severity |
|----|-------|----------|
| DF001 | Container runs as root | High |
| DF002 | Base image not pinned (none or latest tag) | Medium |
| DF003 | Secret hardcoded in ENV or ARG | High |
| DF004 | ADD used with a remote URL | Medium |
| DF005 | No HEALTHCHECK | Low |
| DF006 | Remote script piped into a shell | High |
| DF007 | sudo used or installed | Medium |
| DF008 | SSH port 22 exposed | Medium |
| DC001 | Privileged container | Critical |
| DC002 | Docker socket mounted | Critical |
| DC003 | Host network mode | High |
| DC004 | Secret hardcoded in environment | High |
| DC005 | Sensitive port published on all interfaces | High |
| DC006 | cap_add includes ALL or SYS_ADMIN | High |
| DC008 | No non-root user set for the service | Low |
| DC009 | no-new-privileges not set | Low |
| DC011 | Image not pinned (none or latest tag) | Medium |

Rules live in `dockerscan/rules/*.yml`. Each rule picks a built-in check and supplies parameters, so a rule
that reuses an existing check needs no Python. CIS section numbers follow common numbering; verify them
against the benchmark version you cite.

## Evaluation summary (28 real-world files)

Full method, manifest and raw outputs are in `evaluation/`.

- Compose files (13): Trivy, Checkov and Hadolint produced no findings. dockerscan reported 82.
- Dockerfiles (15): root user, missing HEALTHCHECK and unpinned image findings matched Trivy and Checkov
  on exactly the same files. Only dockerscan flagged a `curl | bash` install.
- Manual review: 5 of 53 verifiable findings were false positives (secret-file paths such as
  `/run/secrets/db-password` flagged as hardcoded secrets). The rule was tuned, which removed them.
  67 findings (DC008 and DC009) cannot be verified without inspecting the images, so they were
  downgraded to Low severity.
- Limits: dockerscan covers fewer Dockerfile best-practice checks than Hadolint or Trivy (for example apk
  or apt flags, `cd` in `RUN`). The review was done by the project author on the same set used to tune the
  rules, so the post-tuning precision is optimistic.

## Tests and CI

    pytest -q        # 40 tests

`.github/workflows/ci.yml` runs the tests, requires the secure samples to pass, and uploads an HTML report.
`docs/ci-example.yml` shows how to gate pull requests in your own repository.

## Layout

    dockerscan/    parsers.py  checks.py  engine.py  reporters.py  cli.py  rules/
    tests/         40 pytest tests
    samples/       insecure/ and secure/ hand-written samples (all secrets are obvious fakes)
    evaluation/    real-world test set, manifest, licences, raw tool outputs
    research/      Week 1 raw Trivy, Checkov and Hadolint outputs
    docs/          CI example

## Safety notes

- Static analysis only. No network access and no execution of scanned content.
- YAML uses the safe loader, files over 1 MB are skipped and symlinks are not followed.
- The HTML report escapes every dynamic value, has no scripts and sets a restrictive Content-Security-Policy
  meta tag. `frame-ancestors` cannot be set from a meta tag, so send it as an HTTP header if you serve the report.

## Known limitations

- DC008 can be a false alarm when the image already sets a non-root USER; compose alone cannot show this.
- Compose extends, profiles and variable interpolation are not resolved.
- The sensitive-port list and secret-name pattern are fixed in this version.
- Kubernetes, Terraform and live cloud scanning are out of scope (future work).
