# dockerscan

A lightweight static security scanner for **Dockerfiles** and **docker-compose files**.
It checks them against a YAML rule set mapped to the CIS Docker Benchmark and OWASP
guidance, then reports each finding with a severity, a plain-language risk, and a fix.

Built for the CyberFox Society Cybersecurity R&D Internship (project area 5: Cloud & Infrastructure Security).

## Why

In Week 1 testing, Trivy, Checkov and Hadolint produced no findings on a compose file with
8 planted issues, and no single tool caught every planted Dockerfile issue. dockerscan covers
both file types with one consistent severity model and readable explanations.

## Install and run

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python -m dockerscan samples/insecure                 # text report
    python -m dockerscan samples/insecure --format json   # JSON report
    python -m dockerscan . --fail-on critical             # exit 1 only on critical findings

Exit codes: 0 = clean (or below the `--fail-on` threshold), 1 = findings at or above the threshold, 2 = usage or rule error.

## Tests

    pytest -q

## How rules work

Rules live in `dockerscan/rules/dockerfile.yml` and `compose.yml`. Each rule picks a built-in
check and supplies parameters, so many rules need no Python:

    - id: DF004
      title: ADD used with a remote URL
      severity: medium
      check: regex_instruction
      params: {instructions: [ADD], pattern: '(?:^|\s)https?://'}
      risk: ...
      fix: ...
      reference: CIS Docker Benchmark 4.9

Available checks: `no_nonroot_user`, `missing_instruction`, `unpinned_base_image`,
`secret_assignment`, `regex_instruction` (Dockerfile); `key_equals`, `list_contains_any`,
`volume_source_matches`, `secret_assignment`, `published_ports_exposed`, `key_missing`,
`list_missing_value`, `image_unpinned` (compose).

## Layout

    dockerscan/   parsers.py  checks.py  engine.py  reporters.py  cli.py  rules/
    tests/        pytest suite (31 tests)
    samples/      insecure/ and secure/ test files (all secrets are obvious fakes)
    research/     raw Trivy, Checkov and Hadolint outputs from Week 1

## Safety notes

- Static analysis only. No network access, no execution of scanned content.
- YAML is parsed with the safe loader, files over 1 MB are skipped, symlinks are not followed.
- CIS section numbers in rule references follow common numbering; verify against the benchmark version you cite.

## Known limitations (Week 2)

- DC008 (no `user:` in compose) can be a false alarm when the image already sets a non-root USER.
- The sensitive-port list is fixed in the rule file.
- HTML report, CI action and a larger evaluation come in Weeks 3 and 4.
