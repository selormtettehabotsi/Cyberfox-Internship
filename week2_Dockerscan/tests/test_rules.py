import json
from pathlib import Path

import pytest

from dockerscan.cli import main
from dockerscan.engine import load_rules, scan_file, scan_path

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules()


def ids(findings):
    return [f.rule_id for f in findings]


def scan_text(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    kind = "compose" if name.endswith((".yml", ".yaml")) else "dockerfile"
    return scan_file(p, kind, RULES)


# ----------------------------------------------------- whole-sample tests
def test_rules_load_and_ids_unique():
    assert len(RULES) >= 15
    assert len({r.id for r in RULES}) == len(RULES)


def test_insecure_dockerfile_every_planted_issue_detected():
    findings, err = scan_file(ROOT / "samples/insecure/Dockerfile", "dockerfile", RULES)
    assert err is None
    assert set(ids(findings)) == {f"DF00{i}" for i in range(1, 9)}
    assert ids(findings).count("DF003") == 2  # ENV and ARG


def test_insecure_compose_every_planted_issue_detected():
    findings, err = scan_file(ROOT / "samples/insecure/docker-compose.yml", "compose", RULES)
    assert err is None
    assert {"DC001", "DC002", "DC003", "DC004", "DC005", "DC006", "DC011"} <= set(ids(findings))
    ports = [f for f in findings if f.rule_id == "DC005"]
    assert {f.target for f in ports} == {"db", "cache"}


def test_secure_samples_have_no_findings():
    findings, errors, scanned = scan_path(ROOT / "samples/secure", RULES)
    assert scanned == 2 and errors == []
    assert findings == []


# ----------------------------------------------------- Dockerfile edge cases
def test_multistage_only_final_stage_user_counts(tmp_path):
    text = "FROM golang:1.22 AS build\nRUN go build\nFROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n"
    findings, _ = scan_text(tmp_path, "Dockerfile", text)
    assert "DF001" not in ids(findings)


def test_explicit_root_user_flagged(tmp_path):
    findings, _ = scan_text(tmp_path, "Dockerfile", "FROM alpine:3.20\nUSER root\n")
    assert "DF001" in ids(findings)


def test_variable_secret_references_not_flagged(tmp_path):
    text = "FROM alpine:3.20\nARG TOKEN\nENV DB_PASSWORD=${DB_PASSWORD}\nUSER app\n"
    findings, _ = scan_text(tmp_path, "Dockerfile", text)
    assert "DF003" not in ids(findings)


@pytest.mark.parametrize("image, flagged", [
    ("python:3.12.4-slim", False), ("python:latest", True), ("python", True),
    ("python@sha256:" + "a" * 64, False), ("scratch", False), ("registry.local:5000/app", True),
])
def test_base_image_pinning(tmp_path, image, flagged):
    findings, _ = scan_text(tmp_path, "Dockerfile", f"FROM {image}\nUSER app\n")
    assert ("DF002" in ids(findings)) == flagged


def test_stage_reference_not_flagged_as_unpinned(tmp_path):
    text = "FROM alpine:3.20 AS base\nFROM base\nUSER app\n"
    findings, _ = scan_text(tmp_path, "Dockerfile", text)
    assert "DF002" not in ids(findings)


def test_line_continuation_and_pipe_to_shell(tmp_path):
    text = "FROM alpine:3.20\nRUN curl -fsSL https://x.example/i.sh \\\n    | sh\nUSER app\n"
    findings, _ = scan_text(tmp_path, "Dockerfile", text)
    hit = [f for f in findings if f.rule_id == "DF006"]
    assert len(hit) == 1 and hit[0].line == 2


def test_healthcheck_none_counts_as_missing(tmp_path):
    findings, _ = scan_text(tmp_path, "Dockerfile", "FROM alpine:3.20\nUSER app\nHEALTHCHECK NONE\n")
    assert "DF005" in ids(findings)


# ------------------------------------------------------- compose edge cases
@pytest.mark.parametrize("port, flagged", [
    ("5432:5432", True), ("0.0.0.0:6379:6379", True), ("127.0.0.1:5432:5432", False),
    ("[::1]:5432:5432", False), ("5432", False), ("8080:80", False), ("3306:3306/tcp", True),
])
def test_sensitive_port_publishing(tmp_path, port, flagged):
    text = f'services:\n  db:\n    image: postgres:16.3\n    user: "999"\n    security_opt: ["no-new-privileges:true"]\n    ports:\n      - "{port}"\n'
    findings, _ = scan_text(tmp_path, "docker-compose.yml", text)
    assert ("DC005" in ids(findings)) == flagged


def test_compose_dict_environment_and_long_port_syntax(tmp_path):
    text = (
        "services:\n  api:\n    image: api:1.0\n    user: '1'\n    security_opt: ['no-new-privileges:true']\n"
        "    environment:\n      API_KEY: abc123\n      MODE: prod\n"
        "    ports:\n      - target: 6379\n        published: 6379\n"
    )
    findings, _ = scan_text(tmp_path, "docker-compose.yml", text)
    assert {"DC004", "DC005"} <= set(ids(findings))


def test_compose_line_numbers_reported(tmp_path):
    text = "services:\n  web:\n    image: app:1.0\n    privileged: true\n"
    findings, _ = scan_text(tmp_path, "docker-compose.yml", text)
    priv = [f for f in findings if f.rule_id == "DC001"][0]
    assert priv.line == 4


def test_invalid_yaml_reports_error_not_crash(tmp_path):
    findings, err = scan_text(tmp_path, "docker-compose.yml", "services: [unclosed\n")
    assert findings == [] and err and "invalid YAML" in err


def test_non_mapping_compose_reports_error(tmp_path):
    _, err = scan_text(tmp_path, "docker-compose.yml", "- just\n- a list\n")
    assert err


# ------------------------------------------------------------------- CLI
def test_cli_json_output_and_exit_code(capsys):
    code = main([str(ROOT / "samples/insecure"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["summary"]["critical"] >= 2 and data["scanned_files"] == 2


def test_cli_secure_exit_zero(capsys):
    assert main([str(ROOT / "samples/secure")]) == 0


def test_cli_fail_on_never(capsys):
    assert main([str(ROOT / "samples/insecure"), "--fail-on", "never"]) == 0


def test_cli_no_files_exit_two(tmp_path, capsys):
    assert main([str(tmp_path)]) == 2
