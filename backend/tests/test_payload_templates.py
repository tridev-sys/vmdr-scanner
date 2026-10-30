"""Payload DAST templates: discovery, the -dast flag, and the vendored set shipped in the repo."""

from pathlib import Path

import pytest


def test_payload_dirs_empty_when_missing(tmp_path):
    from app.services.nuclei import payload_template_dirs
    assert payload_template_dirs(tmp_path / "absent") == []


def test_payload_dirs_empty_without_yaml(tmp_path):
    from app.services.nuclei import payload_template_dirs
    (tmp_path / "xss").mkdir()
    (tmp_path / "xss" / "README.md").write_text("no templates")
    assert payload_template_dirs(tmp_path) == []


def test_payload_dirs_returns_root_when_templates_present(tmp_path):
    from app.services.nuclei import payload_template_dirs
    (tmp_path / "lfi").mkdir()
    (tmp_path / "lfi" / "x.yaml").write_text("id: x\n")
    assert payload_template_dirs(tmp_path) == [str(tmp_path)]


@pytest.fixture()
def cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("VMDR_NUCLEI_BIN", "/bin/nuclei")
    from app import config
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def test_build_command_adds_dast_only_when_asked(cfg, tmp_path):
    from app.services.nuclei import build_command
    targets, out = tmp_path / "t.txt", tmp_path / "o.jsonl"
    plain = build_command(targets, out, ["high"], templates=["/x"])
    dast = build_command(targets, out, ["high"], templates=["/x"], dast=True)
    assert "-dast" not in plain
    assert "-dast" in dast
    assert dast[dast.index("-t") + 1] == "/x"


def test_vendored_payload_set_is_complete_and_pinned():
    root = Path(__file__).resolve().parent.parent / "payload-templates"
    assert (root / "PIN.txt").is_file()
    pin = (root / "PIN.txt").read_text()
    assert "commit: 5585787b43e6f7242fcbb706688f9528be63e29f" in pin
    for family in ("lfi", "sqli", "xss", "ssti", "ssrf", "cmdi"):
        assert any((root / family).rglob("*.yaml")), f"no {family} templates vendored"
    # Every vendored template must declare DAST fuzzing, or -dast would skip it silently.
    for path in root.rglob("*.yaml"):
        assert "fuzzing:" in path.read_text(), f"{path.name} has no fuzzing block"
