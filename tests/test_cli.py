"""Tests for the CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ioc_hunter import cli
from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict

runner = CliRunner()


def _verdict(
    ioc: IOC,
    verdict: Verdict = Verdict.MALICIOUS,
    *,
    confidence: float = 0.92,
    sources: tuple[str, ...] = ("vt", "abuseipdb", "otx"),
    tags: tuple[str, ...] = ("apt", "phishing"),
) -> IOCVerdict:
    results = tuple(
        SourceResult(
            source=name,
            ioc_type=ioc.type,
            ioc_value=ioc.value,
            verdict=verdict,
            score=0.9,
            tags=tags,
        )
        for name in sources
    )
    return IOCVerdict(
        ioc=ioc,
        verdict=verdict,
        confidence=confidence,
        results=results,
        tags=tags,
    )


class _FakeEngine:
    def __init__(self, verdict_map: dict[str, IOCVerdict]) -> None:
        self._verdicts = verdict_map
        self.active_sources = ["vt", "abuseipdb"]

    async def lookup_one(self, ioc: IOC) -> IOCVerdict:
        return self._verdicts.get(ioc.value, _verdict(ioc, Verdict.UNKNOWN))

    async def lookup_many(self, iocs):
        return [await self.lookup_one(ioc) for ioc in iocs]


@pytest.fixture
def patch_engine(monkeypatch):
    """Swap `_build_engine` with a fake that returns prepared verdicts."""

    def _patch(verdicts: dict[str, IOCVerdict]) -> None:
        engine = _FakeEngine(verdicts)
        monkeypatch.setattr(cli, "_build_engine", lambda *a, **kw: engine)

    return _patch


@pytest.fixture(autouse=True)
def _isolate_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)


def test_version_flag() -> None:
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "ioc-hunter" in result.stdout


def test_check_with_malicious_verdict(patch_engine) -> None:
    ioc = IOC(value="1.2.3.4", type=IOCType.IPV4)
    patch_engine({"1.2.3.4": _verdict(ioc, Verdict.MALICIOUS, confidence=0.92)})
    result = runner.invoke(cli.app, ["check", "1.2.3.4", "--no-cache"])
    assert result.exit_code == 0
    assert "MALICIOUS" in result.stdout
    # IP should be defanged in output for safety.
    assert "1[.]2[.]3[.]4" in result.stdout


def test_check_accepts_defanged_input(patch_engine) -> None:
    ioc = IOC(value="1.2.3.4", type=IOCType.IPV4)
    patch_engine({"1.2.3.4": _verdict(ioc, Verdict.MALICIOUS, confidence=0.92)})
    result = runner.invoke(cli.app, ["check", "1[.]2[.]3[.]4", "--no-cache"])
    assert result.exit_code == 0
    assert "MALICIOUS" in result.stdout


def test_check_unparseable_ioc_returns_1(patch_engine) -> None:
    patch_engine({})
    result = runner.invoke(cli.app, ["check", "this is not an ioc", "--no-cache"])
    assert result.exit_code == 1
    assert "Could not detect" in result.stdout


def test_check_with_type_hint(patch_engine) -> None:
    ioc = IOC(value="weirdthing", type=IOCType.DOMAIN)
    patch_engine({"weirdthing": _verdict(ioc, Verdict.BENIGN, confidence=0.6)})
    result = runner.invoke(cli.app, ["check", "weirdthing", "--type", "domain", "--no-cache"])
    assert result.exit_code == 0
    assert "BENIGN" in result.stdout


def test_check_bad_type_hint_errors() -> None:
    result = runner.invoke(cli.app, ["check", "1.2.3.4", "--type", "nonsense", "--no-cache"])
    assert result.exit_code != 0
    assert "unknown type" in result.stdout.lower() or "unknown type" in (result.stderr or "")


def test_scan_file_with_iocs(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "report.txt"
    sample.write_text("Beacon to 185[.]220[.]101[.]42 then exfil via hxxps://evil[.]com/x")
    patch_engine(
        {
            "185.220.101.42": _verdict(
                IOC(value="185.220.101.42", type=IOCType.IPV4),
                Verdict.MALICIOUS,
            ),
            "https://evil.com/x": _verdict(
                IOC(value="https://evil.com/x", type=IOCType.URL),
                Verdict.MALICIOUS,
            ),
            "evil.com": _verdict(
                IOC(value="evil.com", type=IOCType.DOMAIN),
                Verdict.MALICIOUS,
            ),
        }
    )
    result = runner.invoke(cli.app, ["scan-file", str(sample), "--no-cache"])
    assert result.exit_code == 0
    assert "Extracted" in result.stdout
    assert "MALICIOUS" in result.stdout


def test_scan_file_with_no_iocs(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "empty.txt"
    sample.write_text("just some prose, no indicators in here")
    patch_engine({})
    result = runner.invoke(cli.app, ["scan-file", str(sample), "--no-cache"])
    assert result.exit_code == 0
    assert "No IOCs" in result.stdout


def test_sources_command() -> None:
    result = runner.invoke(cli.app, ["sources"])
    assert result.exit_code == 0
    # Every source name should appear.
    for name in ("tor_exit", "urlhaus", "threatfox", "abuseipdb", "otx", "virustotal"):
        assert name in result.stdout


def test_report_markdown_to_file(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "in.txt"
    sample.write_text("Beacon to 185[.]220[.]101[.]42")
    patch_engine(
        {
            "185.220.101.42": _verdict(
                IOC(value="185.220.101.42", type=IOCType.IPV4),
                Verdict.MALICIOUS,
            ),
        }
    )
    out_path = tmp_path / "report.md"
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(sample),
            "--format",
            "markdown",
            "--out",
            str(out_path),
            "--no-cache",
        ],
    )
    assert result.exit_code == 0
    body = out_path.read_text()
    assert "# IOC Hunter Report" in body
    assert "185[.]220[.]101[.]42" in body


def test_report_stix_to_stdout(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "in.txt"
    sample.write_text("evil.com is dangerous")
    patch_engine(
        {"evil.com": _verdict(IOC(value="evil.com", type=IOCType.DOMAIN), Verdict.MALICIOUS)}
    )
    result = runner.invoke(
        cli.app,
        ["report", str(sample), "--format", "stix", "--no-cache"],
    )
    assert result.exit_code == 0
    assert '"type": "bundle"' in result.stdout
    assert "domain-name:value" in result.stdout


def test_report_bad_format(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "in.txt"
    sample.write_text("evil.com")
    patch_engine({})
    result = runner.invoke(
        cli.app,
        ["report", str(sample), "--format", "nope", "--no-cache"],
    )
    assert result.exit_code == 2
    assert "Unknown format" in result.stdout


def test_correlate_command(patch_engine, tmp_path: Path) -> None:
    sample = tmp_path / "in.txt"
    sample.write_text("Beacon to 185[.]220[.]101[.]42 and 185[.]220[.]101[.]99")
    ip1 = IOC(value="185.220.101.42", type=IOCType.IPV4)
    ip2 = IOC(value="185.220.101.99", type=IOCType.IPV4)
    patch_engine(
        {
            "185.220.101.42": _verdict(ip1, tags=("apt",)),
            "185.220.101.99": _verdict(ip2, tags=("apt",)),
        }
    )
    result = runner.invoke(cli.app, ["correlate", str(sample), "--no-cache"])
    assert result.exit_code == 0
    # Subnet pair should show up; tag pair should show up.
    assert "shared_subnet" in result.stdout
    assert "shared_tag" in result.stdout


def test_configure_writes_env(tmp_path: Path) -> None:
    target = tmp_path / "fresh.env"
    # Provide answers for each prompt: abuse_ch, abuseipdb, otx, virustotal, shodan
    answers = "newkey1\n\nnewotx\n\n\n"
    result = runner.invoke(
        cli.app,
        ["configure", "--env-path", str(target)],
        input=answers,
    )
    assert result.exit_code == 0
    contents = target.read_text()
    assert "ABUSE_CH_AUTH_KEY=newkey1" in contents
    assert "OTX_API_KEY=newotx" in contents
    # Skipped fields aren't written.
    assert "ABUSEIPDB_API_KEY" not in contents
