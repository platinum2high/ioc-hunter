"""Universal binary analyser.

Subphase 14.1 ships ``analyze(path)`` over PE / ELF / Mach-O. Future
subphases plug PDF / Office / PCAP / archive analysers into the same
``AnalyzerReport`` shape so the CLI renders them with one code path.
"""

from ioc_hunter.analyze.attack_map import all_techniques
from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
    Verdict,
)
from ioc_hunter.analyze.dispatcher import analyze, detect_format
from ioc_hunter.analyze.markdown import to_markdown

__all__ = (
    "AnalyzerReport",
    "FileFormat",
    "Finding",
    "Severity",
    "Verdict",
    "all_techniques",
    "analyze",
    "detect_format",
    "to_markdown",
)
