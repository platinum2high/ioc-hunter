"""Core parsing primitives: types, defang/refang, type detection, IOC extraction."""

from ioc_hunter.core.defang import defang, refang
from ioc_hunter.core.detector import detect_type
from ioc_hunter.core.eml import EmailAttachment, EmailReport, parse_eml
from ioc_hunter.core.parser import extract_iocs
from ioc_hunter.core.types import IOC, IOCType

__all__ = [
    "IOC",
    "EmailAttachment",
    "EmailReport",
    "IOCType",
    "defang",
    "detect_type",
    "extract_iocs",
    "parse_eml",
    "refang",
]
