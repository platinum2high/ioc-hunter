"""Detection-rule generators: Sigma (logsource-grouped) and Suricata."""

from ioc_hunter.rules.sigma import to_sigma
from ioc_hunter.rules.suricata import to_suricata

__all__ = ["to_sigma", "to_suricata"]
