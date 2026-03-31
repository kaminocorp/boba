"""Scope engine — enforces target boundaries for all tool operations."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from boba.core.models import ScopeAction, ScopeConfig, ScopeRule, ScopeRuleType


class ScopeEngine:
    """
    Evaluates whether a target (domain, IP, URL) is in scope.

    Evaluation rules:
    1. If any exclusion rule matches → OUT of scope (exclusions always win)
    2. If any inclusion rule matches → IN scope
    3. If no rule matches → OUT of scope (default deny)
    """

    def __init__(self, config: ScopeConfig):
        self._config = config
        self._domain_includes: list[re.Pattern] = []
        self._domain_excludes: list[re.Pattern] = []
        self._ip_includes: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._ip_excludes: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._url_includes: list[str] = []
        self._url_excludes: list[str] = []
        self._compile()

    def _compile(self) -> None:
        """Pre-compile all rules for fast matching."""
        self._domain_includes.clear()
        self._domain_excludes.clear()
        self._ip_includes.clear()
        self._ip_excludes.clear()
        self._url_includes.clear()
        self._url_excludes.clear()

        for rule in self._config.rules:
            if rule.rule_type == ScopeRuleType.DOMAIN:
                compiled = self._domain_to_regex(rule.pattern)
                if rule.action == ScopeAction.INCLUDE:
                    self._domain_includes.append(compiled)
                else:
                    self._domain_excludes.append(compiled)

            elif rule.rule_type == ScopeRuleType.IP_RANGE:
                network = ipaddress.ip_network(rule.pattern, strict=False)
                if rule.action == ScopeAction.INCLUDE:
                    self._ip_includes.append(network)
                else:
                    self._ip_excludes.append(network)

            elif rule.rule_type == ScopeRuleType.URL_PREFIX:
                prefix = rule.pattern.rstrip("*").rstrip("/")
                if rule.action == ScopeAction.INCLUDE:
                    self._url_includes.append(prefix)
                else:
                    self._url_excludes.append(prefix)

    @staticmethod
    def _domain_to_regex(pattern: str) -> re.Pattern:
        """Convert *.example.com to regex matching example.com and any subdomain."""
        if pattern.startswith("*."):
            base = re.escape(pattern[2:])
            return re.compile(rf"^(.+\.)?{base}$", re.IGNORECASE)
        return re.compile(rf"^{re.escape(pattern)}$", re.IGNORECASE)

    def is_in_scope(self, target: str, entity_type: str = "auto") -> bool:
        """
        Check if a target is within scope.

        Args:
            target: Domain, IP, or URL to check.
            entity_type: One of "subdomain", "host", "ip", "url", or "auto".
        """
        if entity_type == "auto":
            entity_type = self._guess_entity_type(target)

        if entity_type in ("subdomain", "host", "domain"):
            hostname = self._extract_hostname(target)
            return self._check_domain(hostname)
        elif entity_type == "url":
            parsed = urlparse(target if "://" in target else f"https://{target}")
            hostname = parsed.hostname or ""
            # Check URL prefix exclusions/inclusions
            url_result = self._check_url_prefix(target)
            if url_result is not None:
                # URL prefix rule matched; domain must also pass
                if not url_result:
                    return False
                return self._check_domain(hostname)
            # No URL prefix rule matched; fall back to domain check
            return self._check_domain(hostname)
        elif entity_type == "ip":
            return self._check_ip(target)
        return False

    def filter_targets(
        self, targets: list[str], entity_type: str = "auto"
    ) -> tuple[list[str], list[str]]:
        """Split targets into (in_scope, out_of_scope)."""
        in_scope: list[str] = []
        out_of_scope: list[str] = []
        for t in targets:
            if self.is_in_scope(t, entity_type):
                in_scope.append(t)
            else:
                out_of_scope.append(t)
        return in_scope, out_of_scope

    def _check_domain(self, domain: str) -> bool:
        if not domain:
            return False
        for pattern in self._domain_excludes:
            if pattern.match(domain):
                return False
        for pattern in self._domain_includes:
            if pattern.match(domain):
                return True
        return False

    def _check_ip(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str.split(":")[0])
        except ValueError:
            return False
        for network in self._ip_excludes:
            if addr in network:
                return False
        for network in self._ip_includes:
            if addr in network:
                return True
        return False

    def _check_url_prefix(self, url: str) -> bool | None:
        """Check URL prefix rules. Returns None if no rule matched."""
        for prefix in self._url_excludes:
            if url.startswith(prefix):
                return False
        for prefix in self._url_includes:
            if url.startswith(prefix):
                return True
        return None

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from various formats."""
        if "://" in target:
            return urlparse(target).hostname or target
        if ":" in target:
            return target.split(":")[0]
        return target

    @staticmethod
    def _guess_entity_type(target: str) -> str:
        if "://" in target or "/" in target:
            return "url"
        try:
            ipaddress.ip_address(target.split(":")[0])
            return "ip"
        except ValueError:
            return "subdomain"

    @classmethod
    def from_yaml(cls, path: Path | str) -> ScopeEngine:
        """Load scope config from a YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)

        rules = []
        for r in data.get("rules", []):
            rules.append(
                ScopeRule(
                    pattern=r["pattern"],
                    rule_type=ScopeRuleType(r["type"]),
                    action=ScopeAction(r.get("action", "include")),
                )
            )
        return cls(ScopeConfig(rules=rules))

    @property
    def config(self) -> ScopeConfig:
        return self._config
