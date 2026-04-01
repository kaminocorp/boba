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
                try:
                    compiled = self._domain_to_regex(rule.pattern)
                except re.error as e:
                    raise ValueError(f"Invalid domain scope pattern '{rule.pattern}': {e}") from e
                if rule.action == ScopeAction.INCLUDE:
                    self._domain_includes.append(compiled)
                else:
                    self._domain_excludes.append(compiled)

            elif rule.rule_type == ScopeRuleType.IP_RANGE:
                try:
                    network = ipaddress.ip_network(rule.pattern, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid IP range scope pattern '{rule.pattern}': {e}") from e
                if rule.action == ScopeAction.INCLUDE:
                    self._ip_includes.append(network)
                else:
                    self._ip_excludes.append(network)

            elif rule.rule_type == ScopeRuleType.URL_PREFIX:
                prefix = rule.pattern.rstrip("*").rstrip("/")
                if not prefix:
                    # Bare "*" or "/" after stripping — skip, as empty prefix
                    # would match every URL via startswith("").
                    continue
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
            normalized = target if "://" in target else f"https://{target}"
            parsed = urlparse(normalized)
            hostname = parsed.hostname or ""
            # Check URL prefix exclusions/inclusions using normalized URL
            # so that scheme-less targets still match prefix rules
            url_result = self._check_url_prefix(normalized)
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
            addr = ipaddress.ip_address(self._strip_port(ip_str))
        except ValueError:
            return False
        for network in self._ip_excludes:
            if addr in network:
                return False
        for network in self._ip_includes:
            if addr in network:
                return True
        return False

    @staticmethod
    def _url_prefix_match(url: str, prefix: str) -> bool:
        """Check if *url* starts with *prefix* on a path boundary.

        A naive ``startswith`` allows ``https://example.com.evil.com`` to match
        prefix ``https://example.com``.  We require the character immediately
        after the prefix (if any) to be ``/``, ``?``, ``#``, ``:``, or end-of-
        string so that the match cannot "bleed" into a different hostname.
        """
        if not url.startswith(prefix):
            return False
        if len(url) == len(prefix):
            return True
        return url[len(prefix)] in ("/"  , "?", "#", ":")

    def _check_url_prefix(self, url: str) -> bool | None:
        """Check URL prefix rules. Returns None if no rule matched."""
        for prefix in self._url_excludes:
            if self._url_prefix_match(url, prefix):
                return False
        for prefix in self._url_includes:
            if self._url_prefix_match(url, prefix):
                return True
        return None

    @staticmethod
    def _strip_port(target: str) -> str:
        """Strip port from IP address string, handling both IPv4 and IPv6.

        Examples: '10.0.0.1:8080' → '10.0.0.1', '[::1]:443' → '::1', '::1' → '::1'
        """
        # Bracketed IPv6: [::1]:port or [::1]
        if target.startswith("["):
            bracket_end = target.find("]")
            if bracket_end != -1:
                return target[1:bracket_end]
        # IPv4 with port: exactly one colon
        if target.count(":") == 1:
            return target.split(":")[0]
        # Bare IPv6 or bare IPv4 — return as-is
        return target

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from various formats."""
        if "://" in target:
            return urlparse(target).hostname or target
        # Bracketed IPv6 with port: [::1]:8080
        if target.startswith("["):
            bracket_end = target.find("]")
            if bracket_end != -1:
                return target[1:bracket_end]
        # IPv4 with port — exactly one colon means host:port
        if target.count(":") == 1:
            return target.split(":")[0]
        return target

    @staticmethod
    def _guess_entity_type(target: str) -> str:
        # Scheme present → definitely a URL
        if "://" in target:
            return "url"
        # Strip brackets/port before attempting IP parse
        cleaned = target
        if cleaned.startswith("["):
            bracket_end = cleaned.find("]")
            if bracket_end != -1:
                cleaned = cleaned[1:bracket_end]
        elif cleaned.count(":") == 1:
            cleaned = cleaned.split(":")[0]
        # Check for IP or CIDR (e.g. 10.0.0.0/24) before treating / as URL
        try:
            ipaddress.ip_network(cleaned if "/" not in cleaned else target, strict=False)
            return "ip"
        except ValueError:
            pass
        try:
            ipaddress.ip_address(cleaned)
            return "ip"
        except ValueError:
            pass
        # Contains / but not an IP range → treat as URL path
        if "/" in target:
            return "url"
        return "subdomain"

    @classmethod
    def from_yaml(cls, path: Path | str) -> ScopeEngine:
        """Load scope config from a YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid scope YAML in {path}: expected a mapping, got {type(data).__name__}"
            )

        rules = []
        for i, r in enumerate(data.get("rules", [])):
            if not isinstance(r, dict):
                raise ValueError(f"Scope rule #{i} must be a dict, got {type(r).__name__}")
            if "pattern" not in r:
                raise ValueError(f"Scope rule #{i} missing required 'pattern' key: {r}")
            if "type" not in r:
                raise ValueError(f"Scope rule #{i} missing required 'type' key: {r}")
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
