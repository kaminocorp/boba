"""Tests for the scope engine."""

from boba.core.models import ScopeAction, ScopeConfig, ScopeRule, ScopeRuleType
from boba.core.scope import ScopeEngine


class TestDomainMatching:
    def test_wildcard_matches_subdomain(self, scope_engine):
        assert scope_engine.is_in_scope("api.example.com") is True

    def test_wildcard_matches_deep_subdomain(self, scope_engine):
        assert scope_engine.is_in_scope("deep.sub.example.com") is True

    def test_bare_domain_matches(self, scope_engine):
        assert scope_engine.is_in_scope("example.com") is True

    def test_exclusion_wins(self, scope_engine):
        assert scope_engine.is_in_scope("internal.example.com") is False

    def test_unrelated_domain_rejected(self, scope_engine):
        assert scope_engine.is_in_scope("evil.com") is False

    def test_similar_domain_rejected(self, scope_engine):
        """notexample.com should NOT match *.example.com."""
        assert scope_engine.is_in_scope("notexample.com") is False

    def test_url_extracts_hostname(self, scope_engine):
        assert scope_engine.is_in_scope("https://api.example.com/path") is True

    def test_url_out_of_scope(self, scope_engine):
        assert scope_engine.is_in_scope("https://evil.com/path") is False

    def test_host_with_port(self, scope_engine):
        assert scope_engine.is_in_scope("api.example.com:8443") is True


class TestIPMatching:
    def test_ip_in_range(self):
        config = ScopeConfig(
            rules=[ScopeRule("192.168.1.0/24", ScopeRuleType.IP_RANGE, ScopeAction.INCLUDE)]
        )
        engine = ScopeEngine(config)
        assert engine.is_in_scope("192.168.1.50", entity_type="ip") is True
        assert engine.is_in_scope("192.168.2.1", entity_type="ip") is False

    def test_ip_exclusion(self):
        config = ScopeConfig(
            rules=[
                ScopeRule("10.0.0.0/8", ScopeRuleType.IP_RANGE, ScopeAction.INCLUDE),
                ScopeRule("10.0.0.1", ScopeRuleType.IP_RANGE, ScopeAction.EXCLUDE),
            ]
        )
        engine = ScopeEngine(config)
        assert engine.is_in_scope("10.0.0.2", entity_type="ip") is True
        assert engine.is_in_scope("10.0.0.1", entity_type="ip") is False


class TestURLPrefixMatching:
    def test_url_prefix_in_scope(self):
        config = ScopeConfig(
            rules=[
                ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
                ScopeRule(
                    "https://app.example.com/*", ScopeRuleType.URL_PREFIX, ScopeAction.INCLUDE
                ),
            ]
        )
        engine = ScopeEngine(config)
        assert engine.is_in_scope("https://app.example.com/dashboard") is True

    def test_url_prefix_exclusion(self):
        config = ScopeConfig(
            rules=[
                ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
                ScopeRule(
                    "https://app.example.com/admin", ScopeRuleType.URL_PREFIX, ScopeAction.EXCLUDE
                ),
            ]
        )
        engine = ScopeEngine(config)
        assert engine.is_in_scope("https://app.example.com/admin/settings") is False
        assert engine.is_in_scope("https://app.example.com/dashboard") is True


class TestFilterTargets:
    def test_filter_splits_correctly(self, scope_engine):
        targets = ["api.example.com", "evil.com", "internal.example.com", "app.example.com"]
        in_scope, out_of_scope = scope_engine.filter_targets(targets)
        assert set(in_scope) == {"api.example.com", "app.example.com"}
        assert set(out_of_scope) == {"evil.com", "internal.example.com"}


class TestURLPrefixBoundary:
    """URL prefix matching must not bleed into adjacent hostnames."""

    def _engine(self, prefix: str, action=ScopeAction.INCLUDE):
        rules = [
            ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ScopeRule(prefix, ScopeRuleType.URL_PREFIX, action),
        ]
        return ScopeEngine(ScopeConfig(rules=rules))

    def test_prefix_does_not_match_cross_domain(self):
        """https://example.com prefix must NOT match https://example.com.evil.com."""
        engine = self._engine("https://example.com")
        assert engine.is_in_scope("https://example.com.evil.com/path") is False

    def test_prefix_matches_with_path_separator(self):
        engine = self._engine("https://app.example.com")
        assert engine.is_in_scope("https://app.example.com/dashboard") is True

    def test_prefix_matches_with_query_string(self):
        engine = self._engine("https://app.example.com")
        assert engine.is_in_scope("https://app.example.com?foo=bar") is True

    def test_prefix_matches_exact(self):
        engine = self._engine("https://app.example.com")
        assert engine.is_in_scope("https://app.example.com") is True

    def test_prefix_matches_with_port(self):
        engine = self._engine("https://app.example.com")
        assert engine.is_in_scope("https://app.example.com:8443/path") is True

    def test_prefix_exclusion_cross_domain_not_excluded(self):
        """Exclusion prefix must also respect boundary."""
        engine = self._engine("https://example.com/admin", action=ScopeAction.EXCLUDE)
        # example.com.evil.com should not be affected by the exclusion
        # (but also rejected by domain check — just verify no crash)
        assert engine.is_in_scope("https://example.com.evil.com/admin") is False


class TestDefaultDeny:
    def test_empty_scope_denies_all(self):
        engine = ScopeEngine(ScopeConfig())
        assert engine.is_in_scope("anything.com") is False
