"""HttpClient — async HTTP client for crafted requests (Burp Repeater/Intruder)."""

from __future__ import annotations

import asyncio
import itertools
import time
from typing import Any

import httpx

from boba.core.models import CompareResult, FuzzAttackType, FuzzResult, HttpResponse
from boba.interaction.history import HttpHistorySink

# Marker for fuzz injection positions
FUZZ_MARKER = "§"


class HttpClient:
    """Stateless HTTP client for crafted requests.

    Every request/response is persisted to http_history via the sink.
    """

    def __init__(self, sink: HttpHistorySink):
        self._sink = sink

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout_seconds: float = 30.0,
        verify_ssl: bool = False,
        proxy: str | None = None,
        source: str = "http_client",
        session_name: str | None = None,
        parent_request_id: int | None = None,
        tags: list[str] | None = None,
    ) -> HttpResponse:
        """Send an HTTP request and persist to history."""
        start = time.monotonic()
        redirect_chain: list[str] = []

        transport_kwargs: dict[str, Any] = {}
        if proxy:
            transport_kwargs["proxy"] = proxy

        async with httpx.AsyncClient(
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout_seconds,
            **transport_kwargs,
        ) as client:
            content = body.encode("utf-8") if isinstance(body, str) else body
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
                cookies=cookies,
            )

            # Track redirect chain
            if resp.history:
                redirect_chain = [str(r.url) for r in resp.history]

        elapsed_ms = (time.monotonic() - start) * 1000
        resp_headers = dict(resp.headers)
        resp_body = resp.content

        record_id = self._sink.record(
            method=method,
            url=str(resp.url) if follow_redirects else url,
            request_headers=headers or {},
            request_body=body,
            status_code=resp.status_code,
            response_headers=resp_headers,
            response_body=resp_body,
            elapsed_ms=elapsed_ms,
            source=source,
            session_name=session_name,
            parent_request_id=parent_request_id,
            tags=tags,
        )

        return HttpResponse(
            request_id=record_id,
            status_code=resp.status_code,
            headers=resp_headers,
            body=resp_body,
            body_text=resp.text[:8192] if resp.text else "",
            elapsed_ms=elapsed_ms,
            redirect_chain=redirect_chain,
        )

    async def replay(
        self,
        request_id: int,
        modifications: dict[str, Any] | None = None,
    ) -> HttpResponse:
        """Replay a request from HTTP history with optional modifications."""
        record = self._sink.get(request_id)
        if not record:
            raise ValueError(f"Request {request_id} not found in HTTP history")

        mods = modifications or {}
        method = mods.get("method", record["method"])
        url = mods.get("url", record["url"])
        headers = mods.get("headers", record.get("request_headers", {}))
        body = mods.get("body", record.get("request_body"))
        cookies = mods.get("cookies")

        return await self.request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            cookies=cookies,
            source="replay",
            parent_request_id=request_id,
        )

    async def compare(
        self,
        response_id_a: int,
        response_id_b: int,
    ) -> CompareResult:
        """Diff two responses from HTTP history."""
        a = self._sink.get(response_id_a)
        b = self._sink.get(response_id_b)
        if not a or not b:
            raise ValueError("One or both response IDs not found")

        status_a = a.get("status_code") or 0
        status_b = b.get("status_code") or 0

        # Header diff
        headers_a = a.get("response_headers", {})
        headers_b = b.get("response_headers", {})
        header_diffs = []
        all_keys = set(list(headers_a.keys()) + list(headers_b.keys()))
        for key in sorted(all_keys):
            va = headers_a.get(key)
            vb = headers_b.get(key)
            if va != vb:
                header_diffs.append({"header": key, "a": va, "b": vb})

        # Body diff summary
        body_a = a.get("response_body") or ""
        body_b = b.get("response_body") or ""
        len_a = a.get("response_length") or len(body_a)
        len_b = b.get("response_length") or len(body_b)

        if body_a == body_b:
            body_summary = "identical"
        else:
            lines_a = body_a.splitlines() if isinstance(body_a, str) else []
            lines_b = body_b.splitlines() if isinstance(body_b, str) else []
            diff_lines = sum(1 for la, lb in zip(lines_a, lines_b) if la != lb)
            diff_lines += abs(len(lines_a) - len(lines_b))
            body_summary = f"{diff_lines} lines differ (length: {len_a} vs {len_b})"

        timing_a = a.get("elapsed_ms") or 0
        timing_b = b.get("elapsed_ms") or 0

        return CompareResult(
            status_match=(status_a == status_b),
            status_a=status_a,
            status_b=status_b,
            header_diffs=header_diffs,
            body_diff_summary=body_summary,
            body_length_a=len_a,
            body_length_b=len_b,
            timing_diff_ms=abs(timing_a - timing_b),
        )

    async def fuzz(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        positions: list[str] | None = None,
        payloads: dict[str, list[str]] | None = None,
        attack_type: FuzzAttackType = FuzzAttackType.SNIPER,
        rate_limit: int = 10,
        cookies: dict[str, str] | None = None,
        session_name: str | None = None,
    ) -> FuzzResult:
        """Systematic parameter fuzzing (Burp Intruder equivalent).

        positions: list of position names to inject into (marked with § in url/body)
        payloads: dict mapping position name to payload list
        """
        if not positions or not payloads:
            return FuzzResult()

        # Generate payload combinations based on attack type
        combinations = self._generate_combinations(positions, payloads, attack_type)

        results: list[dict[str, Any]] = []
        baseline_status = 0
        baseline_length = 0

        for i, combo in enumerate(combinations):
            # Apply payloads to template
            fuzzed_url = url
            fuzzed_body = body
            for pos_name, payload in combo.items():
                marker = f"{FUZZ_MARKER}{pos_name}{FUZZ_MARKER}"
                fuzzed_url = fuzzed_url.replace(marker, payload)
                if fuzzed_body:
                    fuzzed_body = fuzzed_body.replace(marker, payload)

            resp = await self.request(
                method=method,
                url=fuzzed_url,
                headers=headers,
                body=fuzzed_body,
                cookies=cookies,
                source="fuzz",
                session_name=session_name,
                tags=["fuzz"],
            )

            entry = {
                "index": i,
                "payloads": combo,
                "status_code": resp.status_code,
                "body_length": len(resp.body),
                "elapsed_ms": resp.elapsed_ms,
                "request_id": resp.request_id,
            }
            results.append(entry)

            # First result is baseline
            if i == 0:
                baseline_status = resp.status_code
                baseline_length = len(resp.body)

            # Rate limiting
            if rate_limit > 0 and i < len(combinations) - 1:
                await asyncio.sleep(1.0 / rate_limit)

        # Detect anomalies: responses that differ from baseline
        anomalies = []
        for entry in results:
            is_anomaly = (
                entry["status_code"] != baseline_status
                or abs(entry["body_length"] - baseline_length) > max(50, baseline_length * 0.1)
            )
            if is_anomaly:
                anomalies.append(entry)

        return FuzzResult(
            total_requests=len(results),
            results=results,
            anomalies=anomalies,
            baseline_status=baseline_status,
            baseline_length=baseline_length,
        )

    def _generate_combinations(
        self,
        positions: list[str],
        payloads: dict[str, list[str]],
        attack_type: FuzzAttackType,
    ) -> list[dict[str, str]]:
        """Generate payload combinations based on attack type."""
        if attack_type == FuzzAttackType.SNIPER:
            # One position at a time, cycle payloads for each
            combos = []
            for pos in positions:
                for payload in payloads.get(pos, []):
                    combo = {p: "" for p in positions}
                    combo[pos] = payload
                    combos.append(combo)
            return combos

        elif attack_type == FuzzAttackType.BATTERING_RAM:
            # All positions get same payload
            all_payloads = payloads.get(positions[0], [])
            return [{pos: p for pos in positions} for p in all_payloads]

        elif attack_type == FuzzAttackType.PITCHFORK:
            # Positions paired by index
            payload_lists = [payloads.get(pos, []) for pos in positions]
            return [
                dict(zip(positions, vals))
                for vals in zip(*payload_lists)
            ]

        elif attack_type == FuzzAttackType.CLUSTER_BOMB:
            # Cartesian product
            payload_lists = [payloads.get(pos, [""]) for pos in positions]
            return [
                dict(zip(positions, vals))
                for vals in itertools.product(*payload_lists)
            ]

        return []
