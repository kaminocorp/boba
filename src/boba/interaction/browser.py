"""BrowserManager — Playwright-based browser automation with traffic interception."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from boba.core.errors import BrowserError
from boba.core.models import BrowserConfig, DOMExtraction, PageInfo, SessionState
from boba.interaction.history import HttpHistorySink

logger = logging.getLogger(__name__)


class BrowserManager:
    """Owns a Playwright browser instance and named browser contexts.

    Replaces what a human does with Chrome + Burp Proxy: browse a web app,
    intercept all traffic, interact with pages, capture evidence.
    """

    def __init__(self, config: BrowserConfig, sink: HttpHistorySink):
        self._config = config
        self._sink = sink
        self._playwright: Any = None
        self._browser: Any = None
        self._contexts: dict[str, Any] = {}
        self._pages: dict[str, Any] = {}
        self._request_counts: dict[str, int] = {}

    async def start(self) -> None:
        """Launch Playwright + Chromium."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise BrowserError(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )

        self._playwright = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": self._config.headless,
        }
        if self._config.slow_mo:
            launch_kwargs["slow_mo"] = self._config.slow_mo
        if self._config.proxy:
            launch_kwargs["proxy"] = {"server": self._config.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)

    async def stop(self) -> None:
        """Close all pages, contexts, browser, Playwright."""
        # Close pages before their parent contexts to avoid dangling handlers
        for name in list(self._pages.keys()):
            try:
                await self._pages[name].close()
            except Exception as exc:
                logger.debug("Error closing page %s: %s", name, exc)
        self._pages.clear()

        for name in list(self._contexts.keys()):
            try:
                await self._contexts[name].close()
            except Exception as exc:
                logger.debug("Error closing browser context %s: %s", name, exc)
        self._contexts.clear()
        self._request_counts.clear()

        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def __aenter__(self) -> BrowserManager:
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()

    async def get_or_create_context(
        self,
        name: str = "default",
        cookies: list[dict] | None = None,
        storage_state: dict | None = None,
    ) -> Any:
        """Get existing or create new named browser context."""
        if name in self._contexts:
            return self._contexts[name]

        if not self._browser:
            raise BrowserError("Browser not started. Call start() first.")

        ctx_kwargs: dict[str, Any] = {
            "ignore_https_errors": self._config.ignore_https_errors,
            "viewport": self._config.viewport,
        }
        if self._config.user_agent:
            ctx_kwargs["user_agent"] = self._config.user_agent
        if self._config.extra_headers:
            ctx_kwargs["extra_http_headers"] = self._config.extra_headers
        if storage_state:
            ctx_kwargs["storage_state"] = storage_state

        context = await self._browser.new_context(**ctx_kwargs)
        try:
            if cookies:
                await context.add_cookies(cookies)

            # Create a page for this context
            page = await context.new_page()
            await self._setup_interception(page, name)
        except Exception:
            await context.close()
            raise

        self._contexts[name] = context
        self._request_counts[name] = 0
        self._pages[name] = page

        return context

    async def _setup_interception(self, page: Any, context_name: str) -> None:
        """Register response handler to capture all traffic."""

        async def _on_response(response: Any) -> None:
            try:
                body = await response.body()
            except Exception as exc:
                logger.debug("Could not read response body for %s: %s", response.url, exc)
                body = None

            try:
                req_headers = await response.request.all_headers()
            except Exception as exc:
                logger.debug("Could not read request headers for %s: %s", response.url, exc)
                req_headers = {}

            try:
                resp_headers = await response.all_headers()
            except Exception as exc:
                logger.debug("Could not read response headers for %s: %s", response.url, exc)
                resp_headers = {}

            self._sink.record(
                method=response.request.method,
                url=response.url,
                request_headers=req_headers,
                request_body=response.request.post_data,
                status_code=response.status,
                response_headers=resp_headers,
                response_body=body,
                # Playwright timing dict values are relative to navigationStart, not
                # request-level elapsed time.  We cannot reliably compute per-request
                # elapsed inside the response handler, so record 0 and let callers
                # use navigate()'s wall-clock timing for page-level latency.
                elapsed_ms=0,
                source="browser",
                session_name=context_name if context_name != "default" else None,
                resource_type=response.request.resource_type,
            )
            self._request_counts[context_name] = (
                self._request_counts.get(context_name, 0) + 1
            )

        page.on("response", _on_response)

    async def _get_page(self, context_name: str) -> Any:
        """Get the page for a context, creating context if needed."""
        if context_name not in self._pages:
            await self.get_or_create_context(context_name)
        return self._pages[context_name]

    async def navigate(
        self,
        url: str,
        context_name: str = "default",
        wait_until: str = "networkidle",
    ) -> PageInfo:
        """Navigate to URL, wait for load, return page info."""
        page = await self._get_page(context_name)
        self._request_counts[context_name] = 0

        start = time.monotonic()
        response = await page.goto(url, wait_until=wait_until)
        elapsed = (time.monotonic() - start) * 1000

        status_code = response.status if response else 0
        headers = {}
        if response:
            try:
                headers = await response.all_headers()
            except Exception:
                pass

        cookies = await page.context.cookies()
        title = await page.title()

        return PageInfo(
            url=url,
            final_url=page.url,
            status_code=status_code,
            title=title,
            content_type=headers.get("content-type", ""),
            headers=headers,
            cookies=cookies,
            timing_ms=elapsed,
            requests_captured=self._request_counts.get(context_name, 0),
        )

    async def screenshot(
        self,
        path: str | Path,
        context_name: str = "default",
        full_page: bool = True,
    ) -> Path:
        """Capture screenshot for evidence/PoC."""
        page = await self._get_page(context_name)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(path), full_page=full_page)
        return path

    async def extract(self, context_name: str = "default") -> DOMExtraction:
        """Extract structured DOM data from current page."""
        page = await self._get_page(context_name)

        data = await page.evaluate("""() => {
            const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                    name: i.name,
                    type: i.type || 'text',
                    value: i.value || '',
                    id: i.id || '',
                }))
            }));

            const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({
                href: a.href,
                text: a.textContent?.trim().substring(0, 200) || '',
            }));

            const scripts = Array.from(document.querySelectorAll('script')).map(s => {
                if (s.src) return { src: s.src };
                // Hash inline scripts for identification
                const text = s.textContent || '';
                return { inline_length: text.length };
            });

            const meta = {};
            document.querySelectorAll('meta').forEach(m => {
                const name = m.getAttribute('name') || m.getAttribute('property') || '';
                const content = m.getAttribute('content') || '';
                if (name && content) meta[name] = content;
            });

            // Extract HTML comments
            const comments = [];
            const walker = document.createTreeWalker(
                document, NodeFilter.SHOW_COMMENT, null
            );
            while (walker.nextNode()) {
                const text = walker.currentNode.textContent?.trim();
                if (text) comments.push(text.substring(0, 500));
            }

            const inputs = Array.from(
                document.querySelectorAll('input, textarea, select')
            ).map(i => ({
                name: i.name,
                type: i.type || 'text',
                value: i.value || '',
                id: i.id || '',
                form: i.form?.action || null,
            }));

            const textContent = document.body?.innerText?.substring(0, 5000) || '';

            return { forms, links, scripts, meta, comments, inputs, textContent };
        }""")

        return DOMExtraction(
            url=page.url,
            title=await page.title(),
            forms=data.get("forms", []),
            links=data.get("links", []),
            scripts=data.get("scripts", []),
            meta=data.get("meta", {}),
            comments=data.get("comments", []),
            inputs=data.get("inputs", []),
            text_content=data.get("textContent", ""),
        )

    async def execute_js(self, script: str, context_name: str = "default") -> Any:
        """Execute JavaScript in page context."""
        page = await self._get_page(context_name)
        return await page.evaluate(script)

    async def fill_form(
        self,
        selector: str,
        values: dict[str, str],
        context_name: str = "default",
        submit: bool = False,
    ) -> None:
        """Fill form fields and optionally submit."""
        page = await self._get_page(context_name)
        for field_name, value in values.items():
            await page.fill(f"{selector} [name='{field_name}']", value)
        if submit:
            await page.click(f"{selector} [type='submit']")
            await page.wait_for_load_state("networkidle")

    async def click(self, selector: str, context_name: str = "default") -> None:
        """Click an element."""
        page = await self._get_page(context_name)
        await page.click(selector)

    async def get_cookies(self, context_name: str = "default") -> list[dict]:
        """Get all cookies for a context."""
        if context_name not in self._contexts:
            return []
        return await self._contexts[context_name].cookies()

    async def set_cookies(
        self, cookies: list[dict], context_name: str = "default"
    ) -> None:
        """Set cookies on a context."""
        ctx = await self.get_or_create_context(context_name)
        await ctx.add_cookies(cookies)

    async def get_storage_state(self, context_name: str = "default") -> dict:
        """Get full storage state (cookies + localStorage) for session persistence."""
        if context_name not in self._contexts:
            return {}
        return await self._contexts[context_name].storage_state()

    async def apply_session(self, session: SessionState) -> None:
        """Apply a SessionState to a browser context named after the session."""
        cookies_list = [
            {"name": k, "value": v, "url": session.target_url}
            for k, v in session.cookies.items()
        ]
        ctx_kwargs: dict[str, Any] = {}
        if session.storage_state:
            ctx_kwargs["storage_state"] = session.storage_state

        await self.get_or_create_context(
            name=session.name,
            cookies=cookies_list if cookies_list else None,
            storage_state=session.storage_state,
        )

        # Set extra headers if present
        if session.headers:
            ctx = self._contexts[session.name]
            await ctx.set_extra_http_headers(session.headers)
