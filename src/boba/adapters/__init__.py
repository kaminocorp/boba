"""Adapter registry — maps tool names to adapter classes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boba.adapters.base import BaseAdapter


def get_adapter_registry() -> dict[str, type[BaseAdapter]]:
    """Lazy import to avoid circular dependencies."""
    from boba.adapters.ffuf import FfufAdapter
    from boba.adapters.gau import GauAdapter
    from boba.adapters.httpx_runner import HttpxRunnerAdapter
    from boba.adapters.katana import KatanaAdapter
    from boba.adapters.naabu import NaabuAdapter
    from boba.adapters.subfinder import SubfinderAdapter
    from boba.adapters.waybackurls import WaybackurlsAdapter
    from boba.adapters.whatweb import WhatwebAdapter

    return {
        "subfinder": SubfinderAdapter,
        "httpx": HttpxRunnerAdapter,
        "naabu": NaabuAdapter,
        "gau": GauAdapter,
        "waybackurls": WaybackurlsAdapter,
        "whatweb": WhatwebAdapter,
        "katana": KatanaAdapter,
        "ffuf": FfufAdapter,
    }
