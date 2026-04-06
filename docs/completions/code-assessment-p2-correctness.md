# Code Assessment — Part 2: Correctness Issues

**Date:** 2026-04-06
**Source:** [Code Assessment](../plans/code-assessment.md) Part 2
**Scope:** 5 correctness fixes across 5 files. 0 new tests, 0 regressions (722 tests pass).

---

## CORR-1. CVSS cloud metadata scoring — missing confidentiality vector

**File:** `src/boba/analysis/severity.py:162-164`

### Problem

SSRF with cloud metadata evidence (`169.254.169.254`) only set `integrity="H"`. The primary impact of IMDSv1 credential theft is **confidentiality** (reading IAM credentials, tokens, service account keys), not integrity alone. The base SSRF rule already set `confidentiality="H"`, so the cloud_metadata branch added integrity without explicitly ensuring confidentiality — getting the right CVSS score (CRITICAL) by accident rather than by design.

### Analysis

The assessment recommended changing `integrity="H"` to `confidentiality="H"`. However, this would have dropped SSRF+cloud_metadata from CRITICAL to HIGH, because the base rule already has `confidentiality="H"` — the branch would become a no-op.

Cloud metadata credential theft actually enables **both** impacts:
- **Confidentiality (H):** Reading IAM credentials, tokens, and role ARNs from the metadata service
- **Integrity (H):** Stolen IAM credentials enable modifying cloud resources, escalating IAM policies, and pivoting to other services

### Fix

Set both vectors explicitly, with a clarified comment:

```python
# Before
if "cloud_metadata" in evidence_str or "169.254.169.254" in evidence_str:
    metrics["integrity"] = "H"

# After
if "cloud_metadata" in evidence_str or "169.254.169.254" in evidence_str:
    metrics["confidentiality"] = "H"
    metrics["integrity"] = "H"
```

The `confidentiality="H"` assignment is technically redundant (already set in the SSRF base rule), but making it explicit documents the reasoning: cloud metadata access is a confidentiality impact *first*, integrity impact *second*. If the base rule ever changes, the cloud_metadata branch still produces the correct score.

---

## CORR-2. Coverage host filter gated behind directory check

**File:** `src/boba/analysis/coverage.py:93`

### Problem

```python
if host and directories:  # host filter only applied when directories exist
    endpoint_set = {ep for ep in endpoint_set if urlparse(ep).hostname == host}
```

When `directories` was empty (no directory scan results for a hunt), the host filter was never applied. A per-host coverage query like "what endpoints have we tested on `api.target.com`?" would return endpoints from *all* hosts mixed together — inflating coverage counts and producing misleading reports.

The `directories` variable was irrelevant to whether host filtering should occur — it was just coincidentally truthy in most test scenarios (which is why this wasn't caught earlier).

### Fix

```python
# Before
if host and directories:

# After
if host:
```

Removed the `directories` guard entirely. The host filter applies unconditionally when a host is specified, regardless of whether directory scan results exist.

---

## CORR-3. Chaining picks arbitrary finding for cross-host rules

**File:** `src/boba/analysis/chaining.py:311-322`

### Problem

For cross-host chain rules (e.g., `redirect_to_ssrf`), the code picked the first finding of each required type:

```python
all_findings.append(type_matches[rtype][0])  # always picks first
```

`type_matches[rtype]` is populated from `by_type.get(rtype, [])`, which comes from a database query with no guaranteed ordering. The selection was effectively random — a low-confidence, INFO-severity SSRF could anchor a chain even when a confirmed, HIGH-severity SSRF existed for a different host.

### Fix

Sort candidates by severity (descending) then confidence (descending) before selecting:

```python
_sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_conf_rank = {"confirmed": 0, "likely": 1, "possible": 2}
all_findings = []
for rtype in required:
    best = sorted(
        type_matches[rtype],
        key=lambda f: (
            _sev_rank.get(f.get("severity", "info"), 4),
            _conf_rank.get(f.get("confidence", "possible"), 2),
        ),
    )
    all_findings.append(best[0])
```

Rank maps are defined inline at the call site (not module-level) because they're only used in this one branch. The sort is stable — ties preserve insertion order. This ensures the strongest available evidence anchors each chain, producing higher-quality chain scores and more actionable reports.

---

## CORR-4. Temp file leak in FfufAdapter and ArjunAdapter

**Files:** `src/boba/adapters/ffuf.py:57-60`, `src/boba/adapters/arjun.py:64-67`

### Problem

Both adapters create a temporary output file for the tool to write JSON results into:

```python
tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_ffuf_", delete=False)
tf.close()
output_file = Path(tf.name)
```

`BaseAdapter` provides `_create_temp_file(lines, suffix)` which writes content *and* appends the path to `self._temp_files` for cleanup. But ffuf/arjun need *empty* output files (the tool writes to them), so they can't use `_create_temp_file()`. The problem is they also never registered the file with `self._temp_files`.

`BaseAdapter._cleanup_temp_files()` iterates `self._temp_files` and deletes each one. Without registration, if the adapter crashed between file creation and the point where it reads + deletes the output file, the temp file persisted on disk indefinitely.

### Fix

Added `self._temp_files.append(output_file)` immediately after file creation in both adapters:

```python
tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_ffuf_", delete=False)
tf.close()
output_file = Path(tf.name)
self._temp_files.append(output_file)  # register for cleanup
```

Now `_cleanup_temp_files()` (called in `BaseAdapter.run()`'s `finally` block) will clean up the file even if the adapter crashes mid-run.

---

## CORR-5. Redundant `test_params` re-initialization in `test_xss` and `test_sqli`

**File:** `src/boba/tools/vuln.py` (two sites)

### Problem

Both `test_xss` and `test_sqli` initialized `test_params` at the top of the function and identically re-initialized it after the main detection loop:

**`test_xss`:**
```python
test_params = params or {"q": ""}   # line 548 — initial assignment
# ... ~135 lines of detection logic ...
test_params = params or {"q": ""}   # line 683 — identical re-assignment (dead code)
```

**`test_sqli`:**
```python
test_params = params or {"id": "1"}  # line 728 — initial assignment
# ... ~206 lines of detection logic ...
test_params = params or {"id": "1"}  # line 934 — identical re-assignment (dead code)
```

The `params` argument is never mutated within the function body, so the second assignment always produces the same result as the first. These are copy-paste artifacts — likely from duplicating the initialization block at the bottom when the persist/coverage code was added.

### Fix

Removed both redundant lines. The subsequent `param_str = ",".join(test_params.keys())` and coverage loop continue to reference the `test_params` variable set at the top of each function.
