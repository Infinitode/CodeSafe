# CodeSafe Security & Quality Audit

**Date:** 2026-11-24 · **Scope:** `codesafe` package (`codesafe/__init__.py`), packaging, CI, tests · **Audited from commit:** `916cd04`

This document records the issues found during the audit and how they were addressed in **v0.0.6**. Findings marked ✅ are fixed and covered by regression tests (`TestHardeningRegression` in `test_poc_vulnerability.py`, plus new cases in `test.py`). Findings marked ⚠️ are documented limitations or recommendations for the maintainers.

---

## 1. Critical / High

### 1.1 Dunder attribute filter bypass via string arguments — ✅ Fixed
**Severity:** High · **Component:** `safe_eval` (`allow_attributes=True`) · **Introduced:** v0.0.3

`_check_ast` only blocked a hardcoded list of dunder attributes (`__globals__`, `__class__`, …). Any dunder not on the list — and every dunder reached through a *string argument*, which the AST checker never inspects — was allowed:

```python
>>> safe_eval("().__getattribute__('__class__')", allow_attributes=True)
<class 'tuple'>
```

`__getattribute__`, `__getattr__`, `__mro__`, `__dict__`, `__getattribute__('__len__')()`, etc. were all reachable. This is exactly the class of bug the v0.0.5 CVE fix was meant to close, one layer up.

**Fix:** all attributes whose names start with `__` are now always rejected, in both the attribute-access check and the method-call check. Regression tests cover `__getattribute__`, `__mro__`, `__dict__` and friends.

### 1.2 `immediate_termination=False` leaks runaway CPU processes — ✅ Fixed
**Severity:** High (DoS) · **Component:** `safe_eval`

When the timeout expired and `immediate_termination` was `False`, the child process was left running — a `while True: pass` expression could spin a core forever (confirmed with `multiprocessing.active_children()`).

**Fix:** the child is always terminated on timeout. `immediate_termination` is deprecated and ignored (kept for backwards compatibility); the docstring, README and changelog call this out.

### 1.3 Encryption silently corrupts any non-ASCII code — ✅ Fixed
**Severity:** High (data loss) · **Component:** `encrypt` / `encrypt_with_mapping`

The cipher replaced every mapped character with a fixed 64-character output and passed everything else through unchanged, but `decrypt` re-splits the stream into fixed 64-character chunks. Any unmapped character (i.e. **any non-ASCII source**: `print('héllo')`, emoji, typographic quotes, non-ASCII identifiers) silently misaligned the chunks and produced garbage — irreversible corruption of the "encrypted" artifact, with no error at encrypt time. Even Latin-1 (`é`) was broken, not just wide Unicode.

**Fix:**
- `encrypt()` validates that every character in `code` is present in the `mapping` and every mapping value is exactly 64 characters; otherwise a clear `ValueError` is raised (fail loudly, never corrupt).
- Validation applies to custom mappings too.

### 1.4 Misleading `EvaluationTimeoutError` / dropped results (`queue.empty()` race) — ✅ Fixed
**Severity:** Medium-High · **Component:** `safe_eval`

After `process.join()`, the code trusted `multiprocessing.Queue.empty()`, which is documented as unreliable. Worse, unpicklable results (lambdas, generators, `mappingproxy`) were pickled in the queue's background feeder thread — never in the caller — so the failure was invisible and surfaced as `EvaluationTimeoutError: No result returned from the evaluation process.` (confirmed: `safe_eval("lambda: 1")` always produced that error, never a `PicklingError`).

**Fix:** the child now serializes its result synchronously with `pickle.dumps` (falling back to a picklable `RuntimeError` with a clear message), and the parent polls with `queue.get(timeout=1.0)`. Errors always reach the caller deterministically; the 1-second poll covers reader-thread lag. Child processes and the queue are always closed in `finally`.

---

## 2. Medium

### 2.1 Source tree cannot be built or installed — ✅ Fixed
**Severity:** Medium · **Component:** packaging

`setup.py` declared `version='{{VERSION_PLACEHOLDER}}'`, which setuptools rejects (`Invalid version`). `python -m build`, `pip install .` and `pip install .` from a tag all failed; only the CI `sed` trick made releases work, and it produced distributions whose version came from the tag rather than the source.

**Fix:** PEP 621 `pyproject.toml` is now the single source of truth (`version = "0.0.6"`, SPDX `MIT`, proper metadata, project URLs). `setup.py` is a thin shim. The publish workflow verifies the tag matches the version. Wheels and sdists build cleanly from a fresh checkout (verified).

### 2.2 Publish workflow was broken — ✅ Fixed
**Severity:** Medium · **Component:** CI

- `::set-output` is disabled on current GitHub runners → the "Extract tag name" step (and the whole release) would fail.
- `actions/checkout@master`, `setup-python@v3`, `gh-action-pypi-publish@master` — unpinned/deprecated.
- `python setup.py sdist bdist_wheel` — removed from modern setuptools; `python -m build` is the supported route.
- No check that the tag matches the package version.

**Fix:** rewritten workflow (`checkout@v4`, `setup-python@v5`, `build`, tag↔version consistency check, `gh-action-pypi-publish@release/v1`). A separate `test.yml` now runs the full test suite on Python 3.8–3.12 (Linux) plus 3.12 on Windows/macOS for every push/PR.

### 2.3 No regression tests for the above; a test that cannot fail — ✅ Fixed
**Severity:** Medium · **Component:** tests

- `test_security_error_on_unsafe_function` wrapped its assertion in `try/except UnsafeExpressionError: pass` — it passed even if no exception was raised.
- Nothing covered: unpicklable results, process leaks, Unicode encryption, timeout validation, the dunder-string-argument bypass.

**Fix:** that test now uses `assertRaises`; `TestHardeningRegression` (9 tests) and 6 new functional tests added (73 tests total, all passing).

### 2.4 Base64 input never validated — ✅ Fixed
`base64.b64decode` without `validate=True` ignored invalid characters, so corrupt `.encrypt` files degraded into confusing "empty result" errors. Now decoded with `validate=True` (surrounding/embedded whitespace is stripped first) and invalid input raises a clear `ValueError`.

---

## 3. Low / Hardening

- **`dir()` and `id()` removed from the default safe builtins.** Pure information leakage (scope introspection, addresses) with no legitimate expression use. ✅
- **Non-positive `timeout` values are rejected** with `ValueError` instead of reaching `join()`. ✅
- **`run()` now executes decrypted code with `__name__ == "__main__"`** in a fresh namespace instead of CodeSafe's module globals. (Still obfuscation, not a security boundary — documented.) ✅
- **Exception chaining** (`raise ... from e`) added throughout; child exceptions propagate with their original type; `BaseException` (e.g. `SystemExit` from an allowed function) is caught so the child never vanishes silently. ✅
- **All file I/O in encrypt/decrypt paths explicitly uses UTF-8.** ✅
- **Anchored extraction regex** for the `# <base64>` payload (`^# …$`, multiline) — a base64 blob can no longer match inside an arbitrary comment; trailing `\r`/whitespace tolerated. ✅
- **`__version__`** is now exported; **`codesafe.egg-info`**, test artifacts and virtualenvs are git-ignored; `IOError`/`FileNotFoundError` handlers unified to `OSError`. ✅

---

## 4. Documented limitations & recommendations (not bugs, by design)

- ⚠️ **Encryption is obfuscation, not encryption.** The "key" is shipped inside the package. Do not rely on it for confidentiality; use real cryptographic tooling for secrets. (Already stated in the README; kept for emphasis.)
- ⚠️ **Encryption alphabet is printable ASCII + common whitespace only** (the format maps each character to a fixed 64-char chunk). Escape non-ASCII characters (`\uXXXX`) in source before encrypting. Custom mappings must map every used character and use exactly 64-character values — now validated at encrypt time.
- ⚠️ **`safe_eval` is not a perfect sandbox.** It relies on AST filtering + a subprocess timeout, and expressions run with the privileges of the host process. Standard-library objects reachable through the allowlist may still have unexpected behaviours; defense in depth (containers, `seccomp`, dropped privileges) is recommended for hostile input. `allow_attributes=True` is convenient but always increases risk — prefer leaving it `False`.
- ⚠️ **`allowed_vars` are trusted code.** Anything passed in `allowed_vars`/`allowed_builtins` runs outside the sandbox checks if *it* does something dangerous (e.g. `allowed_vars={'system': os.system}`). The sandbox protects against the expression, not against what you hand it.
- ⚠️ **Results must be picklable.** Lambdas, generators, modules and `mappingproxy` objects cannot be returned; you now get a clear `RuntimeError` instead of a hang or a wrong error type.
- ⚠️ **`restricted_imports` is effectively redundant** — imports are always rejected in expressions. Consider deprecating it in a future release.
- ⚠️ **Custom `mapping` encryption/decryption performance** is O(n·64); fine for typical sources, but very large files will be slow and produce ~64× output. Consider a binary (non-text) format with length-prefixing in 1.0.
- ⚠️ **`dir`/`id` removal is technically breaking** for anyone relying on them in expressions; noted in the changelog.
- ⚠️ **`type` remains in the default safe builtins.** It is required for `isinstance`-style patterns and `type(x)` introspection; with all dunders blocked it does not by itself yield an escape path, but it is the remaining reflection-adjacent primitive worth watching.

## 5. Residual risks of the fixed design

- Results cross the process boundary via `pickle`. Payloads are produced and consumed by CodeSafe itself, but any future change that lets callers or decrypted code influence the pickle stream must treat unpickling as code execution.
- The 64-chunk format and the `# <base64>` container format are untouched for compatibility with existing `.encrypt` files; they carry no integrity or authenticity guarantees. Tampered files decrypt to garbage or fail loudly, but are not detectable as forgeries.

## 6. CVE tracking

| Advisory | CVE | GHSA | Fixed in | Status |
| :--- | :--- | :--- | :--- | :--- |
| `safe_eval` sandbox escape via indirect subscript call | **CVE-2026-133467** | GHSA-7gp8-3j6q-v4h8 | 0.0.5 | ✅ Fixed; README updated to reference the CVE ID |
| Dunder attribute bypass via string arguments (`allow_attributes=True`) | not yet assigned | not yet assigned | 0.0.6 | ✅ Fixed — consider requesting a CVE/GHSA from the GitHub Security Advisory form |
