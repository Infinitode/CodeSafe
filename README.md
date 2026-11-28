# CodeSafe
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
[![Code Size](https://img.shields.io/github/languages/code-size/infinitode/codesafe)](https://github.com/infinitode/codesafe)
![Downloads](https://pepy.tech/badge/codesafe)
![License Compliance](https://img.shields.io/badge/license-compliance-brightgreen.svg)
![PyPI Version](https://img.shields.io/pypi/v/codesafe)
[![PyPI - Provenance](https://img.shields.io/badge/provenance-trusted%20publishing-3673A5?logo=pypi&logoColor=white)](https://pypi.org/project/codesafe/#security)

An open-source Python library for code encryption, decryption, and safe evaluation using Python's built-in AST module, complete with allowed functions, variables, built-in imports, timeouts, and blocked access to attributes.

*CodeSafe is an experimental library, and we're still running some tests on it. If you encounter any issues or have an edge use case, please let us know.*

> [!NOTE]
> **CodeSafe** encrypts Python files with authenticated encryption (Fernet: AES-128-CBC + HMAC-SHA256) and can run them without exposing the plaintext on disk (e.g. to end-users). Note that the built-in default key is public, so for real confidentiality you must supply your own key - see [Security Limitations & Notes](#security-limitations--notes). We have also included a `safe_eval` function, that can safely evaluate expressions within a safe environment.

## Security Advisory

### Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.** See [SECURITY.md](SECURITY.md) for how to report vulnerabilities to us privately (private vulnerability reporting or email). We maintain this page with published advisories:

| Advisory | CVE / GHSA | Affected | Fixed in |
| :--- | :--- | :--- | :--- |
| `safe_eval` sandbox escape via indirect subscript call | CVE-2026-133467 · [GHSA-7gp8-3j6q-v4h8](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8) | 0.0.1 - 0.0.4 | 0.0.5 |
| `safe_eval` sandbox escape via dunder attribute access with `allow_attributes=True` (string-argument indirection, e.g. `().__getattribute__('__class__')`) | [GHSA-m85r-gp57-6p5q](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-m85r-gp57-6p5q) · CVE pending | 0.0.3 - 0.0.5 | **0.0.6** |
| Remote code execution in the calling process via unsafe deserialization of the `safe_eval()` result (cloudpickle) | [GHSA-2565-87hp-2588](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-2565-87hp-2588) · CVE pending | 0.0.6 | **0.0.7** |

You can browse all advisories at https://github.com/Infinitode/CodeSafe/security/advisories

### Remote code execution in the caller via result deserialization (fixed in v0.0.7)

**Version 0.0.6 deserialized the result of `safe_eval()` in the calling process with `cloudpickle.loads()` - outside the sandbox it had just enforced.**

- **Vulnerability**: The AST checker only guarded what ran inside the evaluation subprocess. The child serialized whatever the expression produced with `cloudpickle.dumps()`, and the parent called `cloudpickle.loads()` on it with full builtins. An expression could return an object whose `__reduce__` chain ran arbitrary code *the moment the parent unpickled it* - the injected code executed in the caller's process, not the sandbox, and the default configuration was enough.
- **Impact**: An attacker who controls only the expression passed to `safe_eval()` obtained arbitrary code execution in the host application, with the host's privileges (CVSS 3.1: 9.8, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). This is a distinct root cause from CVE-2026-133467: the sandbox itself worked; the boundary back to the caller did not.
- **Affected versions**: 0.0.6 only. Versions 0.0.1-0.0.5 are not affected by this specific bug: they return results through a `multiprocessing.Queue` with the standard library's `pickle`, and this gadget cannot survive that encoder (`Can't pickle local object`). Those versions are affected by the earlier advisories instead. Note that 0.0.5's `Queue.get()` does unpickle in the parent, so the underlying pattern is similar, but no working payload of this kind was found for 0.0.5.
- **Fixed in**: Version **0.0.7**. The result boundary no longer involves pickle at all: the child encodes only plain data (see below) and the parent reconstructs it from primitives. A returned value has no code path into the caller.
- **Workaround for 0.0.6**: none that is complete - treat every expression as fully trusted, or upgrade.
- **Related hardening in the same release**: `str.format`/`format_map` templates that name attributes or keys (`'{0.__class__}'.format(obj)`) are rejected; rebinding a safe-builtin name (`(len := f)()`, `[f() for len in [..]]`, `(lambda len: len())(f)`) no longer lets an expression call a non-allowlisted callable; callables passed to builtins that invoke them (`sorted(key=...)`, `iter(f, None)`) follow the same allowlist; `__builtins__` is not reachable by name; `SystemExit`/`KeyboardInterrupt`/`GeneratorExit` raised by an expression arrive as a catchable `RuntimeError` instead of killing or unwinding the caller; and `file_access=False` can no longer be bypassed by re-introducing `open` through `allowed_builtins`.

**What `safe_eval()` returns in 0.0.7.** Results are restricted to plain data: `None`, `bool`, `int`, `float`, `complex`, `str`, `bytes`, `decimal.Decimal`, `fractions.Fraction`. Containers of plain data (`list`, `tuple`, `dict`, `set`) are returned only when `allow_objects=True` is passed. Lambdas, classes, instances of user-defined types, modules and generators are no longer returned - they raise a clear `RuntimeError` instead of being serialized. If your code relied on returning lambdas or dynamic classes, restructure the expression to return data.

**Advisory**: [GHSA-2565-87hp-2588](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-2565-87hp-2588). Reported by **Juan Lucas Armendares** of **Sunplace Solutions** - thank you for finding and reporting this.

### Second sandbox-escape issue fixed in v0.0.6

**Versions 0.0.3 through 0.0.5, when `safe_eval()` is called with `allow_attributes=True` (not the default), allowed dunder attributes to be read indirectly through string arguments that the AST validator never inspects.**

- **Vulnerability**: The dunder blocklist only inspected attribute names written literally in the expression. `().__getattribute__('__class__')` walked past it and returned `<class 'tuple'>`, instead of being rejected. All dunder names (`__class__`, `__mro__`, `__globals__`, `__dict__`, `__subclasses__`, ...) were affected via `__getattribute__`/`__mro__`/`__dict__` and similar indirection.
- **Impact**: Reading dunder attributes defeats the class-hierarchy-traversal protections and, depending on the allowed functions/attributes in the evaluation context, can lead to a full sandbox escape and arbitrary code execution (the same impact class as GHSA-7gp8-3j6q-v4h8).
- **Affected versions**: 0.0.3, 0.0.4, 0.0.5
- **Fixed in**: Version **0.0.6** - all attribute names starting with `__` are now always rejected.
- **Workaround for older versions**: leave `allow_attributes` at its default (`False`). There is no complete workaround otherwise - upgrade.
- **Advisory**: [GHSA-m85r-gp57-6p5q](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-m85r-gp57-6p5q) (High, 8.1). Fixed in v0.0.6, which is live on PyPI. A CVE ID will be requested from and assigned by GitHub when the advisory is published; see the advisory for the CVE once it has been assigned.

### Critical Vulnerability Fixed in v0.0.5

**Versions 0.0.1 through 0.0.4 contain a known sandbox escape vulnerability in `safe_eval()` that allows arbitrary code execution.**

See the security advisory: https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8 (CVE ID: CVE-2026-133467 · CVSS 3.1 score: 9.8)

- **Vulnerability**: The `safe_eval()` function in versions 0.0.1-0.0.4 is vulnerable to a sandbox escape via indirect subscript lookup (e.g., `__builtins__['exec'](...)`). This bypasses the AST validation and allows execution of arbitrary Python code.
- **Impact**: An attacker controlling an expression passed to `safe_eval()` can execute arbitrary Python code with the application's permissions.
- **Affected Versions**: 0.0.1, 0.0.2, 0.0.3, 0.0.4
- **Fixed In**: Version 0.0.5 and later

**If you are using any version from 0.0.1 to 0.0.4, you should upgrade to version 0.0.7 or later immediately.** These earlier versions should **not** be used in untrusted expression evaluation environments.

The fix includes:
1. Rejecting all `ast.Call` nodes unless the exact target is explicitly whitelisted (including calls via subscript, attribute, and other indirect targets)
2. Using a minimal built-ins allowlist that excludes dangerous functions like `exec`, `eval`, `compile`, and `__import__`
3. Added comprehensive regression tests for indirect call targets

Version **0.0.6** additionally closes this second, related sandbox issue: with `allow_attributes=True`, dunder attributes such as `__class__` could be read indirectly through string arguments (e.g., `().__getattribute__('__class__')`), bypassing the dunder blocklist. All attribute names starting with `__` are now always rejected.

A huge thanks to [@hkmj19](https://github.com/hkmj19)/[Linkedin](https://www.linkedin.com/in/hemanth-kumar-mj-24b50a256/) for finding and reporting this vulnerability.

## Vulnerability & Security Testing ([`test_poc_vulnerability.py`](https://github.com/Infinitode/CodeSafe/blob/main/test_poc_vulnerability.py))

> [!NOTE]
> These tests are only available on GitHub, and not on PyPI. They are external tests that aren't built along with `CodeSafe` versions.

CodeSafe v0.0.7 includes a rigorous test suite (`TestVulnerabilityFixes`, `TestEdgeCases`, `TestHardeningRegression` and `TestResultBoundaryV007` in `test_poc_vulnerability.py`, plus `test.py`) to systematically verify that `safe_eval` blocks sandbox escapes while preserving standard evaluation features.

### Test Results Summary

**108/108 Tests Passing** (`100% Pass Rate` across all vector categories)

| Attack Vector / Category | Specific Vectors Tested | Status |
| :--- | :--- | :--- |
| **AST Subscript & Indirect Calls** | `__builtins__['exec']()`, `__builtins__['eval']()`, `__builtins__['__import__']()`, `getattr(__builtins__, 'exec')`, nested subscript access | **[PASS] Blocked** |
| **Dunder Attribute Escapes** | `__class__`, `__bases__`, `__mro__`, `__subclasses__`, `__globals__`, `__closure__`, `__code__`, `__dict__`, `__getattribute__` (all dunders, including string-argument indirection) | **[PASS] Blocked** |
| **Class Hierarchy Traversal** | `object.__subclasses__()`, `type().subclasses()` | **[PASS] Blocked** |
| **Expression Bypasses** | Comprehensions (list, dict, set), generator expressions, short-circuit logic (`and`/`or`), ternary operators, tuple unpacking, walrus operator (`:=`), lambda calls | **[PASS] Blocked** |
| **Module & I/O Execution** | Direct/from `import`, `os.system`, `subprocess`, `io.open`, `socket`, `requests`, `urllib`, `pathlib` write operations | **[PASS] Blocked** |
| **Dangerous Built-ins** | `exec()`, `eval()`, `compile()`, `input()`, `open()` (default settings), modifying `__builtins__`, `dir()`, `id()` | **[PASS] Blocked** |
| **Resource & Process Safety** | Timeout always terminates the child process (no leaked runaway processes); non-positive timeouts rejected | **[PASS] Enforced** |
| **Result Deserialization** (v0.0.7) | `__reduce__` gadgets returned as the result, in a list/tuple/dict/set, or via `allowed_vars`; lambdas, classes, modules, functions and user types as results | **[PASS] Blocked** |
| **Format-String Traversal** (v0.0.7) | `'{0.__class__}'.format(o)`, `format_map`, nested spec fields, mapping-key access (`'{0[k]}'`) | **[PASS] Blocked** |
| **Name Shadowing** (v0.0.7) | `(len := f)()`, `[f() for len in [..]]`, `(lambda len: len())(f)`, callables in `sorted(key=...)` / `iter(f, None)` | **[PASS] Blocked** |
| **Reserved Names & Flags** (v0.0.7) | `__builtins__` read/rebind, `open` re-introduced via `allowed_builtins`, `SystemExit`/`KeyboardInterrupt` from an expression | **[PASS] Blocked** |
| **Error Handling** | Plain-data results round-trip losslessly (`Decimal`/`Fraction` included); unserializable results (lambdas, classes, generators, modules) raise a clear `RuntimeError`; builtin exceptions propagate with their original type; user-defined exception types arrive as `RuntimeError`; no `Queue` race | **[PASS] Working** |
| **Functional Baseline** | Safe arithmetic, string/list/dict operations, standard safe builtins (`len`, `max`, `abs`), explicitly allowed functions | **[PASS] Working** |

### Running the Tests

To run the security PoC suite locally:

```bash
python -m unittest test_poc_vulnerability.py -v
```

To run everything (including the functional suite in `test.py`):

```bash
python -m unittest test.py test_poc_vulnerability.py -v
```

### Changelog v0.0.7:

* **Security Fix (critical)**: `safe_eval()` no longer deserializes the evaluation result with `cloudpickle` in the calling process. In 0.0.6 the child serialized its result and the parent called `cloudpickle.loads()` on it with full builtins, so an expression could return a `__reduce__` gadget that ran arbitrary code in the *caller* - outside the sandbox that had just been enforced. The result now crosses the process boundary as plain primitives and is rebuilt with a non-executable decoder. See the [Security Advisory](#security-advisory) above.
* **Changed**: `safe_eval()` returns plain data only - `None`, `bool`, `int`, `float`, `complex`, `str`, `bytes`, `Decimal`, `Fraction`. Containers of plain data are opt-in via the new `allow_objects=True` parameter. Lambdas, dynamic classes, instances of user-defined types, modules and generators raise a clear `RuntimeError` instead of being pickled. **This removes a feature that 0.0.6 advertised**; it was also the attack surface.
* **Security Fix**: `str.format`/`format_map` templates that traverse attributes or mapping keys (`'{0.__class__}'.format(obj)`, `'{0[key]}'.format(obj)`) are rejected. They read attributes without ever producing an `ast.Attribute` node for the checker to inspect.
* **Security Fix**: An expression can no longer rebind a safe-builtin *name* and then call it - `(len := host_callable)()`, `[host_callable() for len in [..]]` and `(lambda len: len())(host_callable)` previously reached a caller-supplied callable that was not on `allowed_function_calls`. Such calls now require explicit allowlisting.
* **Security Fix**: Callables passed to builtins that invoke them (`sorted(key=...)`, `iter(f, None)`) follow the same allowlist as direct calls. `allowed_vars` entries are data, not implicit call permissions.
* **Security Fix**: `__builtins__` is no longer reachable by name from an expression, and can no longer be rebound or mutated.
* **Security Fix**: An expression raising `SystemExit`, `KeyboardInterrupt` or `GeneratorExit` no longer terminates or unwinds the calling process; it arrives as a catchable `RuntimeError`. Exceptions of user-defined types are reported the same way instead of being reconstructed in the parent.
* **Security Fix**: `file_access=False` and `network_access=False` are enforced *after* `allowed_builtins` is merged, so passing `open` (or similar) through `allowed_builtins` no longer bypasses the flag.
* **Security**: Returned data is bounded (nesting depth 100, 1M nodes, 1 MiB of `str`/`bytes`), and int-to-str conversion is capped for the duration of a call so a returned giant integer cannot burn CPU in the caller.
* **Changed**: The result transport is a `multiprocessing.Pipe` drained by a reader thread instead of a `Queue`. A result larger than the OS pipe buffer can no longer deadlock the parent, and the timing of `EvaluationTimeoutError` is tighter.
* **Changed**: The `cloudpickle` dependency was removed - CodeSafe no longer imports pickle on the evaluation path at all.
* Added regression tests for every item above (see [Vulnerability & Security Testing](#vulnerability--security-testing-test_poc_vulnerabilitypy)).
* **Credit**: The critical result-deserialization issue above was reported by **Juan Lucas Armendares** of **Sunplace Solutions** - many thanks. See [GHSA-2565-87hp-2588](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-2565-87hp-2588).

### Changelog v0.0.6:

* **Security Fix**: With `allow_attributes=True`, *all* attribute names starting with `__` are now rejected (previously only a cherry-picked list of dunders, which was bypassable via string arguments, e.g. `().__getattribute__('__class__')`). See the [Security Advisory](#security-advisory) above.
* **Security**: Timed-out evaluations always terminate the child process. Previously `immediate_termination=False` leaked an unkillable, CPU-spinning process; the parameter is deprecated and ignored.
* **Changed**: `encrypt()` now uses authenticated cryptography - Fernet (AES-128-CBC + HMAC-SHA256) with a 256-bit key - instead of the Caesar/mapping obfuscation. Any Unicode source code round-trips losslessly. Keys come from the `key` argument (see the new `generate_key()`), the `CODESAFE_KEY` environment variable, or a built-in default key (public; obfuscation-grade only - supply your own key for real confidentiality). Files written by `encrypt_to_file()` now contain `# codesafe:v2:<token>`; legacy pre-0.0.6 `.encrypt` files are still fully readable and runnable via `decrypt()`, `decrypt_to_file()` and `run()`.
* **Changed**: The Caesar `mapping` parameter was removed from `encrypt()` (passing it raises `TypeError`). It is still accepted by `decrypt()`/`decrypt_to_file()`/`run()` for decrypting legacy payloads.
* **Changed** (reverted in 0.0.7 for security reasons): Evaluation results were serialized with `cloudpickle` (returned from a subprocess), so lambdas and dynamically created classes could be returned from `safe_eval()`. Results that could not be serialized (e.g. generators) raised a clear `RuntimeError` instead of a misleading `EvaluationTimeoutError`, and the `queue.empty()` race that could drop valid results was eliminated. **This was the deserialization sink fixed in 0.0.7** - see the [Security Advisory](#security-advisory).
* **Changed**: `restricted_imports` was removed from `safe_eval()` - it was redundant (imports are rejected in expressions regardless) and misleading.
* **Bug Fix**: `decrypt()` validates its input and produces clear errors for corrupt/tampered payloads (wrong key, corrupted or tampered v2 data is detected by the HMAC).
* **Bug Fix**: Non-positive `timeout` values are rejected with `ValueError`.
* Exceptions from the evaluation child process now propagate with their original type (including `BaseException`); exception chaining (`raise ... from e`) is used throughout; decrypted code executed via `run()` gets a clean `__main__` namespace isolated from CodeSafe's module globals.
* Removed `dir()` and `id()` from the default safe builtins (pure information leakage with no legitimate use in expressions).
* All encryption/decryption file operations now explicitly use UTF-8.
* The package depends on `cryptography` (installed automatically by pip). `cloudpickle` was a dependency in 0.0.6 only.
* Packaging modernized: PEP 621 `pyproject.toml`; source distributions and wheels build correctly from a fresh checkout (the `{{VERSION_PLACEHOLDER}}` version made `pip install .` and `python -m build` fail). Trusted Publishing (OIDC) is used for PyPI releases - no stored API tokens - and releases carry PEP 740 provenance attestations, shown on PyPI.
* A test workflow runs the full test suite on Python 3.8-3.12 across Linux, Windows and macOS for every push and PR.
* Added [SECURITY.md](SECURITY.md) with instructions for reporting vulnerabilities privately. The security notes and limitations previously tracked in a separate audit file are now maintained in this README (see [Security Limitations & Notes](#security-limitations--notes)).

### Changelog v0.0.5:

> [!WARNING]
> **v0.0.5 (and earlier) has a second, known sandbox-escape issue**, fixed in v0.0.6: with `allow_attributes=True`, dunder attributes could be read through string arguments (e.g. `().__getattribute__('__class__')`), bypassing the dunder blocklist. See the [Security Advisory](#security-advisory) section. **If you use `allow_attributes=True` on 0.0.5 or earlier, upgrade to v0.0.7 now.**

* **Security Fix**: Patched critical sandbox escape vulnerability in `safe_eval()` (CVE-2026-133467), thanks to [@hkmj19](https://github.com/hkmj19)/[Linkedin](https://www.linkedin.com/in/hemanth-kumar-mj-24b50a256/) for reporting.
* Blocked indirect function calls via `ast.Subscript`, `ast.Attribute`, and other non-`ast.Name` targets
* Implemented minimal safe builtins whitelist excluding `exec`, `eval`, `compile`, `__import__`, and similar dangerous functions
* Added regression tests for indirect call bypass attempts

### Changelog v0.0.4:

* Major performance optimizations for encryption and decryption (~10x speedup).
* Optimized `safe_eval` by pre-filtering builtins and reducing internal overhead.
* Added support for `bytes` input in `encrypt`.
* Added support for file-like stream objects in `run` and `decrypt_to_file`.
* Standardized error handling (replaced `print` with exceptions).

### Changelog v0.0.3:

* Added an `allow_attributes` parameter to `safe_eval` and set `immediate_termination` to be `True` by default for safer function calling.

### Changelog v0.0.2:

* Fixed function returns.
* Added error handling to `CodeSafe`, removed some print statements with edits from `@0XC7R`.

### Changelog v0.0.1:

* Initial release

## Installation

You can install CodeSafe using pip (it automatically installs the `cryptography` dependency):

```bash
pip install codesafe

```

## Supported Python Versions

CodeSafe supports the following Python versions:

* Python 3.8
* Python 3.9
* Python 3.10
* Python 3.11
* Python 3.12 (Preferred)

Versions 0.0.5 and earlier supported Python 3.6/3.7, but those versions are end-of-life and are no longer supported as of 0.0.6.

Please ensure that you have one of these Python versions installed before using CodeSafe. CodeSafe may not work as expected on lower versions of Python than the supported.

## Features

* **Safe Eval**: Safely allow `eval()` expressions to run, while maintaining complete control over the entire evaluation process.
* **Code Encryption/Decryption**: Encrypt your code with authenticated cryptography (Fernet: AES-128-CBC + HMAC-SHA256), including full Unicode support. Legacy pre-0.0.6 `.encrypt` files can still be decrypted.
* **Run encrypted code at runtime**: Run your encrypted code files, without needing to expose your code to end-users.

> [!NOTE]
> Running encrypted files at runtime using `run()` are only available in formats that can be understood by Python.

> [!IMPORTANT]
> When running `safe_eval`, make sure to wait for the Python file to finish its bootstrapping phase. This can be done by simply waiting for:
> ```python
> if __name__ == '__main__':
>    # Run eval, etc.
> 
> ```
> 
> 
> If you're planning on including `safe_eval` in executables:
> ```python
> import multiprocessing
> if __name__ == '__main__':
>       multiprocessing.freeze_support()
>       # Call safe_eval afterwards
> 
> ```
> 
> 
> You can read more about why this needs to be done here: https://pytorch.org/docs/stable/notes/windows.html#multiprocessing-error-without-if-clause-protection

## Usage

### Safe Eval

```python
from codesafe import safe_eval

if __name__ == '__main__':
    # Run a normal, safe expression
    expression = "1 + 1"
    disallowed_expression = "os.getcwd()"

    result1 = safe_eval(expression, timeout=10)
    result2 = safe_eval(disallowed_expression, timeout=10)  # raises UnsafeExpressionError

```

> [!NOTE]
> Attribute inspection is disabled when using `safe_eval`. You can read more about how to use `safe_eval` from [here](https://infinitode-docs.gitbook.io/documentation/package-documentation/codesafe-package-documentation?utm_source=gemini).

#### What `safe_eval` can return

Since v0.0.7 the result is plain data, transported from the evaluation subprocess as primitives and rebuilt without pickle:

```python
from codesafe import safe_eval

safe_eval("2 + 2")                        # 4
safe_eval("'hello'.upper()", allow_attributes=True)   # 'HELLO'
safe_eval("[1, 2, 3]")                    # RuntimeError: containers are opt-in
safe_eval("[1, 2, 3]", allow_objects=True)            # [1, 2, 3]
safe_eval("lambda: 1")                    # RuntimeError: lambdas are not returned
```

Allowed values are `None`, `bool`, `int`, `float`, `complex`, `str`, `bytes`, `Decimal` and `Fraction`. Containers (`list`, `tuple`, `dict`, `set`) of those are returned only with `allow_objects=True`, up to 100 levels deep and 1 MiB of string/bytes data. Lambdas, classes, modules, generators and instances of user-defined types raise `RuntimeError` - nothing callable ever crosses back into your process.

Names you pass in `allowed_vars` are **data**, not implicit call permissions: a function is only called from the expression when its name is in `allowed_function_calls` (or it is a safe builtin). This also applies to callables handed to builtins that invoke them, such as `sorted(xs, key=fn)`.

> [!IMPORTANT]
> Since v0.0.6, encrypted payloads are self-describing (`# codesafe:v2:<token>`) and any Unicode source code round-trips losslessly. Pre-0.0.6 `.encrypt` files (Base64 Caesar) keep working with `run()`, `decrypt()` and `decrypt_to_file()`, but they are no longer produced - and they were never cryptographically secure.

### Encrypt & Run Code

```python
from codesafe import encrypt_to_file, decrypt_to_file, run, generate_key

code = """
greetJohnny = "Hello Johnny!"

def greet_someone(greeting):
    print(greeting)

greet_someone(greetJohnny)
"""

# Generate a key (do this once and keep it secret!)
key = generate_key()
# ...or set the CODESAFE_KEY environment variable instead of passing key= everywhere

# Encrypt the code
encrypted_file_path = "encrypted_code.encrypt"
encrypt_to_file(code, encrypted_file_path, key=key)

# Run the encrypted code
run(encrypted_file_path, key=key) # Hello Johnny!

# Decrypt code to another file
output_file = "decrypted_code.py"
decrypt_to_file(encrypted_file_path, output_file, key=key)

```

If you omit `key=`, CodeSafe uses the `CODESAFE_KEY` environment variable, falling back to a built-in default key that is public knowledge - fine for hiding code from casual reading, useless against anyone determined. **Pass your own key for real confidentiality.** Legacy pre-0.0.6 `.encrypt` files can still be opened by the same functions (pass the old Caesar `mapping` positionally to decrypt legacy payloads if you used a custom one).

## Security Limitations & Notes

CodeSafe is designed for practical code protection, not absolute guarantees. Please read these before relying on it:

* **Encryption is only as strong as your key.** The built-in default key is public (it ships with the package), so payloads encrypted with it are protected only from casual inspection. Generate your own key with `generate_key()` and keep it secret (e.g. via the `CODESAFE_KEY` environment variable) for real confidentiality. Even then, `run()` must be able to read the key at execution time - anyone with both the encrypted file and the key can decrypt it.
* **Encrypted code runs with the full permissions of the current process.** Encryption protects code at rest; it is not a security boundary at runtime. Only run code you trust.
* **`safe_eval()` is not a perfect sandbox.** It relies on AST filtering plus a subprocess with a timeout, and expressions run with the privileges of the host process. `allow_attributes=True` convenience comes at increased risk (prefer the default `False`), and anything passed via `allowed_vars`/`allowed_builtins` runs as trusted code - the sandbox protects against the *expression*, not against what you hand it. For hostile input, add defense in depth (containers, seccomp, dropped privileges).
* **Result boundary is data-only by design.** Since v0.0.7 the result of an evaluation is transported as plain primitives and rebuilt without pickle; nothing the expression produces executes in the calling process. The cost is that lambdas, dynamic classes, instances of user-defined types, modules and generators cannot be returned (they raise `RuntimeError`), and containers of plain data need `allow_objects=True`.
* **`type` remains in the default safe builtins** (needed for `isinstance`-style patterns and `type(x)` introspection). With all dunder attributes rejected and no deserialization of results, it does not on its own yield an escape path, but it is the remaining reflection-adjacent primitive and is worth watching.
* **Integrity of v2 payloads is enforced by HMAC**, but payloads carry no identity - a valid token only proves it was produced with the key, not *who* produced it. The legacy Caesar format (pre-0.0.6) has no integrity or authenticity at all.
* **Custom Caesar mappings** (legacy) had a fixed 64-character-value requirement and are no longer produced by `encrypt()`; they are only honored when decrypting legacy payloads.
* **Results must be plain data.** `None`, `bool`, `int`, `float`, `complex`, `str`, `bytes`, `Decimal`, `Fraction`, and - with `allow_objects=True` - `list`/`tuple`/`dict`/`set` containing those. Everything else raises `RuntimeError`.

## Contributing

Contributions are welcome! If you encounter any issues, have suggestions, or want to contribute to CodeSafe, please open an issue or submit a pull request on [GitHub](https://github.com/infinitode/codesafe?utm_source=gemini).

## License

CodeSafe is released under the terms of the **MIT License (Modified)**. Please see the [LICENSE](https://github.com/infinitode/codesafe/blob/main/LICENSE?utm_source=gemini) file for the full text.

**Modified License Clause**

The modified license clause grants users the permission to make derivative works based on the CodeSafe software. However, it requires any substantial changes to the software to be clearly distinguished from the original work and distributed under a different name.
