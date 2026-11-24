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
| `safe_eval` sandbox escape via dunder attribute access with `allow_attributes=True` (string-argument indirection, e.g. `().__getattribute__('__class__')`) | Pending assignment | 0.0.3 - 0.0.5 | **0.0.6** |

You can browse all advisories at https://github.com/Infinitode/CodeSafe/security/advisories

### Second sandbox-escape issue fixed in v0.0.6

**Versions 0.0.3 through 0.0.5, when `safe_eval()` is called with `allow_attributes=True` (not the default), allowed dunder attributes to be read indirectly through string arguments that the AST validator never inspects.**

- **Vulnerability**: The dunder blocklist only inspected attribute names written literally in the expression. `().__getattribute__('__class__')` walked past it and returned `<class 'tuple'>`, instead of being rejected. All dunder names (`__class__`, `__mro__`, `__globals__`, `__dict__`, `__subclasses__`, ...) were affected via `__getattribute__`/`__mro__`/`__dict__` and similar indirection.
- **Impact**: Reading dunder attributes defeats the class-hierarchy-traversal protections and, depending on the allowed functions/attributes in the evaluation context, can lead to a full sandbox escape and arbitrary code execution (the same impact class as GHSA-7gp8-3j6q-v4h8).
- **Affected versions**: 0.0.3, 0.0.4, 0.0.5
- **Fixed in**: Version **0.0.6** - all attribute names starting with `__` are now always rejected.
- **Workaround for older versions**: leave `allow_attributes` at its default (`False`). There is no complete workaround otherwise - upgrade.
- **Advisory**: a GitHub Security Advisory is being prepared for this issue and will be published together with v0.0.6, at which point a CVE ID will be requested and assigned. Track it under [GitHub Security Advisories](https://github.com/Infinitode/CodeSafe/security/advisories).

### Critical Vulnerability Fixed in v0.0.5

**Versions 0.0.1 through 0.0.4 contain a known sandbox escape vulnerability in `safe_eval()` that allows arbitrary code execution.**

See the security advisory: https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8 (CVE ID: CVE-2026-133467 · CVSS 3.1 score: 9.8)

- **Vulnerability**: The `safe_eval()` function in versions 0.0.1-0.0.4 is vulnerable to a sandbox escape via indirect subscript lookup (e.g., `__builtins__['exec'](...)`). This bypasses the AST validation and allows execution of arbitrary Python code.
- **Impact**: An attacker controlling an expression passed to `safe_eval()` can execute arbitrary Python code with the application's permissions.
- **Affected Versions**: 0.0.1, 0.0.2, 0.0.3, 0.0.4
- **Fixed In**: Version 0.0.5 and later

**If you are using any version from 0.0.1 to 0.0.4, you should upgrade to version 0.0.6 or later immediately.** These earlier versions should **not** be used in untrusted expression evaluation environments.

The fix includes:
1. Rejecting all `ast.Call` nodes unless the exact target is explicitly whitelisted (including calls via subscript, attribute, and other indirect targets)
2. Using a minimal built-ins allowlist that excludes dangerous functions like `exec`, `eval`, `compile`, and `__import__`
3. Added comprehensive regression tests for indirect call targets

Version **0.0.6** additionally closes this second, related sandbox issue: with `allow_attributes=True`, dunder attributes such as `__class__` could be read indirectly through string arguments (e.g., `().__getattribute__('__class__')`), bypassing the dunder blocklist. All attribute names starting with `__` are now always rejected.

A huge thanks to [@hkmj19](https://github.com/hkmj19)/[Linkedin](https://www.linkedin.com/in/hemanth-kumar-mj-24b50a256/) for finding and reporting this vulnerability.

## Vulnerability & Security Testing ([`test_poc_vulnerability.py`](https://github.com/Infinitode/CodeSafe/blob/main/test_poc_vulnerability.py))

> [!NOTE]
> These tests are only available on GitHub, and not on PyPI. They are external tests that aren't built along with `CodeSafe` versions.

CodeSafe v0.0.6 includes a rigorous test suite (`TestVulnerabilityFixes`, `TestEdgeCases` and `TestHardeningRegression` in `test_poc_vulnerability.py`, plus `test.py`) to systematically verify that `safe_eval` blocks sandbox escapes while preserving standard evaluation features.

### Test Results Summary

**79/79 Tests Passing** (`100% Pass Rate` across all vector categories)

| Attack Vector / Category | Specific Vectors Tested | Status |
| :--- | :--- | :--- |
| **AST Subscript & Indirect Calls** | `__builtins__['exec']()`, `__builtins__['eval']()`, `__builtins__['__import__']()`, `getattr(__builtins__, 'exec')`, nested subscript access | **[PASS] Blocked** |
| **Dunder Attribute Escapes** | `__class__`, `__bases__`, `__mro__`, `__subclasses__`, `__globals__`, `__closure__`, `__code__`, `__dict__`, `__getattribute__` (all dunders, including string-argument indirection) | **[PASS] Blocked** |
| **Class Hierarchy Traversal** | `object.__subclasses__()`, `type().subclasses()` | **[PASS] Blocked** |
| **Expression Bypasses** | Comprehensions (list, dict, set), generator expressions, short-circuit logic (`and`/`or`), ternary operators, tuple unpacking, walrus operator (`:=`), lambda calls | **[PASS] Blocked** |
| **Module & I/O Execution** | Direct/from `import`, `os.system`, `subprocess`, `io.open`, `socket`, `requests`, `urllib`, `pathlib` write operations | **[PASS] Blocked** |
| **Dangerous Built-ins** | `exec()`, `eval()`, `compile()`, `input()`, `open()` (default settings), modifying `__builtins__`, `dir()`, `id()` | **[PASS] Blocked** |
| **Resource & Process Safety** | Timeout always terminates the child process (no leaked runaway processes); non-positive timeouts rejected | **[PASS] Enforced** |
| **Error Handling** | Unserializable results (e.g. generators) raise a clear `RuntimeError`; lambdas and dynamic classes round-trip via cloudpickle; child exceptions propagate with their original type; `queue.empty()` race eliminated | **[PASS] Working** |
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

### Changelog v0.0.6:

* **Security Fix**: With `allow_attributes=True`, *all* attribute names starting with `__` are now rejected (previously only a cherry-picked list of dunders, which was bypassable via string arguments, e.g. `().__getattribute__('__class__')`). See the [Security Advisory](#security-advisory) above.
* **Security**: Timed-out evaluations always terminate the child process. Previously `immediate_termination=False` leaked an unkillable, CPU-spinning process; the parameter is deprecated and ignored.
* **Changed**: `encrypt()` now uses authenticated cryptography - Fernet (AES-128-CBC + HMAC-SHA256) with a 256-bit key - instead of the Caesar/mapping obfuscation. Any Unicode source code round-trips losslessly. Keys come from the `key` argument (see the new `generate_key()`), the `CODESAFE_KEY` environment variable, or a built-in default key (public; obfuscation-grade only - supply your own key for real confidentiality). Files written by `encrypt_to_file()` now contain `# codesafe:v2:<token>`; legacy pre-0.0.6 `.encrypt` files are still fully readable and runnable via `decrypt()`, `decrypt_to_file()` and `run()`.
* **Changed**: The Caesar `mapping` parameter was removed from `encrypt()` (passing it raises `TypeError`). It is still accepted by `decrypt()`/`decrypt_to_file()`/`run()` for decrypting legacy payloads.
* **Changed**: Evaluation results are serialized with `cloudpickle` (returned from a subprocess), so lambdas and dynamically created classes can now be returned from `safe_eval()`. Results that cannot be serialized (e.g. generators) still raise a clear `RuntimeError` instead of a misleading `EvaluationTimeoutError`, and the `queue.empty()` race that could drop valid results is eliminated.
* **Changed**: `restricted_imports` was removed from `safe_eval()` - it was redundant (imports are rejected in expressions regardless) and misleading.
* **Bug Fix**: `decrypt()` validates its input and produces clear errors for corrupt/tampered payloads (wrong key, corrupted or tampered v2 data is detected by the HMAC).
* **Bug Fix**: Non-positive `timeout` values are rejected with `ValueError`.
* Exceptions from the evaluation child process now propagate with their original type (including `BaseException`); exception chaining (`raise ... from e`) is used throughout; decrypted code executed via `run()` gets a clean `__main__` namespace isolated from CodeSafe's module globals.
* Removed `dir()` and `id()` from the default safe builtins (pure information leakage with no legitimate use in expressions).
* All encryption/decryption file operations now explicitly use UTF-8.
* The package now depends on `cryptography` and `cloudpickle` (installed automatically by pip).
* Packaging modernized: PEP 621 `pyproject.toml`; source distributions and wheels build correctly from a fresh checkout (the `{{VERSION_PLACEHOLDER}}` version made `pip install .` and `python -m build` fail). Trusted Publishing (OIDC) is used for PyPI releases - no stored API tokens - and releases carry PEP 740 provenance attestations, shown on PyPI.
* A test workflow runs the full test suite on Python 3.8-3.12 across Linux, Windows and macOS for every push and PR.
* Added [SECURITY.md](SECURITY.md) with instructions for reporting vulnerabilities privately. The security notes and limitations previously tracked in a separate audit file are now maintained in this README (see [Security Limitations & Notes](#security-limitations--notes)).

### Changelog v0.0.5:

> [!WARNING]
> **v0.0.5 (and earlier) has a second, known sandbox-escape issue**, fixed in v0.0.6: with `allow_attributes=True`, dunder attributes could be read through string arguments (e.g. `().__getattribute__('__class__')`), bypassing the dunder blocklist. See the [Security Advisory](#security-advisory) section. **If you use `allow_attributes=True` on 0.0.5 or earlier, upgrade to v0.0.6 now.**

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

You can install CodeSafe using pip (it automatically installs the `cryptography` and `cloudpickle` dependencies):

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
* **Serialization boundary.** Results cross the subprocess boundary via `cloudpickle` (lambdas and dynamic classes round-trip; generators and modules cannot be serialized and raise a clear `RuntimeError`). Only deserialize results produced by CodeSafe's own child process - like any pickle-family tool, cloudpickle data must come from a trusted producer.
* **`type` remains in the default safe builtins** (needed for `isinstance`-style patterns and `type(x)` introspection). With all dunder attributes rejected, it does not on its own yield an escape path, but it is the remaining reflection-adjacent primitive and is worth watching.
* **Integrity of v2 payloads is enforced by HMAC**, but payloads carry no identity - a valid token only proves it was produced with the key, not *who* produced it. The legacy Caesar format (pre-0.0.6) has no integrity or authenticity at all.
* **Custom Caesar mappings** (legacy) had a fixed 64-character-value requirement and are no longer produced by `encrypt()`; they are only honored when decrypting legacy payloads.
* **Results must be serializable.** Lambdas and dynamic classes work; generators, modules, open file objects, frames and locks do not.

## Contributing

Contributions are welcome! If you encounter any issues, have suggestions, or want to contribute to CodeSafe, please open an issue or submit a pull request on [GitHub](https://github.com/infinitode/codesafe?utm_source=gemini).

## License

CodeSafe is released under the terms of the **MIT License (Modified)**. Please see the [LICENSE](https://github.com/infinitode/codesafe/blob/main/LICENSE?utm_source=gemini) file for the full text.

**Modified License Clause**

The modified license clause grants users the permission to make derivative works based on the CodeSafe software. However, it requires any substantial changes to the software to be clearly distinguished from the original work and distributed under a different name.
