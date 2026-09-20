# CodeSafe
![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)
[![Code Size](https://img.shields.io/github/languages/code-size/infinitode/codesafe)](https://github.com/infinitode/codesafe)
![Downloads](https://pepy.tech/badge/codesafe)
![License Compliance](https://img.shields.io/badge/license-compliance-brightgreen.svg)
![PyPI Version](https://img.shields.io/pypi/v/codesafe)

An open-source Python library for code encryption, decryption, and safe evaluation using Python's built-in AST module, complete with allowed functions, variables, built-in imports, timeouts, and blocked access to attributes.

*CodeSafe is an experimental library, and we're still running some tests on it. If you encounter any issues, or have an edge use case, please let us know.*

> [!NOTE]
> **CodeSafe** is intended to quickly encrypt/decrypt code files, and run them (only for Python script files) while in their encrypted form, but not as a means for powerful encryption, just code obfuscation. We have also included a `safe_eval` function, that can safely evaluate expressions within a safe environment.

## Security Advisory

### Critical Vulnerability Fixed in v0.0.5

**Versions 0.0.1 through 0.0.4 contain a known sandbox escape vulnerability in `safe_eval()` that allows arbitrary code execution.**

- **Vulnerability**: The `safe_eval()` function in versions 0.0.1-0.0.4 is vulnerable to a sandbox escape via indirect subscript lookup (e.g., `__builtins__['exec'](...)`). This bypasses the AST validation and allows execution of arbitrary Python code.
- **Impact**: An attacker controlling an expression passed to `safe_eval()` can execute arbitrary Python code with the application's permissions.
- **Affected Versions**: 0.0.1, 0.0.2, 0.0.3, 0.0.4
- **Fixed In**: Version 0.0.5 and later

**If you are using any version from 0.0.1 to 0.0.4, you should upgrade to version 0.0.5 or later immediately.** These earlier versions should **not** be used in untrusted expression evaluation environments.

The fix includes:
1. Rejecting all `ast.Call` nodes unless the exact target is explicitly whitelisted (including calls via subscript, attribute, and other indirect targets)
2. Using a minimal built-ins allowlist that excludes dangerous functions like `exec`, `eval`, `compile`, and `__import__`
3. Added comprehensive regression tests for indirect call targets

---

## Vulnerability & Security Testing (`test_poc.py`)

CodeSafe v0.0.5+ includes a rigorous test suite (`TestVulnerabilityFixes` and `TestEdgeCases` in `test_poc.py`) to systematically verify that `safe_eval` blocks sandbox escapes while preserving standard evaluation features.

### Test Results Summary

**49/49 Security & Edge Case Tests Passing** (`100% Pass Rate` across all vector categories)

| Attack Vector / Category | Specific Vectors Tested | Status |
| :--- | :--- | :--- |
| **AST Subscript & Indirect Calls** | `__builtins__['exec']()`, `__builtins__['eval']()`, `__builtins__['__import__']()`, `getattr(__builtins__, 'exec')`, nested subscript access | **[PASS] Blocked** |
| **Dunder Attribute Escapes** | `__class__`, `__bases__`, `__mro__`, `__subclasses__`, `__globals__`, `__closure__`, `__code__` | **[PASS] Blocked** |
| **Class Hierarchy Traversal** | `object.__subclasses__()`, `type().subclasses()` | **[PASS] Blocked** |
| **Expression Bypasses** | Comprehensions (list, dict, set), generator expressions, short-circuit logic (`and`/`or`), ternary operators, tuple unpacking, walrus operator (`:=`), lambda calls | **[PASS] Blocked** |
| **Module & I/O Execution** | Direct/from `import`, `os.system`, `subprocess`, `io.open`, `socket`, `requests`, `urllib`, `pathlib` write operations | **[PASS] Blocked** |
| **Dangerous Built-ins** | `exec()`, `eval()`, `compile()`, `input()`, `open()` (default settings), modifying `__builtins__` | **[PASS] Blocked** |
| **Functional Baseline** | Safe arithmetic, string/list/dict operations, standard safe builtins (`len`, `max`, `abs`), explicitly allowed functions | **[PASS] Working** |

### Running the Proof of Concept Tests

To run the security PoC suite locally:

```bash
python -m unittest test_poc.py -v

```

---

### Changelog v0.0.5:

* **Security Fix**: Patched critical sandbox escape vulnerability in `safe_eval()` (CVE pending)
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

You can install CodeSafe using pip:

```bash
pip install codesafe

```

## Supported Python Versions

CodeSafe supports the following Python versions:

* Python 3.6
* Python 3.7
* Python 3.8
* Python 3.9
* Python 3.10
* Python 3.11/Later (Preferred)

Please ensure that you have one of these Python versions installed before using CodeSafe. CodeSafe may not work as expected on lower versions of Python than the supported.

## Features

* **Safe Eval**: Safely allow `eval()` expressions to run, while maintaining complete control over the entire evaluation process.
* **Code Encryption/Decryption**: Quickly encrypt your code. This is meant for code obfuscation, and not high-level encryption.
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

    result1 = safe_eval(expression, timeout=10, immediate_termination=True)
    result2 = safe_eval(disallowed_expression, timeout=10, immediate_termination=True)

```

> [!NOTE]
> Attribute inspection is disabled when using `safe_eval`. You can read more about how to use `safe_eval` from [here](https://infinitode-docs.gitbook.io/documentation/package-documentation/codesafe-package-documentation?utm_source=gemini).

### Encrypt & Run Code

```python
from codesafe import encrypt_to_file, decrypt_to_file, run

code = """
greetJohnny = "Hello Johnny!"

def greet_someone(greeting):
    print(greeting)

greet_someone(greetJohnny)
"""

# Encrypt the code
encrypted_file_path = "encrypted_code.encrypt"
encrypt_to_file(code, encrypted_file_path)

# Run the encrypted code
run(encrypted_file_path) # Hello Johnny!

# Decrypt code to another file
output_file = "decrypted_code.py"
decrypt_to_file(encrypted_file_path, output_file)

```

## Contributing

Contributions are welcome! If you encounter any issues, have suggestions, or want to contribute to CodeSafe, please open an issue or submit a pull request on [GitHub](https://github.com/infinitode/codesafe?utm_source=gemini).

## License

CodeSafe is released under the terms of the **MIT License (Modified)**. Please see the [LICENSE](https://github.com/infinitode/codesafe/blob/main/LICENSE?utm_source=gemini) file for the full text.

**Modified License Clause**

The modified license clause grants users the permission to make derivative works based on the CodeSafe software. However, it requires any substantial changes to the software to be clearly distinguished from the original work and distributed under a different name.