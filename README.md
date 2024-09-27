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

## Installation

You can install CodeSafe using pip:

```bash
pip install codesafe
```

## Supported Python Versions

CodeSafe supports the following Python versions:

- Python 3.6
- Python 3.7
- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11/Later (Preferred)

Please ensure that you have one of these Python versions installed before using CodeSafe. CodeSafe may not work as expected on lower versions of Python than the supported.

## Features

- **Safe Eval**: Safely allow `eval()` expressions to run, while maintaining complete control over the entire evaluation process.
- **Code Encryption/Decryption**: Quickly encrypt your code. This is meant for code obfuscation, and not high-level encryption.
- **Run encrypted code at runtime**: Run your encrypted code files, without needing to expose your code to end-users.

> [!NOTE]
> Running encrypted files at runtime using `run()` are only available in formats that can be understood by Python.

> [!IMPORTANT]
> When running `safe_eval`, make sure to wait for the Python file to finish its bootstrapping phase. This can be done by simple waiting for:
> ```python
> if __name__ == '__main__':
>    # Run eval, etc.
> ```
> If you're planning on including `safe_eval` in executables:
> ```python
> import multiprocessing
> if __name__ == '__main__':
>       multiprocessing.freeze_support()
>       # Call safe_eval afterwards
> ```
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
> Attribute inspection is disabled when using `safe_eval`. You can read more about how to use `safe_eval` from [here](https://infinitode-docs.gitbook.io/documentation/package-documentation/codesafe-package-documentation).

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

Contributions are welcome! If you encounter any issues, have suggestions, or want to contribute to CodeSafe, please open an issue or submit a pull request on [GitHub](https://github.com/infinitode/codesafe).

## License

CodeSafe is released under the terms of the **MIT License (Modified)**. Please see the [LICENSE](https://github.com/infinitode/codesafe/blob/main/LICENSE) file for the full text.

**Modified License Clause**

The modified license clause grants users the permission to make derivative works based on the CodeSafe software. However, it requires any substantial changes to the software to be clearly distinguished from the original work and distributed under a different name.
