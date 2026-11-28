import ast
import builtins
import contextlib
import os
import re
import sys
import threading
import multiprocessing
import base64
from multiprocessing import Process, Pipe
from typing import Union, Optional, IO

from cryptography.fernet import Fernet, InvalidToken

__all__ = ['safe_eval', 'EvaluationTimeoutError', 'UnsafeExpressionError',
           'encrypt_to_file', 'encrypt', 'decrypt', 'run', 'decrypt_to_file',
           'generate_key', '__version__']

__version__ = "0.0.7"

# Pre-filtered builtins to speed up safe_eval
# Only include truly safe builtins - exclude exec, eval, compile, __import__, etc.
_SAFE_BUILTIN_NAMES = {
    # Types
    'int', 'float', 'complex', 'str', 'bytes', 'bytearray', 'list', 'tuple', 
    'range', 'set', 'frozenset', 'dict', 'bool', 'object',
    # Functions
    'abs', 'all', 'any', 'bin', 'chr', 'divmod', 'enumerate',
    'format', 'hex', 'isinstance', 'issubclass', 'iter', 'len',
    'max', 'min', 'oct', 'ord', 'pow', 'repr', 'reversed', 'round',
    'sorted', 'sum', 'type', 'zip',
    # Exceptions (safe to expose)
    'Exception', 'BaseException', 'ArithmeticError', 'AssertionError', 
    'AttributeError', 'BlockingIOError', 'BrokenPipeError', 'BufferError', 
    'BytesWarning', 'ChildProcessError', 'ConnectionAbortedError', 
    'ConnectionError', 'ConnectionRefusedError', 'ConnectionResetError', 
    'DeprecationWarning', 'EOFError', 'EnvironmentError', 'FileExistsError', 
    'FileNotFoundError', 'FloatingPointError', 'FutureWarning', 
    'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 
    'IndentationError', 'IndexError', 'InterruptedError', 'IsADirectoryError', 
    'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 
    'ModuleNotFoundError', 'NameError', 'NotADirectoryError', 
    'NotImplementedError', 'OSError', 'OverflowError', 
    'PendingDeprecationWarning', 'PermissionError', 'ProcessLookupError', 
    'RecursionError', 'ReferenceError', 'ResourceWarning', 'RuntimeError', 
    'RuntimeWarning', 'StopAsyncIteration', 'StopIteration', 'SyntaxError', 
    'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'TimeoutError', 
    'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 
    'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 
    'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 
    'ZeroDivisionError',
    # Constants
    'True', 'False', 'None',
}

_BASE_BUILTINS = {name: getattr(builtins, name) for name in _SAFE_BUILTIN_NAMES if hasattr(builtins, name)}
_FILE_FUNCS = {'open'}
_NETWORK_FUNCS = {
    'socket', 'requests', 'urllib', 'http.client', 'http.server',
    'ftplib', 'smtplib', 'telnetlib', 'xmlrpc.client'
}

class EvaluationTimeoutError(Exception):
    """Custom exception to handle timeouts during evaluation."""
    def __init__(self, error):
        self.message = f"EvaluationTimeoutError: Evaluation exceeded the maximum execution timeout limit. Reason: {error}"
        super().__init__(self.message)

class UnsafeExpressionError(Exception):
    """Custom exception for unsafe expressions detected in the AST."""
    def __init__(self, error):
        self.message = f"UnsafeExpressionError: An unsafe evaluation expression was detected. Reason: {error}"
        super().__init__(self.message)

# Upper bound on int<->str conversions. Applied only for the duration of a
# safe_eval() call, so the host's own settings are restored afterwards.
_SAFE_INT_MAX_STR_DIGITS = 10_000


@contextlib.contextmanager
def _digit_limit(limit):
    """Temporarily cap int<->str conversion size (Python 3.11+; no-op before)."""
    if not hasattr(sys, "set_int_max_str_digits"):
        yield
        return
    original = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(limit)
    except ValueError:
        yield
        return
    try:
        yield
    finally:
        sys.set_int_max_str_digits(original)


def safe_eval(expr: str,
              allowed_builtins: Optional[dict] = None,
              allowed_vars: Optional[dict] = None,
              timeout: float = 5,
              allowed_function_calls: Optional[list] = None,
              allow_attributes: bool = False,
              immediate_termination: bool = True,
              file_access: bool = False,
              network_access: bool = False,
              allow_objects: bool = False) -> object:
    """
    Safely evaluate a Python expression with limited access to built-ins, custom variables, and optional file access restriction.

    Parameters:
        expr (str): The expression to evaluate.
        allowed_builtins (dict, optional): A dictionary of allowed built-in functions.
        allowed_vars (dict, optional): A dictionary of allowed variables and functions.
        timeout (float, optional): Time limit for evaluation in seconds. Defaults to 5.
        allowed_function_calls (list, optional): A list of allowed function names to call.
        allow_attributes (bool, optional): Whether to allow access to safe attributes and methods (e.g., 'str.upper()'). Defaults to False.
        immediate_termination (bool, optional): Deprecated and ignored. The evaluation process is always terminated when the timeout is exceeded, so a runaway expression can never outlive the call. Accepted for backwards compatibility.
        file_access (bool, optional): Whether to allow file access (open, etc.). Defaults to False.
        network_access (bool, optional): Whether to allow network access (requests, etc.). Defaults to False.
        allow_objects (bool, optional): Whether the result may be a container
            (list/tuple/dict/set) of plain data. Defaults to False, in which case
            only a single plain value (None, bool, int, float, complex, str,
            bytes, Decimal, Fraction) can be returned and a container raises
            ``RuntimeError``. This keeps the default surface minimal; set it to
            ``True`` if your expressions legitimately return collections.

    Returns:
        object: The result of the evaluated expression. Results are restricted to
            plain data - see ``allow_objects``. The outcome travels from the
            evaluation subprocess as plain primitives and is never deserialized
            with pickle/cloudpickle, so a returned value cannot execute code in
            the calling process. Lambdas, classes and instances of user-defined
            types are not returned; they raise ``RuntimeError``.

    Raises:
        EvaluationTimeoutError: If the evaluation exceeds the allowed time.
        RuntimeError: If the evaluation produced no result, or the result is not
            plain data (for example a lambda, a generator, a module or a
            user-defined object).

    .. warning::
       On platforms without ``fork`` (Windows), or when the host application
       has pinned the ``spawn`` start method, ``multiprocessing`` pickles the
       process arguments - including everything in ``allowed_vars`` and
       ``allowed_builtins`` - inside the calling process before the child
       starts. Only pass trusted objects in those dictionaries, as you would
       with any pickle-based API. Where ``fork`` is available and the host has
       not pinned a start method, CodeSafe selects ``fork`` precisely so that
       nothing supplied by the caller is pickled.
        UnsafeExpressionError: If restricted imports or unsafe nodes are detected in the AST.
        SyntaxError: If the expression contains invalid syntax.
        ValueError: If ``timeout`` is not a positive number.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds.")

    # An expression can build arbitrarily large integers in a few operations
    # (e.g. ``10 ** 10 ** 8``). The child enforces a timeout, but constructing
    # or converting such an int can burn CPU in the parent afterwards, so the
    # limit is tightened for the duration of this call (Python 3.11+).
    with _digit_limit(_SAFE_INT_MAX_STR_DIGITS):
        return _safe_eval_impl(
            expr, allowed_builtins, allowed_vars, timeout,
            allowed_function_calls, allow_attributes, file_access,
            network_access, allow_objects,
        )


def _safe_eval_impl(expr, allowed_builtins, allowed_vars, timeout,
                    allowed_function_calls, allow_attributes, file_access,
                    network_access, allow_objects):
    """Body of :func:`safe_eval` (run under the int-digit limit)."""
    allowed_builtins = allowed_builtins or {}
    allowed_vars = allowed_vars or {}
    allowed_function_calls = allowed_function_calls or []

    try:
        parsed_expr = ast.parse(expr, mode='eval')
    except SyntaxError as e:
        raise SyntaxError(f"Invalid syntax: {e}") from e

    _check_ast(parsed_expr, allowed_function_calls, allow_attributes,
               allowed_builtins=allowed_builtins, allowed_vars=allowed_vars)

    # Optimization: Use pre-filtered builtins base
    safe_builtins = _BASE_BUILTINS.copy()

    # Caller-supplied builtins are merged BEFORE the feature flags are applied,
    # so file_access=False cannot be bypassed by passing ``open`` through
    # ``allowed_builtins``.
    if allowed_builtins:
        safe_builtins.update(allowed_builtins)

    if not file_access:
        for func in _FILE_FUNCS:
            safe_builtins.pop(func, None)

    if not network_access:
        for func in _NETWORK_FUNCS:
            safe_builtins.pop(func, None)

    # Set up the globals for eval. ``__builtins__`` cannot be named by the
    # expression: the AST checker rejects it.
    safe_globals = {"__builtins__": safe_builtins}
    if allowed_vars:
        safe_globals.update(allowed_vars)

    # On the 'spawn' start method (the default on Windows and macOS) starting a
    # process pickles the whole Process object, arguments included, *in the
    # caller*. Everything passed through allowed_vars/allowed_builtins would be
    # reduced with pickle in the parent - a deserialization sink in the caller,
    # before any sandbox exists. Where the platform supports it, use fork so the
    # child inherits these objects and nothing is pickled on the way in. When
    # the host application has chosen a start method explicitly we respect it,
    # and spawn's cost is documented in the README.
    context = multiprocessing.get_context()
    if context.get_start_method() == 'spawn' and \
            multiprocessing.get_start_method(allow_none=True) is None:
        try:
            multiprocessing.set_start_method('fork')
            context = multiprocessing.get_context()
        except (ValueError, RuntimeError):
            pass  # platform has no fork; stay on spawn

    parent_conn, child_conn = context.Pipe(duplex=False)
    process = context.Process(target=_eval_in_process, args=(expr, safe_globals, child_conn))

    # Read in a background thread: the child blocks once the OS pipe buffer is
    # full, so the parent must keep draining while it waits. (A large result
    # can exceed the buffer; a synchronous recv() would deadlock against it.)
    received = []
    finished = threading.Event()

    def _reader():
        try:
            received.append(parent_conn.recv())
        except (EOFError, OSError):
            pass
        finally:
            finished.set()

    reader = threading.Thread(target=_reader, name="codesafe-eval-reader", daemon=True)

    try:
        process.start()
        child_conn.close()  # parent must not hold the write end open
        reader.start()
        finished.wait(timeout)

        if not finished.is_set():
            # Give the child a brief grace period to finish, then terminate any
            # runaway process so it can never outlive this call, regardless of
            # the (deprecated) immediate_termination flag.
            finished.wait(0.2)
            if not finished.is_set() or process.is_alive():
                process.terminate()
                process.join()
                raise EvaluationTimeoutError(
                    f"Evaluation exceeded the maximum execution timeout of {timeout} seconds and was terminated."
                )

        process.join(0.2)
        if process.is_alive():
            # The child produced its result but has not exited (for example it
            # spawned a thread); it can no longer affect us, so reap it.
            process.terminate()
            process.join()

        outcome = received[0] if received else None
        if outcome is None:
            raise RuntimeError(
                "The evaluation process finished without returning a result. "
                "This usually means the evaluation crashed the child process."
            )

        if not isinstance(outcome, (tuple, list)) or len(outcome) != 5:
            raise RuntimeError("Failed to deserialize the evaluation result: malformed outcome.")

        kind, payload, error_name, error_message, error_attrs = outcome
        if kind not in _RESULT_KINDS:
            raise RuntimeError(f"Failed to deserialize the evaluation result: unknown kind {kind!r}")

        if kind == 'error':
            raise _rebuild_error(error_name, error_message, error_attrs)
        if kind == 'unserializable':
            raise RuntimeError(
                f"The evaluation result of type '{payload}' cannot be returned. "
                "Only plain data (None, bool, int, float, complex, str, bytes, "
                "Decimal, Fraction) is returned from safe_eval - lambdas, classes, "
                "instances of user-defined types, modules and generators are not."
            )
        if kind == 'depth_exceeded':
            raise RuntimeError(
                f"The evaluation result is nested more than {_MAX_DEPTH} levels deep "
                "and cannot be returned."
            )
        if kind == 'too_large':
            raise RuntimeError("The evaluation result is too large to be returned.")

        result_kind, result_payload = payload
        result = _decode_result((result_kind, result_payload))
        if isinstance(result, (list, tuple, dict, set, frozenset)) and not allow_objects:
            raise RuntimeError(
                "The evaluation returned a container (list, tuple, dict, set). "
                "Returning containers across the process boundary is opt-in: pass "
                "allow_objects=True to receive them, or select a single plain value "
                "from the container (e.g. ``[...][0]``)."
            )
        return result
    finally:
        finished.wait(0.5)  # let the reader finish before the fd disappears
        try:
            parent_conn.close()
        except Exception:
            pass
        try:
            process.join(0)
        except Exception:
            pass
        try:
            process.close()
        except (ValueError, AttributeError):
            pass


# Exceptions that must never escape into the caller: they do not derive from
# Exception, so ``except Exception`` would not catch them, and SystemExit would
# terminate the host process. They are reported as RuntimeError instead.
_CONTROL_FLOW_EXCEPTIONS = frozenset({'SystemExit', 'KeyboardInterrupt', 'GeneratorExit'})


def _rebuild_error(name, message, attrs):
    """Recreate an exception raised by the child from plain, vetted parts."""
    exc_type = getattr(builtins, name, None)
    if name in _CONTROL_FLOW_EXCEPTIONS or not _is_stdlib_error_type(exc_type):
        exc_type = RuntimeError
    try:
        exc = exc_type(message)
    except Exception:
        exc = RuntimeError(message)
    try:
        for attr_name, attr_value in (attrs or ()):
            if attr_name in _ERROR_ATTRS:
                setattr(exc, attr_name, attr_value)
    except Exception:
        pass
    return exc


# ---------------------------------------------------------------------------
# Safe-eval result channel
#
# The child process evaluates the expression and reports its outcome over a
# multiprocessing.Pipe as a self-describing, fixed-shape structure: the kind of
# outcome plus an already-encoded, primitive payload.  The parent NEVER
# deserializes objects it receives - there is no pickle/cloudpickle on the
# boundary at all, so a value produced by the expression has no way to run code
# in the parent.  (Up to v0.0.6 the child sent a cloudpickle blob and the parent
# called cloudpickle.loads() on it, which let an expression smuggle a
# __reduce__ gadget into the caller's process.)
#
# Accepted results are deliberately limited to plain data:
#   * None, True/False, int, float, complex, str, bytes
#   * decimal.Decimal and fractions.Fraction (returned as Decimal/Fraction)
#   * ... optionally nested, but only inside list, tuple, dict and set/frozenset
#
# Anything else - lambdas, classes, instances of user-defined types, modules,
# generators, file objects - raises a clear RuntimeError instead of being
# serialized.  This closes the parent-side deserialization sink completely:
# there is nothing left for a malicious result to hook into.
# ---------------------------------------------------------------------------
_MAX_DEPTH = 100
_MAX_RESULT_NODES = 1_000_000
_MAX_RESULT_BYTES = 1 * 1024 * 1024  # total size of returned str/bytes data
_ATOMIC_TYPES = (type(None), bool, int, float, complex, str, bytes)

_RESULT_KINDS = frozenset({
    'value', 'error', 'unserializable', 'depth_exceeded', 'too_large',
})

# Exception attributes that are safe to carry across the boundary for the
# exceptions CodeSafe itself produces (timeouts, blocked expressions).
_ERROR_ATTRS = ('message',)


def _is_stdlib_error_type(exc_type) -> bool:
    """True if exc_type is a plain builtin exception (no user code attached)."""
    return (
        isinstance(exc_type, type)
        and issubclass(exc_type, BaseException)
        and exc_type.__module__ == 'builtins'
        and getattr(builtins, exc_type.__name__, None) is exc_type
    )


def _encode_result(value):
    """Encode an evaluation result into plain, JSON-compatible primitives.

    Returns ``(kind, payload)`` where ``kind`` is one of ``_RESULT_KINDS``.
    The encoder walks the object graph directly; it never calls ``pickle``,
    ``__reduce__`` or any other serialization hook on the objects it sees.
    """
    budget = [_MAX_RESULT_NODES, _MAX_RESULT_BYTES]  # nodes, bytes

    def enc(obj, depth):
        if depth > _MAX_DEPTH:
            return ('depth_exceeded', None)
        if budget[0] <= 0:
            return ('too_large', None)
        budget[0] -= 1

        cls = type(obj)
        if cls in _ATOMIC_TYPES or obj is None:
            if cls is int:
                return ('i', str(obj))
            if cls is float:
                # float.hex() is exact and also round-trips NaN/inf.
                return ('f', obj.hex())
            if cls is complex:
                return ('c', str(obj))
            if cls in (str, bytes):
                budget[1] -= len(obj)
                if budget[1] < 0:
                    return ('too_large', None)
            return (cls.__name__, obj)

        # Ordered check: subclasses of the atomic types are NOT accepted; only
        # the exact builtin types above are. This keeps the decoder simple and
        # immune to str/int subclasses carrying overridden behaviour.
        name = cls.__module__ + '.' + cls.__qualname__
        # Leaf nodes are returned without the (kind, value) wrapper used for
        # containers below.
        if name == 'decimal.Decimal':
            return ('dec', str(obj))
        if name == 'fractions.Fraction':
            # Copy the integer parts; str(Fraction) would format them as a
            # ratio string and is subject to the digit limit like any other
            # int-to-str conversion. (int.__int__ only exists on 3.11+, so go
            # through int() and verify the exact type rather than calling a
            # version-dependent slot wrapper.)
            numerator = int(obj.numerator)
            denominator = int(obj.denominator)
            if type(numerator) is not int or type(denominator) is not int:
                return ('unserializable', name)
            return ('frac', (str(numerator), str(denominator)))

        if cls is list:
            items = []
            for item in obj:
                kind, payload = enc(item, depth + 1)
                if kind in ('depth_exceeded', 'too_large'):
                    return (kind, None)
                if kind == 'unserializable':
                    return ('unserializable', payload + ' (inside a list)')
                items.append((kind, payload))
            return ('list', items)
        if cls is tuple:
            items = []
            for item in obj:
                kind, payload = enc(item, depth + 1)
                if kind in ('depth_exceeded', 'too_large'):
                    return (kind, None)
                if kind == 'unserializable':
                    return ('unserializable', payload + ' (inside a tuple)')
                items.append((kind, payload))
            return ('tuple', items)
        if cls is set or cls is frozenset:
            items = []
            label = 'frozenset' if cls is frozenset else 'set'
            for item in obj:
                kind, payload = enc(item, depth + 1)
                if kind in ('depth_exceeded', 'too_large'):
                    return (kind, None)
                if kind == 'unserializable':
                    return ('unserializable', payload + f' (inside a {label})')
                items.append((kind, payload))
            return (label, items)
        if cls is dict:
            items = []
            for key, val in obj.items():
                kk, kp = enc(key, depth + 1)
                if kk in ('depth_exceeded', 'too_large'):
                    return (kk, None)
                if kk == 'unserializable':
                    return ('unserializable', kp + ' (as a dict key)')
                vk, vp = enc(val, depth + 1)
                if vk in ('depth_exceeded', 'too_large'):
                    return (vk, None)
                if vk == 'unserializable':
                    return ('unserializable', vp + ' (inside a dict)')
                items.append((kk, kp, vk, vp))
            return ('dict', items)

        return ('unserializable', cls.__module__ + '.' + cls.__qualname__)

    try:
        kind, payload = enc(value, 0)
    except BaseException as exc:  # a hostile container can raise from iteration
        return ('unserializable', f'<{type(exc).__name__} while encoding the result>')
    if kind in ('unserializable', 'depth_exceeded', 'too_large'):
        return (kind, payload)
    return ('value', (kind, payload))


def _decode_result(payload):
    """Rebuild a plain-data result from an encoded, primitive payload.

    Only the primitives produced by :func:`_encode_result` are constructed -
    no class lookup, no imports, no dynamic code.
    """
    def dec(kind, data):
        if kind == 'NoneType':
            return None
        if kind == 'bool':
            return bool(data)
        if kind == 'i':
            return int(data)
        if kind == 'f':
            return float.fromhex(data)
        if kind == 'c':
            return complex(data)
        if kind == 'str':
            return str(data)
        if kind == 'bytes':
            return bytes(data)
        if kind == 'dec':
            import decimal
            return decimal.Decimal(data)
        if kind == 'frac':
            import fractions
            return fractions.Fraction(int(data[0]), int(data[1]))
        if kind == 'list':
            return [dec(k, v) for k, v in data]
        if kind == 'tuple':
            return tuple(dec(k, v) for k, v in data)
        if kind == 'set':
            return {dec(k, v) for k, v in data}
        if kind == 'frozenset':
            return frozenset(dec(k, v) for k, v in data)
        if kind == 'dict':
            return {dec(kk, kp): dec(vk, vp) for kk, kp, vk, vp in data}
        raise RuntimeError(f'Failed to deserialize the evaluation result: unknown kind {kind!r}')

    return dec(payload[0], payload[1])


def _eval_in_process(expr: str, safe_globals: dict, conn):
    """Evaluate ``expr`` in this (child) process and report over ``conn``.

    Only plain-data outcomes leave the process; see the module comment above.
    """
    try:
        result = eval(compile(ast.parse(expr, mode='eval'), "<string>", "eval"), safe_globals)
    except BaseException as exc:
        _send_error(conn, exc)
        return

    try:
        kind, payload = _encode_result(result)
    except BaseException as exc:
        _send_error(conn, exc)
        return

    try:
        conn.send((kind, payload, None, None, None))
    except OSError:
        pass  # parent went away (timeout) - nothing left to report to


def _send_error(conn, exc):
    """Report an exception raised by the expression, without pickling it.

    User-defined exception types are not reconstructed in the parent (that
    would be a deserialization sink). Their type name is reported with a plain
    ``RuntimeError`` instead, which keeps ``except RuntimeError`` working
    without letting attacker-controlled code run in the parent.
    """
    try:
        if _is_stdlib_error_type(type(exc)):
            attrs = []
            for attr in _ERROR_ATTRS:
                if attr in getattr(exc, '__dict__', {}):
                    attrs.append((attr, str(getattr(exc, attr))))
            conn.send(('error', None, type(exc).__name__,
                       str(exc), tuple(attrs)))
        else:
            conn.send(('error', None, 'RuntimeError',
                       f'Evaluation failed with {type(exc).__name__}: {exc}', ()))
    except BaseException:
        try:
            conn.send(('error', None, 'RuntimeError',
                       'The evaluation failed with an exception that could not be reported.', ()))
        except BaseException:
            pass


# Method names that interpret their string arguments as format templates.
# ``'{0.__class__}'.format(obj)`` never produces an ast.Attribute node for
# ``__class__`` - the traversal happens inside str.format - so these names are
# treated as attribute access for the purposes of the dunder/attribute policy.
_FORMAT_METHODS = frozenset({'format', 'format_map'})

# Keywords whose value is invoked by the callee. A function passed as a sort
# key or a default factory is called even though it is never the target of a
# Call node, so the same "is this callable allowed?" policy applies to them.
_CALLBACK_KEYWORDS = frozenset({'key', 'default_factory'})

# Builtins that invoke a callable argument. ``sorted(x, key=f)`` and
# ``iter(f, None)`` never spell a call to ``f``, but they do call it, so a
# callable passed to any of these is subject to the call policy too.
_CALLABLE_ACCEPTING_BUILTINS = frozenset({'sorted', 'iter', 'map', 'filter', 'min', 'max'})

# Names that are never resolvable from an expression. ``__builtins__`` exposes
# the whole (restricted) builtins mapping, which is unnecessary surface even
# though the mapping itself is already filtered.
_DENIED_NAMES = frozenset({'__builtins__', '__import__', 'eval', 'exec', 'compile',
                           'globals', 'locals', 'vars', 'dir', 'getattr', 'setattr',
                           'delattr', 'input', 'breakpoint', 'memoryview', 'open'})


def _FORMAT_STRING_HAS_DUNDER(template: str) -> bool:
    """True if a str.format template names a dunder attribute at all."""
    return re.search(r'(?<![\w])__[A-Za-z0-9_]*__', template) is not None


def _FORMAT_STRING_TRAVERSES_ATTRIBUTES(template: str) -> bool:
    """True if a str.format template reaches inside an object.

    ``format``/``format_map`` look up attribute names and mapping keys named in
    a replacement field - ``'{0.__class__}'.format(obj)`` reads ``__class__``
    without ever producing an ``ast.Attribute`` node, and ``'{0[secret]}'``
    reads a mapping key. Both are access paths the AST never sees, so any field
    that is more than a plain positional/named reference is rejected. Nested
    fields in a format spec (``{0:{1}}``) are unwrapped and checked too.
    """
    probe = template
    for _ in range(4):  # unwrap nested replacement fields a few levels deep
        found = False
        for match in re.finditer(r'\{([^{}]*)\}', probe):
            field = match.group(1)
            if not field or field.startswith(('!', ':')):
                continue  # automatic field, e.g. "{}", "{!r}" or "{:>10}"
            name = re.split(r'[!:\[.]', field, maxsplit=1)[0]
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*|\d+', name):
                found = True
                break
            rest = re.split(r'[!:]', field[len(name):], maxsplit=1)[0]
            if rest:
                # Something other than a conversion/format spec follows the
                # field name: ".attr" or "[key]" - an access we cannot see.
                found = True
                break
        if found:
            return True
        # Re-scan the inside of nested spec fields (e.g. {0:{1.__class__}}).
        inner = ''.join(m.group(1) for m in re.finditer(r'\{([^{}]*)\}', probe))
        if '{' not in inner and '}' not in inner:
            break
        probe = probe.replace('{{', '{').replace('}}', '}')
    return False


def _check_ast(parsed_expr, allowed_function_calls, allow_attributes,
               allowed_builtins=None, allowed_vars=None):
    """
    Check the AST for unsafe operations such as imports and function calls.

    Parameters:
        parsed_expr (ast.AST): The parsed AST expression.
        allowed_function_calls (list): A list of allowed function calls.
        allow_attributes (bool): Whether to allow attribute access.
        allowed_builtins (dict, optional): Names supplied as builtins.
        allowed_vars (dict, optional): Names supplied as variables.

    Raises:
        UnsafeExpressionError: If unsafe operations are detected in the expression.

    The checks are structural rather than name-by-name:

    * Every ``ast.Call`` target must be a plain ``ast.Name`` that is either a
      safe builtin or explicitly allowed, or (with ``allow_attributes=True``) a
      non-dunder attribute. Calls through subscripts, lambdas and other
      indirections are rejected.
    * A name that the expression itself rebinds (``(len := f)()``, ``[f() for
      len in [..]]``, ``(lambda len: len())(f)``) no longer refers to the safe
      builtin, so it may only be *called* if it is explicitly allowed.
    * Callable values handed to builtins that invoke them (``sorted(key=...)``,
      ``iter(f, None)``, ``map``/``filter``) follow the same policy.
    * All attribute names starting with ``__`` are rejected, and
      ``format``/``format_map`` templates that name attributes or keys are
      rejected: they walk into objects without producing ``ast.Attribute``.
    * The names in ``_DENIED_NAMES`` (``__builtins__``, ``eval``, ``exec``,
      ``compile``, ``__import__``, ...) are never resolvable.
    """
    allowed_function_calls = set(allowed_function_calls or ())
    allowed_builtins = allowed_builtins or {}
    allowed_vars = allowed_vars or {}
    # Only these names may reach a callable. allowed_vars entries are data
    # (values may still be callables, which is why passing one somewhere that
    # invokes it is gated on the explicit allowlist); allowed_builtins are
    # exposed names but are not call targets unless also allowlisted.
    callable_names = set(allowed_function_calls) | set(allowed_builtins)
    allowed_names = set(allowed_function_calls) | set(allowed_builtins) | set(allowed_vars)

    # ---- scope analysis -------------------------------------------------
    # Collect every name the expression binds. A comprehension target or a
    # lambda parameter shadows the surrounding scope, so a rebound safe-builtin
    # name is treated as caller data: it may only be called when explicitly
    # allowlisted. This is deliberately conservative across sub-scopes.
    rebound = set()
    for node in ast.walk(parsed_expr):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)

    def _callable_allowed_name(name):
        if name in _DENIED_NAMES:
            return False
        if name in rebound:
            return name in callable_names  # caller-supplied value
        if name in _SAFE_BUILTIN_NAMES or name in callable_names:
            return True
        # Builtin exception/type names are safe callables too (map(str, ...)).
        builtin = getattr(builtins, name, None)
        return isinstance(builtin, type) and builtin.__module__ == 'builtins'

    def _callable_allowed_expr(expr):
        if isinstance(expr, ast.Name):
            return _callable_allowed_name(expr.id)
        if isinstance(expr, ast.Attribute):
            return allow_attributes and not expr.attr.startswith('__')
        return False

    for node in ast.walk(parsed_expr):
        # Imports are never allowed in expressions.
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise UnsafeExpressionError("Imports are not allowed in expressions.")

        # Names: reserved names are never resolvable, whatever the context.
        if isinstance(node, ast.Name) and node.id in _DENIED_NAMES:
            raise UnsafeExpressionError(
                f"Use of the reserved name '{node.id}' is not allowed.")

        # Attribute access is off unless explicitly enabled, and dunder names
        # (__class__, __globals__, __mro__, __dict__, __getattribute__, ...)
        # are always blocked - they are the backbone of every sandbox escape.
        if isinstance(node, ast.Attribute):
            if node.attr.startswith('__'):
                raise UnsafeExpressionError(
                    f"Access to dunder attribute '{node.attr}' is not allowed.")
            if not allow_attributes:
                raise UnsafeExpressionError("Attribute access is disabled.")

        if not isinstance(node, ast.Call):
            continue

        _check_call(node, allowed_function_calls, allowed_names, callable_names,
                    rebound, allow_attributes, _callable_allowed_name, _callable_allowed_expr)


def _check_call(node, allowed_function_calls, allowed_names, callable_names,
                rebound, allow_attributes, callable_allowed_name, callable_allowed_expr):
    """Validate a single ``ast.Call`` node."""
    func = node.func

    # A literal string equal to a reserved name (e.g. eval('...'),  the module
    # name argument of __import__) is never needed. Format templates are
    # validated as templates instead - they may legitimately contain words
    # such as "open" or "format".
    is_format_call = (
        (isinstance(func, ast.Attribute) and func.attr in _FORMAT_METHODS)
        or (isinstance(func, ast.Name) and func.id in _FORMAT_METHODS)
    )
    if not is_format_call:
        for arg in node.args:
            if isinstance(arg, ast.Constant) and arg.value in _DENIED_NAMES:
                raise UnsafeExpressionError(
                    f"Use of the reserved name '{arg.value}' is not allowed.")

    # The call target must be a safe name or an explicitly allowed one.
    if isinstance(func, ast.Name):
        if func.id in _DENIED_NAMES:
            raise UnsafeExpressionError(f"Call to '{func.id}' is not allowed.")
        if func.id in rebound and func.id not in callable_names:
            raise UnsafeExpressionError(
                f"Call through the rebound name '{func.id}' is not allowed. "
                "The expression reassigns this name, so it no longer refers to "
                "the safe builtin; allowlist it explicitly if that is intended.")
        if func.id not in allowed_function_calls and func.id not in _SAFE_BUILTIN_NAMES:
            if func.id not in rebound:  # a rebound name was handled above
                raise UnsafeExpressionError("Function call is not allowed.")
    elif isinstance(func, ast.Attribute) and allow_attributes:
        if func.attr.startswith('__'):
            raise UnsafeExpressionError(
                f"Access to dunder attribute '{func.attr}' is not allowed.")
    else:
        # Calls through subscripts, lambdas, calls, etc. are rejected.
        raise UnsafeExpressionError("Function call is not allowed.")

    # Format templates can traverse attributes and mapping keys, which never
    # appear as AST nodes. Reject templates that do; require attributes to be
    # enabled for formatting at all, since that is what templates exercise.
    if is_format_call:
        if not allow_attributes:
            raise UnsafeExpressionError(
                "Format strings can traverse attributes, so str.format/format_map "
                "require allow_attributes=True.")
        templates = []
        if isinstance(func, ast.Attribute):
            templates.append(func.value)
        templates.extend(node.args)
        for tmpl in templates:
            if not (isinstance(tmpl, ast.Constant) and isinstance(tmpl.value, str)):
                if isinstance(tmpl, ast.Name) and tmpl.id in ('str', 'format'):
                    continue
                if isinstance(func, ast.Attribute) and func.value is tmpl:
                    raise UnsafeExpressionError(
                        "Formatting requires a literal format string.")
                continue
            if _FORMAT_STRING_TRAVERSES_ATTRIBUTES(tmpl.value):
                raise UnsafeExpressionError(
                    "Attribute traversal inside a format string is not allowed.")
            if _FORMAT_STRING_HAS_DUNDER(tmpl.value):
                raise UnsafeExpressionError(
                    "Dunder attribute names inside a format string are not allowed.")
        return

    # Callables passed as values to builtins that invoke them.
    if isinstance(func, ast.Name) and func.id in _CALLABLE_ACCEPTING_BUILTINS:
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if callable_allowed_expr(arg):
                continue
            if isinstance(arg, (ast.Constant, ast.List, ast.Tuple, ast.Dict,
                                ast.Set, ast.JoinedStr)):
                continue  # a literal/container, not a live callable
            raise UnsafeExpressionError(
                "Passing a non-allowed callable to a builtin that invokes it "
                "is not allowed.")
    for kw in node.keywords:
        if kw.arg in _CALLBACK_KEYWORDS and not callable_allowed_expr(kw.value):
            if not isinstance(kw.value, ast.Constant):
                raise UnsafeExpressionError(
                    f"Passing a non-allowed callable as '{kw.arg}' is not allowed.")


# ---------------------------------------------------------------------------
# Encryption
#
# Since v0.0.6 CodeSafe uses real, authenticated cryptography for new
# encryptions: Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography`
# package) with a 256-bit key. Payloads are UTF-8 safe, so ANY source code,
# including non-ASCII text, round-trips losslessly.
#
# The key is resolved in this order:
#   1. the ``key`` argument (``generate_key()`` creates a fresh key),
#   2. the ``CODESAFE_KEY`` environment variable,
#   3. a built-in default key that ships with the package.
#
# The built-in default key is public, so it only protects against casual
# inspection of the payload - it does NOT protect against someone willing to
# read CodeSafe's source. For real protection of confidential code, generate
# your own key and keep it secret.
#
# File format written by encrypt_to_file():
#   # codesafe:v2:<fernet token>
#
# Legacy (<= v0.0.5) payloads - Base64-encoded Caesar cipher - are still fully
# supported by decrypt(), decrypt_to_file() and run() so existing .encrypt
# files keep working. New encryptions always produce v2 payloads.
# ---------------------------------------------------------------------------
_V2_MARKER = "codesafe:v2:"
_V2_TOKEN_PREFIX = "gAAAAA"  # urlsafe-base64 of Fernet's 0x80 version byte

# Built-in default key. Public knowledge - obfuscation-grade only, see above.
_CODESAFE_DEFAULT_KEY = b"mp-yFpyWDo-ho-U1mAFboxbNaESEh-NBnEb_mtQ_4q8="

def generate_key() -> str:
    """
    Generate a fresh encryption key suitable for use with the ``key`` parameter
    or the ``CODESAFE_KEY`` environment variable.

    Returns:
        str: A URL-safe Base64-encoded 256-bit key.
    """
    return Fernet.generate_key().decode("ascii")

def _load_key(key):
    """Resolve the Fernet key: explicit argument > CODESAFE_KEY env > built-in default."""
    if key is None:
        env_key = os.environ.get("CODESAFE_KEY")
        if env_key:
            key = env_key
        else:
            return _CODESAFE_DEFAULT_KEY
    if isinstance(key, str):
        try:
            key = key.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("The encryption key must be URL-safe Base64 ASCII.") from None
    if not isinstance(key, bytes):
        raise TypeError(f"key must be a str, bytes or None, not {type(key).__name__}.")
    try:
        Fernet(key)
    except Exception as e:
        raise ValueError(f"Invalid encryption key: {e}") from None
    return key

def _classify_payload(text: str):
    """Classify an encrypted payload as ``(payload, 'v2' | 'legacy')``."""
    compact = re.sub(r"\s+", "", text.strip())
    if compact.startswith("#"):
        compact = compact[1:]
    if compact.startswith(_V2_MARKER):
        return compact[len(_V2_MARKER):], "v2"
    if compact.startswith(_V2_TOKEN_PREFIX):
        # Bare v2 token (marker stripped)
        return compact, "v2"
    return compact, "legacy"

def _decrypt_v2(token: str, key) -> str:
    if not token:
        raise ValueError("Encryption payload is empty.")
    try:
        plaintext = Fernet(_load_key(key)).decrypt(token.encode("ascii"))
    except InvalidToken:
        raise ValueError(
            "Decryption failed: the key is wrong, or the data is corrupted or tampered with."
        ) from None
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e
    return plaintext.decode("utf-8")

# Legacy (<= v0.0.5) obfuscation layer. Retained only so that existing
# .encrypt files can still be decrypted and executed. New encryptions never
# use this. Not cryptographically secure - never rely on it for confidentiality.
SHIFT = 3  # Caesar cipher shift value
_character_map = {'0': '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', '1': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b', '2': 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35', '3': '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce', '4': '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', '5': 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d', '6': 'e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683', '7': '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451', '8': '2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3', '9': '19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7', 'a': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'b': '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d', 'c': '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6', 'd': '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4', 'e': '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea', 'f': '252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111', 'g': 'cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29', 'h': 'aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123', 'i': 'de7d1b721a1e0632b7cf04edf5032c8ecffa9f9a08492152b926f1a5a7e765d7', 'j': '189f40034be7a199f1fa9891668ee3ab6049f82d38c68be70f596eab2e1857b7', 'k': '8254c329a92850f6d539dd376f4816ee2764517da5e0235514af433164480d7a', 'l': 'acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0', 'm': '62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a', 'n': '1b16b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9', 'o': '65c74c15a686187bb6bbf9958f494fc6b80068034a659a9ad44991b08c58f2d2', 'p': '148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940', 'q': '8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf', 'r': '454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1', 's': '043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89', 't': 'e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8', 'u': '0bfe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6', 'v': '4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080', 'w': '50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326', 'x': '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881', 'y': 'a1fce4363854ff888cff4b8e7875d600c2682390412a8cf79b37d0b11148b0fa', 'z': '594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06', 'A': '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd', 'B': 'df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c', 'C': '6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d', 'D': '3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43', 'E': 'a9f51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58', 'F': 'f67ab10ad4e4c53121b6a5fe4da9c10ddee905b978d3788d2723d7bfacbe28a9', 'G': '333e0a1e27815d0ceee55c473fe3dc93d56c63e3bee2b3b4aee8eed6d70191a3', 'H': '44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21', 'I': 'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c', 'J': '6da43b944e494e885e69af021f93c6d9331c78aa228084711429160a5bbd15b5', 'K': '86be9a55762d316a3026c2836d044f5fc76e34da10e1b45feee5f18be7edb177', 'L': '72dfcfb0c470ac255cde83fb8fe38de8a128188e03ea5ba5b2a93adbea1062fa', 'M': '08f271887ce94707da822d5263bae19d5519cb3614e0daedc4c7ce5dab7473f1', 'N': '8ce86a6ae65d3692e7305e2c58ac62eebd97d3d943e093f577da25c36988246b', 'O': 'c4694f2e93d5c4e7d51f9c5deb75e6cc8be5e1114178c6a45b6fc2c566a0aa8c', 'P': '5c62e091b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d2', 'Q': '4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260', 'R': '8c2574892063f995fdf756bce07f46c1a5193e54cd52837ed91e32008ccf41ac', 'S': '8de0b3c47f112c59745f717a626932264c422a7563954872e237b223af4ad643', 'T': 'e632b7095b0bf32c260fa4c539e9fd7b852d0de454e9be26f24d0d6f91d069d3', 'U': 'a25513c7e0f6eaa80a3337ee18081b9e2ed09e00af8531c8f7bb2542764027e7', 'V': 'de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc', 'W': 'fcb5f40df9be6bae66c1d77a6c15968866a9e6cbd7314ca432b019d17392f6f4', 'X': '4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015', 'Y': '18f5384d58bcb1bba0bcd9e6a6781d1a6ac2cc280c330ecbab6cb7931b721552', 'Z': 'bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83', '!': 'bb7208bc9b5d7c04f1236a82a0093a5e33f40423d5ba8d4266f7092c3ba43b62', '"': '8a331fdde7032f33a71e1b2e257d80166e348e00fcb17914f48bdb57a1c63007', '#': '334359b90efed75da5f0ada1d5e6b256f4a6bd0aee7eb39c0f90182a021ffc8b', '$': '09fc96082d34c2dfc1295d92073b5ea1dc8ef8da95f14dfded011ffb96d3e54b', '%': 'bbf3f11cb5b43e700273a78d12de55e4a7eab741ed2abf13787a4d2dc832b8ec', '&': '951dcee3a7a4f3aac67ec76a2ce4469cc76df650f134bf2572bf60a65c982338', "'": '265fda17a34611b1533d8a281ff680dc5791b0ce0a11c25b35e11c8e75685509', '(': '32ebb1abcc1c601ceb9c4e3c4faba0caa5b85bb98c4f1e6612c40faa528a91c9', ')': 'ba5ec51d07a4ac0e951608704431d59a02b21a4e951acc10505a8dc407c501ee', '*': '684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1', '+': 'a318c24216defe206feeb73ef5be00033fa9c4a74d0b967f6532a26ca5906d3b', ',': 'd03502c43d74a30b936740a9517dc4ea2b2ad7168caa0a774cefe793ce0b33e7', '-': '3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112', '.': 'cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8', '/': '8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1', ':': 'e7ac0786668e0ff0f02b62bd04f45ff636fd82db63b1104601c975dc005f3a67', ';': '41b805ea7ac014e23556e98bb374702a08344268f92489a02f0880849394a1e4', '<': 'dabd3aff769f07eb2965401eb029974ebba3407afd02b26ddb564ea5f8efae72', '=': '380918b946a526640a40df5dced6516794f3d97bbd9e6bb553d037c4439f31c3', '>': '62b67e1f685b7fef51102005dddd27774be3fee38c42965c53aab035d0b6b221', '?': '8a8de823d5ed3e12746a62ef169bcf372be0ca44f0a1236abc35df05d96928e1', '@': 'c3641f8544d7c02f3580b07c0f9887f0c6a27ff5ab1d4a3e29caf197cfc299ae', '[': '245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811', '\\': 'a9253dc8529dd214e5f22397888e78d3390daa47593e26f68c18f97fd7a3876b', ']': 'cfae0d4248f7142f7b17f826cd7a519280e312577690e957830d23dcf35a3fff', '^': '74cd9ef9c7e15f57bdad73c511462ca65cb674c46c49639c60f1b44650fa1dcb', '_': 'd2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde', '`': '8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3', '{': '021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96', '|': 'cbe5cfdf7c2118a9c3d78ef1d684f3afa089201352886449a06a6511cfef74a7', '}': 'd10b36aa74a59bcf4a88185837f658afaf3646eff2bb16c3928d0e9335e945d2', '~': '7ace431cb61584cb9b8dc7ec08cf38ac0a2d649660be86d349fb43108b542fa4', ' ': '36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068', '\t': '2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9', '\n': '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', '\r': '9d1e0e2d9459d06523ad13e28a4093c2316baafe7aec5b25f30eba2e113599c4', '\x0b': 'e7cf46a078fed4fafd0b5e3aff144802b853f8ae459a4f0c14add3314b7cc3a6', '\x0c': 'ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977'}

def _caesar_cipher(text: str, shift: int) -> str:
    """Applies a Caesar cipher to the input text with the given shift."""
    if shift == 0:
        return text
    return "".join(chr((ord(char) + shift) % 256) for char in text)

# Pre-calculated tables for the default character map
_REVERSE_CHARACTER_MAP = {v: k for k, v in _character_map.items()}
_CAESAR_ENCRYPT_TABLE = {
    c: _caesar_cipher(_character_map.get(c, c), SHIFT)
    for c in (chr(i) for i in range(256))
}
_CAESAR_DECRYPT_TRANS = str.maketrans(
    "".join(chr(i) for i in range(256)),
    "".join(chr((i - SHIFT) % 256) for i in range(256))
)

# Encryption and decryption functions using the mapping
def encrypt_with_mapping(code: str, mapping: dict) -> str:
    """Encrypts the code by replacing characters with mapped strings."""
    if mapping is _character_map:
        return "".join(_CAESAR_ENCRYPT_TABLE.get(c, _caesar_cipher(c, SHIFT)) for c in code)

    # Fallback for custom mapping
    mapped = ''.join(mapping.get(char, char) for char in code)
    return _caesar_cipher(mapped, SHIFT)

def decrypt_with_mapping(encrypted_code: str, mapping: dict) -> str:
    """Decrypts the code by replacing mapped strings back to original characters."""
    if mapping is _character_map:
        # Optimization: reverse Caesar first
        decrypted_caesar = encrypted_code.translate(_CAESAR_DECRYPT_TRANS)

        parts = []
        segment_length = 64
        for i in range(0, len(decrypted_caesar), segment_length):
            chunk = decrypted_caesar[i:i+segment_length]
            parts.append(_REVERSE_CHARACTER_MAP.get(chunk, chunk))
        return ''.join(parts)

    # Fallback for custom mapping
    reverse_mapping = {v: k for k, v in mapping.items()}
    decrypted_caesar = _caesar_cipher(encrypted_code, -SHIFT)

    parts = []
    segment_length = 64
    for i in range(0, len(decrypted_caesar), segment_length):
        chunk = decrypted_caesar[i:i+segment_length]
        parts.append(reverse_mapping.get(chunk, chunk))

    return ''.join(parts)

def caesar_cipher(text: str, shift: int) -> str:
    """Applies a Caesar cipher to the input text with the given shift."""
    if shift == 0:
        return text
    if shift == -SHIFT and text:
        return text.translate(_CAESAR_DECRYPT_TRANS)
    return "".join(chr((ord(char) + shift) % 256) for char in text)

def reverse_string(text: str) -> str:
    """Reverses the input string."""
    return text[::-1]

def encrypt(code: Union[str, bytes], key: Optional[Union[str, bytes]] = None, mapping: Optional[dict] = None) -> str:
    """
    Encrypt the code using authenticated cryptography: Fernet (AES-128-CBC +
    HMAC-SHA256) with a 256-bit key. Any Unicode source code is supported -
    the plaintext is UTF-8, so non-ASCII code round-trips losslessly.

    Parameters:
        code (str or bytes): The Python code to encrypt.
        key (str or bytes, optional): URL-safe Base64 256-bit key, as produced by
            ``generate_key()``. Resolution order: this argument, then the
            ``CODESAFE_KEY`` environment variable, then a built-in default key
            (public - obfuscation-grade only).
        mapping (dict): **Removed.** The Caesar-cipher mapping parameter was removed
            in v0.0.6. Passing it raises TypeError.

    Returns:
        str: The encrypted payload, prefixed with ``codesafe:v2:``.

    Raises:
        TypeError: If a legacy ``mapping`` dictionary is passed.
        ValueError: If ``bytes`` input is not valid UTF-8, or the key is invalid.
    """
    if mapping is not None or isinstance(key, dict):
        raise TypeError(
            "The 'mapping' parameter was removed in CodeSafe v0.0.6. "
            "Encryption now uses authenticated cryptography (Fernet). "
            "Use generate_key() to create a key, pass it as key=..., "
            "or set the CODESAFE_KEY environment variable. "
            "Old mapping-encrypted content can still be decrypted by passing "
            "the mapping to decrypt()/decrypt_to_file()/run()."
        )
    if isinstance(code, bytes):
        try:
            code = code.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(f"The bytes input is not valid UTF-8: {e}") from e
    if not isinstance(code, str):
        raise TypeError(f"code must be a str or bytes, not {type(code).__name__}.")

    token = Fernet(_load_key(key)).encrypt(code.encode('utf-8')).decode('ascii')
    return _V2_MARKER + token

def _decrypt_legacy(encrypted_code: str, mapping: dict) -> str:
    """
    Decrypt a pre-0.0.6 Base64 Caesar-cipher payload.

    Kept only so existing .encrypt files keep working. This format is not
    cryptographically secure - never use it for new encryptions.
    """
    try:
        # Tolerate incidental whitespace/newlines, but reject any other
        # characters outside the Base64 alphabet.
        compact = re.sub(r"\s+", "", encrypted_code)
        # Step 1: Decode from Base64
        try:
            base64_decoded = base64.b64decode(compact, validate=True).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Base64 decryption failed: {e}") from e

        if not base64_decoded:
            raise ValueError("Base64 decryption failed. The result is empty.")

        # Combined step: reverse Caesar + reverse Mapping
        original_code = decrypt_with_mapping(base64_decoded, mapping)
        if not original_code:
            raise ValueError("Decryption failed. The result is empty.")

        return original_code
    except Exception as e:
        if isinstance(e, (ValueError, RuntimeError, TypeError)):
            raise
        raise RuntimeError(f"An error occurred during decryption: {e}") from e

def decrypt(encrypted_code: str, key: Optional[Union[str, bytes]] = None, mapping: Optional[dict] = None) -> str:
    """
    Decrypt a payload produced by :func:`encrypt` (v2) or by CodeSafe <= v0.0.5 (legacy).

    Parameters:
        encrypted_code (str): The payload. May be the string returned by
            ``encrypt()`` (``codesafe:v2:...``), a bare v2 token, or a full
            ``# codesafe:v2:...`` comment line such as the one embedded by
            ``encrypt_to_file()``. Legacy Base64 Caesar payloads are detected
            automatically.
        key (str or bytes, optional): Key for v2 payloads. Resolution order:
            this argument, then the ``CODESAFE_KEY`` environment variable, then
            the built-in default key.
        mapping (dict, optional): Legacy Caesar mapping, used only for pre-0.0.6
            payloads. Defaults to the built-in mapping.

    Returns:
        str: The decrypted code.

    Raises:
        ValueError: If the v2 payload cannot be decrypted (wrong key, or the data
            is corrupted or tampered with), or a legacy payload is malformed.
        TypeError: If a v2 payload is combined with a ``mapping`` argument.
    """
    if isinstance(key, dict):  # Legacy positional call: decrypt(payload, legacy_mapping)
        mapping = key
        key = None
    if not isinstance(encrypted_code, str):
        raise TypeError(f"encrypted_code must be a str, not {type(encrypted_code).__name__}.")

    payload, kind = _classify_payload(encrypted_code)
    if kind == "v2":
        if mapping is not None:
            raise TypeError(
                "The 'mapping' parameter only applies to legacy (pre-0.0.6) encrypted "
                "content. For v2 content, pass key=... (or set CODESAFE_KEY) instead."
            )
        return _decrypt_v2(payload, key)
    return _decrypt_legacy(payload, mapping if mapping is not None else _character_map)

def encrypt_to_file(code: Union[str, bytes], output_file: str, key: Optional[Union[str, bytes]] = None, mapping: Optional[dict] = None) -> None:
    """
    Encrypt the given Python code with authenticated cryptography and embed it
    as a comment in a Python file.

    The output file contains a single line of the form ``# codesafe:v2:<token>``,
    which can be executed with :func:`run` and decrypted with :func:`decrypt_to_file`.

    Parameters:
        code (str or bytes): The Python code to encrypt.
        output_file (str): Path of the output Python file to write.
        key (str or bytes, optional): Key for encryption. See :func:`encrypt`.
        mapping (dict): **Removed.** Passing it raises TypeError.

    Returns:
        None
    """
    encrypted_code = encrypt(code, key=key, mapping=mapping)
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(f"# {encrypted_code}")
    except OSError as e:
        raise OSError(f"Failed to write to file '{output_file}': {e}") from e

def decrypt_code(encrypted_code: str, mapping: Optional[dict] = None, key: Optional[Union[str, bytes]] = None) -> str:
    """Decrypt an encrypted payload. Alias of :func:`decrypt` kept for backwards compatibility."""
    return decrypt(encrypted_code, key=key, mapping=mapping)

def _extract_payload(content: str) -> str:
    """Extract the encrypted payload from a file's content (v2 comment, or legacy comment)."""
    match = re.search(r'^# (codesafe:v2:[A-Za-z0-9_-]+={0,2})\s*$', content, re.MULTILINE)
    if match:
        return match.group(1)
    match = re.search(r'^# ([A-Za-z0-9+/=]+)\s*$', content, re.MULTILINE)
    if match:
        return match.group(1)
    raise ValueError("No encrypted code found in the source.")

def _read_source(source) -> str:
    if isinstance(source, str):
        with open(source, 'r', encoding='utf-8') as file:
            return file.read()
    content = source.read()
    if isinstance(content, bytes):
        content = content.decode('utf-8')
    return content

def run(encrypted_source: Union[str, IO], key: Optional[Union[str, bytes]] = None, mapping: Optional[dict] = None) -> None:
    """
    Decrypt and execute the Python code embedded in the specified file or stream.

    The decrypted code is executed with ``__name__`` set to ``"__main__"`` in a
    clean namespace, isolated from CodeSafe's module globals. Encryption
    protects the code at rest and on disk; the decrypted code still runs with
    the full permissions of the current process, so only run code you trust.

    Parameters:
        encrypted_source (str or stream): Path to the file, or a file-like object
            with embedded encrypted code.
        key (str or bytes, optional): Key for v2 payloads. Defaults to
            ``CODESAFE_KEY`` or the built-in default key. A legacy positional
            argument in the ``key`` slot receives a dict and is treated as the
            legacy Caesar ``mapping``.
        mapping (dict, optional): Legacy Caesar mapping for pre-0.0.6 payloads.

    Returns:
        None
    """
    try:
        content = _read_source(encrypted_source)
        payload = _extract_payload(content)
        decrypted_code = decrypt(payload, key=key, mapping=mapping)
    except Exception as e:
        if isinstance(e, (RuntimeError, ValueError, OSError, TypeError)):
            raise
        raise RuntimeError(f"An error occurred during decryption and execution: {e}") from e

    # Execute the decrypted Python code in a clean namespace that looks like a
    # script run as __main__, isolated from CodeSafe's own module globals.
    exec(decrypted_code, {"__name__": "__main__"})

def decrypt_to_file(encrypted_file: Union[str, IO], output_file: Union[str, IO], key: Optional[Union[str, bytes]] = None, mapping: Optional[dict] = None) -> None:
    """
    Decrypt the code embedded in the specified file/stream and write it to an output file/stream.

    Parameters:
        encrypted_file (str or stream): Path to the source or a file-like object.
        output_file (str or stream): Path to the destination or a file-like object.
        key (str or bytes, optional): Key for v2 payloads (see :func:`encrypt`).
        mapping (dict, optional): Legacy Caesar mapping for pre-0.0.6 payloads.

    Returns:
        None
    """
    try:
        if mapping is not None and not isinstance(mapping, dict):
            raise ValueError("The mapping parameter must be a dictionary.")

        content = _read_source(encrypted_file)
        payload = _extract_payload(content)
        decrypted_code = decrypt(payload, key=key, mapping=mapping)

        # Write the decrypted code
        if isinstance(output_file, str):
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(decrypted_code)
        else:
            output_file.write(decrypted_code)

    except Exception as e:
        if isinstance(e, (ValueError, RuntimeError, OSError, TypeError)):
            raise
        raise RuntimeError(f"An error occurred during decryption to file: {e}") from e
