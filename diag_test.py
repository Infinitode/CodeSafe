"""Temporary CI diagnostic: exercise the paths most likely to be
version/platform sensitive and print full tracebacks."""
import platform
import sys
import traceback


def section(name):
    print(f"\n=== {name} ===", flush=True)


def show(label, fn):
    try:
        value = fn()
        print(f"  OK   {label}: {value!r}"[:200], flush=True)
        return True
    except BaseException as exc:  # noqa: BLE001 - diagnostics
        print(f"  FAIL {label}: {type(exc).__name__}: {exc}", flush=True)
        traceback.print_exc()
        print(f"::error title={label}::{type(exc).__name__}: {exc}", flush=True)
        return False


def main():
    section("environment")
    print(f"  python: {sys.version}", flush=True)
    print(f"  platform: {platform.platform()}", flush=True)
    import multiprocessing
    print(f"  start method: {multiprocessing.get_start_method(allow_none=True)}", flush=True)
    try:
        print(f"  available: {multiprocessing.get_all_start_methods()}", flush=True)
    except Exception as exc:
        print(f"  get_all_start_methods failed: {exc}", flush=True)

    section("import")
    ok = show("import codesafe", lambda: __import__("codesafe").__version__)
    if not ok:
        return 1
    from codesafe import EvaluationTimeoutError, safe_eval

    section("basic evaluation")
    show("arithmetic", lambda: safe_eval("1 + 1"))
    show("attribute", lambda: safe_eval("'hi'.upper()", allow_attributes=True))
    show("container", lambda: safe_eval("[1, 2]", allow_objects=True))
    show("float", lambda: safe_eval("1.5"))
    show("bytes", lambda: safe_eval("b'x'"))
    show("none", lambda: safe_eval("None"))

    section("result boundary")
    show("lambda rejected", lambda: _expect(RuntimeError, lambda: safe_eval("lambda: 1")))

    section("timeout / process handling")
    show("timeout", lambda: _expect(
        EvaluationTimeoutError,
        lambda: safe_eval("f()", allowed_vars={"f": _spin},
                          allowed_function_calls=["f"], timeout=0.3)))
    show("after timeout", lambda: safe_eval("1 + 1"))

    section("encryption")
    def _crypto():
        from codesafe import decrypt, encrypt, generate_key
        key = generate_key()
        return decrypt(encrypt("print(1)", key=key), key=key)
    show("roundtrip", _crypto)

    return 0


def _spin():
    while True:
        pass


def _expect(exc_type, fn):
    try:
        fn()
    except exc_type as exc:
        return f"raised {type(exc).__name__}"
    raise AssertionError(f"expected {exc_type.__name__}")


if __name__ == "__main__":
    sys.exit(main())
