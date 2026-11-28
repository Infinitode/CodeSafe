import sys, time, traceback
print("PYTHON:", sys.version, flush=True)
import codesafe
print("codesafe imported:", codesafe.__version__, flush=True)
from codesafe import safe_eval, UnsafeExpressionError, EvaluationTimeoutError

checks = []
def chk(name, fn):
    t0 = time.perf_counter()
    try:
        fn()
        checks.append((name, "PASS", (time.perf_counter()-t0)*1000))
    except Exception as e:
        checks.append((name, f"FAIL {type(e).__name__}: {str(e)[:120]}", (time.perf_counter()-t0)*1000))

chk("basic", lambda: safe_eval("1+1"))
chk("attr", lambda: safe_eval("'hi'.upper()", allow_attributes=True))
chk("container", lambda: safe_eval("[1,2]", allow_objects=True))
chk("float", lambda: safe_eval("1.5"))
chk("bytes", lambda: safe_eval("b'x'"))
chk("timeout", lambda: safe_eval("f()", allowed_vars={"f": lambda: [x for x in iter(int,1)]}, allowed_function_calls=["f"], timeout=0.3))
chk("lambda-reject", lambda: safe_eval("lambda: 1"))
for name, status, ms in checks:
    print(f"{status:8} {ms:8.1f}ms  {name}", flush=True)
sys.exit(0 if all(s == "PASS" for _, s, _ in checks) else 1)
