"""Run the unit tests and surface failures as GitHub annotations.

Windows runners execute ``run:`` steps with PowerShell, so shell tricks for
piping or scraping output are not portable. Doing it in Python keeps the
workflow identical on every runner, and the ``::error`` lines land in the
check-run annotations even when the raw job log cannot be retrieved.
"""
import io
import sys
import unittest

RESULT_FILE = "suite-output.txt"


def main():
    sys.path.insert(0, ".")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromName("test"),
        loader.loadTestsFromName("test_poc_vulnerability"),
    ])
    buffer = io.StringIO()
    runner = unittest.TextTestRunner(stream=buffer, verbosity=2)
    result = runner.run(suite)
    output = buffer.getvalue()
    print(output)

    problems = [(str(test), traceback) for test, traceback in
                result.errors + result.failures]
    for name, traceback in problems:
        print(f"::error title={name}::{traceback.strip().splitlines()[-1][:200]}")

    if problems:
        with open(RESULT_FILE, "w", encoding="utf-8") as handle:
            handle.write(output)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
