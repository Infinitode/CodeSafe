import unittest
import os
from codesafe import safe_eval, encrypt_to_file, encrypt, decrypt_to_file, decrypt, run, EvaluationTimeoutError, UnsafeExpressionError

from time import sleep

LEGACY_PAYLOAD = "NDc7Z2g8ZjhkOmQ3N2c0PGg4OWZnPGRoNGQ4ODdlaTk6Ozc6ZGllM2Y4O2k5aDQ1aWQ1PGRmOmdnaWZkPDw3Mzc4NzY3PGg3NTVpMzg1PDo0PDRoZGc0Nmg1NGc2Z2U4NTNoOGRlaGk4NTM4OGg3PDk3ZTs1aWU1NDZpODw2ZDRnaDpnNGU6NTRkNGgzOTY1ZTpmaTM3aGdpODM2NWY7aGZpaWQ8aTxkMzs3PDU0ODVlPDU5aTRkOGQ6aDo5OGc6NGU0OWU0Z2k4NjtlZDQ1Z2Y2aTw6aGdlZTs4ZmRkOjM4M2c3OWY0Nzs0Njc1PDNpaGVkOzNpOzU2OWY7NmdlPGg2ZTw7ZDdnZDY0ZDQ1Omc3ZWdoOWg3NjM2Nmk5OWVkNTo3ZmRlM2hlOmhlNGY6M2hmNzQ3MzVlaTk1OjZnZzs2NWhlZTRkZWZmNGY5MzRmaGU8ZjdoNmY3aWRlZDNmZGQ4ZTs4ZWU8O2Y3aTRoOTk0NWY3M2lkZDg1O2Q8NGY8NTk4aWdkNDpkNjc5NDRlNDg2Nmc7ZDU7NGlpOTszZ2Y4Ojw0ZTNmaDNkNDRmNThlNjhoNDRmO2g6ODk7ODgzPGRmZGY7OWYzaDkzPGZkPDM5aTk2NWUzaDVnZGZmZmU1ZTo6ZzU1ZTM5NTRpNTNoZWhmaDRkNzs2OGU8Nmk5aTM2aTo8ZWU6ZTc2OGUzODY1NDk4NGdkaGlnNjo3ZmdmOTs0Z2YzOWlkZDk4aDY6N2g2OzY2OmU7O2ZkMzc5Z2hkZmczZGQ8Ozg5NDc6ZTlmOGU3aWk1ZTpnaWhoOGdkNTNkZDY7NTg2Mzw8aGk0ZTdkOTdkZmhnNTY2ZjxkaWg1PGZkPDo7NDQ1ZmQ0ZWVnZmRpZGY1NjRlNjxkNTZnZjdnZDo7OWhpaTs0NzpmN2g6NWU8OzM6Ojs4ZGloaDc7ZWU1aDpnNWYzNmQ8ODM6ZGg1OThoZmk4ZTg2ODk7OzhkODY2PDZkNTM1PGc1NzQ2PDc8PDo1OThkNGQ1OGRoaWY5ZDRpZmg3Njk2Ozg3aWk7OztmaWk3ZTtoOjs6OGc5MzNmNTk7NTY8Mzc0NWQ7Zmk6PGU2OmczZTQ0NDc7ZTNpZDY5ZDxoOmk0Zjw4ZTs1aWllPDw6NzZoM2Y4ZjdmaDw4Zzs2ZjxkNzYzZGRmODxpOzdoaTZmZWlkZTk0NzgzOTs4M2g6NTRoNzxmMzQ2aTMzZjk1Zmk4PGk1NDk2ODc1ZDxnO2dpMzU3OTdoaWhlOTQ4ZzY0Mzg0ZTNpZ2dmNjU5OThmOjdmNDhkOTs5NDs6ZWU5ZWVpPDw4O2k3PDdpZjllOzMzOTszNjdkOTg8ZDxkZzc3PDw0ZTM7Zjg7aTVnNTc4NzY3PGg3NTVpMzg1PDo0PDRoZGc0Nmg1NGc2Z2U4NTNoOGRlaGk4NTM4OGg3PDk3ZTs1aWU1NDZpODw2ZDQ7NTg3ZjY1PGQ8NTs4M2k5Zzg2PGdnNjo5aTc7NDloaDU6OTc4NDpnZDhoMzU2ODg0N2RpNzY2NDk3NzszZzpkMzc2ZDo0Ozo6N2Y4OjVlZztkNThkZ2VoZTRlaWZnOGYzNTg5ZGg0NGZoZmk8aTxmNmk8NThnM2g4NWVoZGk7PDU5OGlnZDQ6ZDY3OTQ0ZTQ4NjZnO2Q1OzRpaTk7M2dmODo8NGUzZmgzZDQ0ZjU4ZTY4aDQ0ZjtoOjg5Ozg4MzxlZDhoZjg0ZzM6ZDdkZjNoPDg0OTM7OjM3NzY0Zzg8ZDM1ZTU0ZDdoPDg0ZGZmNDM4MzhkO2dmNzM6ZjgzNGho"  # produced by CodeSafe <= v0.0.5 encrypt()

# Custom function defined for testing
def custom_sum(a, b):
    return a + b

def long_running_function():
    while True:
        pass  # This will run indefinitely until the timeout occurs

class TestCodeSafe(unittest.TestCase):

    def setUp(self):
        # Set up the safe environment with custom variables and functions
        self.safe_builtins = {"abs": abs, "max": max}
        self.safe_vars = {"x": 10, "y": 20, "custom_sum": custom_sum, "long_running_function": long_running_function, "sleep": sleep}
        self.allowed_function_calls = ['custom_sum', 'max', 'abs', 'long_running_function', 'sleep']

        # Sample Python code for testing encryption and decryption
        self.python_code = """
def greet(name):
    print(f"Hello, {name}!")

greet('Johnny')
"""

        # File names for testing
        self.encrypted_file = "encrypted_code.encrypt"
        self.decrypted_file = "decrypted.py"

    def test_custom_sum(self):
        expression = "custom_sum(x, y)"

        result = safe_eval(
            expression,
            allowed_builtins=self.safe_builtins,
            allowed_vars=self.safe_vars,
            timeout=3,
            allowed_function_calls=self.allowed_function_calls,
            file_access=False
        )

        self.assertEqual(result, 30)

    def test_safe_attribute_access(self):
        expression = "'hello'.upper()"
        result = safe_eval(expression, allow_attributes=True)
        self.assertEqual(result, "HELLO")

    def test_unsafe_attribute_access(self):
        expression = "().__class__.__bases__[0]"
        with self.assertRaises(UnsafeExpressionError):
            safe_eval(expression, allow_attributes=True)

    def test_attribute_access_disabled(self):
        expression = "'hello'.upper()"
        with self.assertRaises(UnsafeExpressionError):
            safe_eval(
                expression,
                allow_attributes=False  # Explicitly disable
            )

    def test_security_error_on_unsafe_function(self):
        expression = "os.getcwd()"  # Attempting to call an unsafe function
        with self.assertRaises(UnsafeExpressionError):
            safe_eval(
                expression,
                allowed_builtins=self.safe_builtins,
                allowed_vars=self.safe_vars,
                timeout=3,
                    allowed_function_calls=self.allowed_function_calls
            )

    def test_timeout_error(self):
        expression = "long_running_function()"  # This will run indefinitely

        # Check if EvaluationTimeoutError is raised
        with self.assertRaises(EvaluationTimeoutError):
            safe_eval(
                expression,
                allowed_builtins=self.safe_builtins,
                allowed_vars=self.safe_vars,
                timeout=1,  # Setting a short timeout
                    allowed_function_calls=self.allowed_function_calls,
                immediate_termination=True
            )

    def test_encryption(self):
        # Encrypt and save the code to a file
        encrypt_to_file(self.python_code, self.encrypted_file)

        # Check if the encrypted file was created
        self.assertTrue(os.path.exists(self.encrypted_file))

    def test_decryption_and_run(self):
        # Encrypt the code first
        encrypt_to_file(self.python_code, self.encrypted_file)

        # Decrypt and run the code from the file
        run(self.encrypted_file)

        # Decrypt to a file
        decrypt_to_file(self.encrypted_file, self.decrypted_file)

        encrypted = encrypt("print('Hello.')")
        decrypted = decrypt(encrypted)

        print(f"Encrypted: {encrypted}\nDecrypted: {decrypted}")

        # Check if the decrypted file was created
        self.assertTrue(os.path.exists(self.decrypted_file))

        # Optionally: Check if the decrypted file content matches the original code
        with open(self.decrypted_file, 'r') as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content.strip(), self.python_code.strip())

    def test_bytes_and_streams(self):
        import io
        code = b"print('Bytes work')"
        enc = encrypt(code)
        self.assertIsInstance(enc, str)

        # Stream run
        stream = io.StringIO(f"# {enc}")
        run(stream)

        # Stream decrypt
        out_stream = io.StringIO()
        decrypt_to_file(io.StringIO(f"# {enc}"), out_stream)
        self.assertEqual(out_stream.getvalue(), "print('Bytes work')")

    def test_encrypt_supports_unicode(self):
        # v2 crypto payloads are UTF-8 safe: any Unicode code round-trips.
        code = "print('héllo, ✓, 你好')"
        encrypted = encrypt(code)
        self.assertTrue(encrypted.startswith("codesafe:v2:"))
        self.assertEqual(decrypt(encrypted), code)
        encrypted_bytes = encrypt(code.encode("utf-8"))
        self.assertEqual(decrypt(encrypted_bytes), code)

    def test_encrypt_rejects_mapping_argument(self):
        # The Caesar mapping parameter was removed in v0.0.6.
        with self.assertRaises(TypeError):
            encrypt("print('hi')", mapping={"p": "too-short"})
        with self.assertRaises(TypeError):
            encrypt("print('hi')", {"p": "too-short"})

    def test_custom_key_roundtrip_and_wrong_key(self):
        from codesafe import generate_key
        key = generate_key()
        encrypted = encrypt("print('secret')", key=key)
        self.assertEqual(decrypt(encrypted, key=key), "print('secret')")
        with self.assertRaises(ValueError):
            decrypt(encrypted, key=generate_key())

    def test_environment_key_roundtrip(self):
        import os
        from codesafe import generate_key
        key = generate_key()
        os.environ["CODESAFE_KEY"] = key
        try:
            encrypted = encrypt("print('env secret')")
            self.assertEqual(decrypt(encrypted), "print('env secret')")
        finally:
            del os.environ["CODESAFE_KEY"]

    def test_legacy_payload_still_decrypts(self):
        # A payload produced by CodeSafe <= v0.0.5 (Base64 Caesar) must keep
        # working. Generated with codesafe.encrypt_with_mapping() and
        # base64.b64encode(), exactly as <= v0.0.5 produced it.
        legacy = LEGACY_PAYLOAD
        self.assertEqual(decrypt(legacy), "print('legacy works')")

    def test_legacy_file_still_runs_and_decrypts(self):
        import io
        legacy = LEGACY_PAYLOAD
        out = io.StringIO()
        decrypt_to_file(io.StringIO(f"# {legacy}"), out)
        self.assertEqual(out.getvalue(), "print('legacy works')")

    def test_v2_file_roundtrip(self):
        import io
        encrypt_to_file("print('v2 works')", "v2_test_prog.encrypt")
        with open("v2_test_prog.encrypt", "r") as f:
            data = f.read()
        self.assertTrue(data.startswith("# codesafe:v2:"))
        out = io.StringIO()
        decrypt_to_file("v2_test_prog.encrypt", out)
        self.assertEqual(out.getvalue(), "print('v2 works')")

    def test_decrypt_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            decrypt("!!! definitely not base64 !!!")
        with self.assertRaises(ValueError):
            decrypt("codesafe:v2:bm90LWEtdmFsaWQtdG90ZW4")

    def test_exception_propagates_from_evaluation(self):
        with self.assertRaises(ZeroDivisionError):
            safe_eval("1/0")
        with self.assertRaises(NameError):
            safe_eval("this_name_is_not_defined")

    def test_timeout_must_be_positive(self):
        for invalid in (0, -1):
            with self.assertRaises(ValueError):
                safe_eval("1 + 1", timeout=invalid)

    def test_dir_and_id_are_not_available(self):
        # Removed from the default safe builtins: pure information leakage.
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("dir()")
        with self.assertRaises(UnsafeExpressionError):
            safe_eval("id(1)")

    def tearDown(self):
        # Clean up: remove the files created during the tests
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists("v2_test_prog.encrypt"):
            os.remove("v2_test_prog.encrypt")

if __name__ == '__main__':
    unittest.main()
