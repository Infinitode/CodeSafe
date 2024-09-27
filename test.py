import unittest
import os
from codesafe import safe_eval, encrypt_to_file, encrypt, decrypt_to_file, decrypt, run, EvaluationTimeoutError, UnsafeExpressionError

from time import sleep

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
        self.restricted_imports = ['os', 'sys']
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
            restricted_imports=self.restricted_imports,
            allowed_function_calls=self.allowed_function_calls,
            file_access=False
        )

        self.assertEqual(result, 30)

    def test_security_error_on_unsafe_function(self):
        expression = "os.getcwd()"  # Attempting to call an unsafe function
        try:
            safe_eval(
                expression,
                allowed_builtins=self.safe_builtins,
                allowed_vars=self.safe_vars,
                timeout=3,
                restricted_imports=self.restricted_imports,
                allowed_function_calls=self.allowed_function_calls
        )
        except UnsafeExpressionError:
            pass

    def test_timeout_error(self):
        expression = "long_running_function()"  # This will run indefinitely
        # expression = "sleep(5)" # Sleep for 5 seconds

        # Check if EvaluationTimeoutError is raised
        try:
            safe_eval(
                expression,
                allowed_builtins=self.safe_builtins,
                allowed_vars=self.safe_vars,
                timeout=1,  # Setting a short timeout
                restricted_imports=self.restricted_imports,
                allowed_function_calls=self.allowed_function_calls,
                immediate_termination=True
            )
            self.fail("EvaluationTimeoutError not raised")  # Fail if no exception is raised
        except EvaluationTimeoutError:
            pass

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

    def tearDown(self):
        # Clean up: remove the files created during the tests
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)

if __name__ == '__main__':
    unittest.main()
