import ast
import builtins
from multiprocessing import Process, Queue
import base64
import re
import gc

__all__ = ['safe_eval', 'EvaluationTimeoutError', 'UnsafeExpressionError', 'encrypt_to_file', 'encrypt', 'decrypt', 'run', 'decrypt_to_file']

def cleanup_resources():
    """
    Clean up all open resources by closing them.
    """
    gc.collect()  # Force garbage collection

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

def _eval_in_process(expr: str, safe_globals: dict, queue: Queue):
    """Function to evaluate the expression in a separate process."""
    try:
        result = eval(compile(ast.parse(expr, mode='eval'), "<string>", "eval"), safe_globals)
        queue.put(result)
    except Exception as e:
        queue.put(e)

def safe_eval(expr: str,
              allowed_builtins: dict = None,
              allowed_vars: dict = None,
              timeout: float = 5,
              restricted_imports: list = None,
              allowed_function_calls: list = None,
              immediate_termination: bool = False,
              file_access: bool = False,
              network_access: bool = False) -> object:
    """
    Safely evaluate a Python expression with limited access to built-ins, custom variables, and optional file access restriction.

    Parameters:
        expr (str): The expression to evaluate.
        allowed_builtins (dict, optional): A dictionary of allowed built-in functions. Defaults to {}.
        allowed_vars (dict, optional): A dictionary of allowed variables and functions. Defaults to {}.
        timeout (float, optional): Time limit for evaluation in seconds. Defaults to 5.
        restricted_imports (list, optional): A list of restricted imports or modules. Defaults to [].
        allowed_function_calls (list, optional): A list of allowed function names to call. Defaults to [].
        immediate_termination (bool, optional): Whether to forcibly terminate the evaluation if it exceeds the timeout. Defaults to False.
        file_access (bool, optional): Whether to allow file access (open, etc.). Defaults to False.
        network_access (bool, optional): Whether to allow network access (requests, etc.). Defaults to False.

    Returns:
        object: The result of the evaluated expression.

    Raises:
        EvaluationTimeoutError: If the evaluation exceeds the allowed time.
        ValueError: If the expression contains unsafe operations.
        UnsafeExpressionError: If restricted imports or unsafe nodes are detected in the AST.
        SyntaxError: If the expression contains invalid syntax.
    """
    allowed_builtins = allowed_builtins or {}
    allowed_vars = allowed_vars or {}
    restricted_imports = restricted_imports or []
    allowed_function_calls = allowed_function_calls or []

    # Restrict file access by removing file-related functions from built-ins if file_access is False
    safe_builtins = allowed_builtins.copy()
    if not file_access:
        # Remove all file-related functions from built-ins
        file_access_functions = {'open', 'os.remove', 'os.rename', 'os.rmdir', 'os.unlink',
                                 'os.mkdir', 'os.makedirs', 'os.chmod', 'os.chown',
                                 'os.truncate', 'os.path', 'shutil', 'pathlib', 'subprocess'}

        # Filter out functions related to file access
        safe_builtins = {k: v for k, v in builtins.__dict__.items() if k not in file_access_functions}

    if not network_access:
        # Remove networking-related functions from built-ins
        network_functions = {
            'socket', 'requests', 'urllib', 'http.client', 'http.server',
            'ftplib', 'smtplib', 'telnetlib', 'xmlrpc.client'
        }

        safe_builtins = {k: v for k, v in safe_builtins.items() if k not in network_functions}

    # Set up the globals for eval
    safe_globals = {"__builtins__": safe_builtins}
    safe_globals.update(allowed_vars)

    # Pre-evaluation AST checks
    try:
        parsed_expr = ast.parse(expr, mode='eval')
    except SyntaxError as e:
        cleanup_resources()
        raise SyntaxError(f"Invalid syntax: {e}")

    _check_ast(parsed_expr, restricted_imports, allowed_function_calls)

    queue = Queue()
    process = Process(target=_eval_in_process, args=(expr, safe_globals, queue))

    process.start()
    process.join(timeout)

    if process.is_alive():
        if immediate_termination:
            process.terminate()  # Terminate the process immediately
            process.join()  # Ensure the process has finished
            cleanup_resources()
            raise EvaluationTimeoutError("Evaluation timed out and was terminated.")
        else:
            cleanup_resources()
            raise EvaluationTimeoutError("Evaluation timed out.")

    # Check for results or exceptions
    if not queue.empty():
        result = queue.get()
        if isinstance(result, Exception):
            cleanup_resources()
            raise result
    else:
        cleanup_resources()
        raise EvaluationTimeoutError("No result returned from the evaluation process.")

    return result

def _check_ast(parsed_expr, restricted_imports, allowed_function_calls):
    """
    Check the AST for unsafe operations such as imports and function calls.

    Parameters:
        parsed_expr (ast.AST): The parsed AST expression.
        restricted_imports (list): A list of restricted import statements.
        allowed_function_calls (list): A list of allowed function calls.

    Raises:
        UnsafeExpressionError: If unsafe operations are detected in the expression.
    """
    for node in ast.walk(parsed_expr):
        # Block all imports if restricted
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name in restricted_imports:
                    raise UnsafeExpressionError(f"Use of '{alias.name}' is restricted.")
            raise UnsafeExpressionError("Imports are not allowed in expressions.")

        # Prevent function calls except for whitelisted ones
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id not in allowed_function_calls:
                raise UnsafeExpressionError(f"Function call to '{node.func.id}' is not allowed.")

        # Prevent attribute access (e.g., accessing os.system or other potentially harmful attributes)
        if isinstance(node, ast.Attribute):
            raise UnsafeExpressionError("Attribute access is restricted for security reasons.")

# Custom key (visible but obfuscated)
SHIFT = 3  # Caesar cipher shift value
_character_map = {'0': '5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9', '1': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b', '2': 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35', '3': '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce', '4': '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', '5': 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d', '6': 'e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683', '7': '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451', '8': '2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3', '9': '19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7', 'a': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'b': '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d', 'c': '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6', 'd': '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4', 'e': '3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea', 'f': '252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111', 'g': 'cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29', 'h': 'aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123', 'i': 'de7d1b721a1e0632b7cf04edf5032c8ecffa9f9a08492152b926f1a5a7e765d7', 'j': '189f40034be7a199f1fa9891668ee3ab6049f82d38c68be70f596eab2e1857b7', 'k': '8254c329a92850f6d539dd376f4816ee2764517da5e0235514af433164480d7a', 'l': 'acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0', 'm': '62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a', 'n': '1b16b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9', 'o': '65c74c15a686187bb6bbf9958f494fc6b80068034a659a9ad44991b08c58f2d2', 'p': '148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940', 'q': '8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf', 'r': '454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1', 's': '043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89', 't': 'e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8', 'u': '0bfe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6', 'v': '4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080', 'w': '50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326', 'x': '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881', 'y': 'a1fce4363854ff888cff4b8e7875d600c2682390412a8cf79b37d0b11148b0fa', 'z': '594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06', 'A': '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd', 'B': 'df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c', 'C': '6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d', 'D': '3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43', 'E': 'a9f51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58', 'F': 'f67ab10ad4e4c53121b6a5fe4da9c10ddee905b978d3788d2723d7bfacbe28a9', 'G': '333e0a1e27815d0ceee55c473fe3dc93d56c63e3bee2b3b4aee8eed6d70191a3', 'H': '44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21', 'I': 'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c', 'J': '6da43b944e494e885e69af021f93c6d9331c78aa228084711429160a5bbd15b5', 'K': '86be9a55762d316a3026c2836d044f5fc76e34da10e1b45feee5f18be7edb177', 'L': '72dfcfb0c470ac255cde83fb8fe38de8a128188e03ea5ba5b2a93adbea1062fa', 'M': '08f271887ce94707da822d5263bae19d5519cb3614e0daedc4c7ce5dab7473f1', 'N': '8ce86a6ae65d3692e7305e2c58ac62eebd97d3d943e093f577da25c36988246b', 'O': 'c4694f2e93d5c4e7d51f9c5deb75e6cc8be5e1114178c6a45b6fc2c566a0aa8c', 'P': '5c62e091b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d2', 'Q': '4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260', 'R': '8c2574892063f995fdf756bce07f46c1a5193e54cd52837ed91e32008ccf41ac', 'S': '8de0b3c47f112c59745f717a626932264c422a7563954872e237b223af4ad643', 'T': 'e632b7095b0bf32c260fa4c539e9fd7b852d0de454e9be26f24d0d6f91d069d3', 'U': 'a25513c7e0f6eaa80a3337ee18081b9e2ed09e00af8531c8f7bb2542764027e7', 'V': 'de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc', 'W': 'fcb5f40df9be6bae66c1d77a6c15968866a9e6cbd7314ca432b019d17392f6f4', 'X': '4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015', 'Y': '18f5384d58bcb1bba0bcd9e6a6781d1a6ac2cc280c330ecbab6cb7931b721552', 'Z': 'bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83', '!': 'bb7208bc9b5d7c04f1236a82a0093a5e33f40423d5ba8d4266f7092c3ba43b62', '"': '8a331fdde7032f33a71e1b2e257d80166e348e00fcb17914f48bdb57a1c63007', '#': '334359b90efed75da5f0ada1d5e6b256f4a6bd0aee7eb39c0f90182a021ffc8b', '$': '09fc96082d34c2dfc1295d92073b5ea1dc8ef8da95f14dfded011ffb96d3e54b', '%': 'bbf3f11cb5b43e700273a78d12de55e4a7eab741ed2abf13787a4d2dc832b8ec', '&': '951dcee3a7a4f3aac67ec76a2ce4469cc76df650f134bf2572bf60a65c982338', "'": '265fda17a34611b1533d8a281ff680dc5791b0ce0a11c25b35e11c8e75685509', '(': '32ebb1abcc1c601ceb9c4e3c4faba0caa5b85bb98c4f1e6612c40faa528a91c9', ')': 'ba5ec51d07a4ac0e951608704431d59a02b21a4e951acc10505a8dc407c501ee', '*': '684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1', '+': 'a318c24216defe206feeb73ef5be00033fa9c4a74d0b967f6532a26ca5906d3b', ',': 'd03502c43d74a30b936740a9517dc4ea2b2ad7168caa0a774cefe793ce0b33e7', '-': '3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112', '.': 'cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8', '/': '8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1', ':': 'e7ac0786668e0ff0f02b62bd04f45ff636fd82db63b1104601c975dc005f3a67', ';': '41b805ea7ac014e23556e98bb374702a08344268f92489a02f0880849394a1e4', '<': 'dabd3aff769f07eb2965401eb029974ebba3407afd02b26ddb564ea5f8efae72', '=': '380918b946a526640a40df5dced6516794f3d97bbd9e6bb553d037c4439f31c3', '>': '62b67e1f685b7fef51102005dddd27774be3fee38c42965c53aab035d0b6b221', '?': '8a8de823d5ed3e12746a62ef169bcf372be0ca44f0a1236abc35df05d96928e1', '@': 'c3641f8544d7c02f3580b07c0f9887f0c6a27ff5ab1d4a3e29caf197cfc299ae', '[': '245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811', '\\': 'a9253dc8529dd214e5f22397888e78d3390daa47593e26f68c18f97fd7a3876b', ']': 'cfae0d4248f7142f7b17f826cd7a519280e312577690e957830d23dcf35a3fff', '^': '74cd9ef9c7e15f57bdad73c511462ca65cb674c46c49639c60f1b44650fa1dcb', '_': 'd2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde', '`': '8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3', '{': '021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96', '|': 'cbe5cfdf7c2118a9c3d78ef1d684f3afa089201352886449a06a6511cfef74a7', '}': 'd10b36aa74a59bcf4a88185837f658afaf3646eff2bb16c3928d0e9335e945d2', '~': '7ace431cb61584cb9b8dc7ec08cf38ac0a2d649660be86d349fb43108b542fa4', ' ': '36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068', '\t': '2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9', '\n': '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', '\r': '9d1e0e2d9459d06523ad13e28a4093c2316baafe7aec5b25f30eba2e113599c4', '\x0b': 'e7cf46a078fed4fafd0b5e3aff144802b853f8ae459a4f0c14add3314b7cc3a6', '\x0c': 'ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977'}

# Encryption and decryption functions using the mapping
def encrypt_with_mapping(code: str, mapping: dict) -> str:
    """Encrypts the code by replacing characters with mapped strings."""
    return ''.join(mapping.get(char, char) for char in code)

def decrypt_with_mapping(encrypted_code: str, mapping: dict) -> str:
    """Decrypts the code by replacing mapped strings back to original characters."""
    reverse_mapping = {v: k for k, v in mapping.items()}

    # Use regex to find all 64-char groups (SHA-256 hashed strings)
    parts = []
    segment_length = 64  # SHA-256 hash length

    # Iterate through the encrypted_code in chunks of segment_length
    for i in range(0, len(encrypted_code), segment_length):
        chunk = encrypted_code[i:i+segment_length]
        parts.append(reverse_mapping.get(chunk, chunk))  # Replace if found

    return ''.join(parts)

def caesar_cipher(text: str, shift: int) -> str:
    """Applies a Caesar cipher to the input text with the given shift."""
    return ''.join(chr((ord(char) + shift) % 256) for char in text)

def reverse_string(text: str) -> str:
    """Reverses the input string."""
    return text[::-1]

def encrypt_to_file(code: str, output_file: str, mapping: dict = _character_map) -> None:
    """
    Encrypt the given Python code using multiple methods and embed it as comments in a Python file.

    Parameters:
        code (str): The Python code to encrypt.
        output_file (str): The path to the output Python file to embed encrypted code.
        mapping (dict): The mapping dictionary for character replacements.

    Returns:
        None
    """
    try:
        # Step 1: Encrypt using mapping
        mapped_encrypted = encrypt_with_mapping(code, mapping)
        if not mapped_encrypted:
            raise ValueError("Mapping encryption failed. The result is empty.")

        # Step 2: Caesar Cipher
        caesar_encrypted = caesar_cipher(mapped_encrypted, SHIFT)
        if not caesar_encrypted:
            raise ValueError("Caesar cipher encryption failed. The result is empty.")

        # Step 3: Base64 Encoding
        base64_encoded = base64.b64encode(caesar_encrypted.encode()).decode()
        if not base64_encoded:
            raise ValueError("Base64 encoding failed. The result is empty.")

        try:
            # Write the encrypted code as comments in the Python file
            with open(output_file, 'w') as file:
                file.write(f"# {base64_encoded}")
        except IOError as e:
            raise IOError(f"Failed to write to file '{output_file}': {e}")

    except Exception as e:
        raise RuntimeError(f"An error occurred during encryption: {e}")

def decrypt_code(encrypted_code: str, mapping: dict) -> str:
    """Decrypts the encrypted code using the reverse of the encryption methods."""
    try:
        # Step 1: Decode from Base64
        base64_decoded = base64.b64decode(encrypted_code).decode()
        if not base64_decoded:
            raise ValueError("Base64 decryption failed. The result is empty.")

        # Step 2: Apply the reverse Caesar cipher
        caesar_decoded = caesar_cipher(base64_decoded, -SHIFT)
        if not caesar_decoded:
            raise ValueError("Caesar cipher decryption failed. The result is empty.")

        # Step 3: Decrypt using mapping
        original_code = decrypt_with_mapping(caesar_decoded, mapping)
        if not original_code:
            raise ValueError("Mapping decryption failed. The result is empty.")

        return original_code

    except Exception as e:
        raise RuntimeError(f"An error occurred during decryption: {e}")

def encrypt(code:str, mapping: dict = _character_map) -> str:
    """
    Encrypt the code using multiple methods and return it.

    Parameters:
        code (str): The Python code to encrypt.
        mapping (dict): The mapping dictionary for character replacements.

    Returns:
        str: The encrypted code.
    """
    try:
        # Step 1: Encrypt using mapping
        mapped_encrypted = encrypt_with_mapping(code, mapping)
        if not mapped_encrypted:
            raise ValueError("Mapping encryption failed. The result is empty.")

        # Step 2: Caesar Cipher
        caesar_encrypted = caesar_cipher(mapped_encrypted, SHIFT)
        if not caesar_encrypted:
            raise ValueError("Caesar cipher encryption failed. The result is empty.")

        # Step 3: Base64 Encoding
        base64_encoded = base64.b64encode(caesar_encrypted.encode()).decode()
        if not base64_encoded:
            raise ValueError("Base64 encoding failed. The result is empty.")

        return base64_encoded
    except Exception as e:
        raise RuntimeError(f"An error occurred during encryption: {e}")

def decrypt(encrypted_code:str, mapping: dict =_character_map) -> str:
    """
    Decrypt the code using multiple methods and return it.

    Parameters:
        code (str): The Python code to decrypt.
        mapping (dict): The mapping dictionary for character replacements.

    Returns:
        str: The decrypted code.
    """
    try:
         # Step 1: Decode from Base64
        base64_decoded = base64.b64decode(encrypted_code).decode()
        if not base64_decoded:
            raise ValueError("Base64 decryption failed. The result is empty.")

        # Step 2: Apply the reverse Caesar cipher
        caesar_decoded = caesar_cipher(base64_decoded, -SHIFT)
        if not caesar_decoded:
            raise ValueError("Caesar cipher decryption failed. The result is empty.")

        # Step 3: Decrypt using mapping
        original_code = decrypt_with_mapping(caesar_decoded, mapping)
        if not original_code:
            raise ValueError("Mapping decryption failed. The result is empty.")

        return original_code
    except Exception as e:
        raise RuntimeError(f"An error occurred during decryption: {e}")

def run(encrypted_file: str, mapping: dict = _character_map) -> None:
    """
    Decrypt and execute the Python code embedded in the specified file.

    Parameters:
        encrypted_file (str): Path to the Python file with embedded encrypted code.
        mapping (dict): The mapping dictionary for character replacements.

    Returns:
        None
    """
    try:
        # Read the encrypted code from the file
        with open(encrypted_file, 'r') as file:
            content = file.read()

        # Extract the encrypted code from the comments
        encrypted_code = re.search(r'# (.+)', content).group(1)
        encrypted_code = encrypted_code.replace("# ", '')

        # Decrypt the code
        decrypted_code = decrypt_code(encrypted_code, mapping)

        # Execute the decrypted Python code
        exec(decrypted_code)
    except Exception as e:
        raise RuntimeError(f"An error occurred during decryption and execution: {e}")

def decrypt_to_file(encrypted_file: str, output_file: str, mapping: dict = _character_map) -> None:
    """
    Decrypt the code embedded in the specified file and write it to an output file.

    Parameters:
        encrypted_file (str): Path to the Python file with embedded encrypted code.
        output_file (str): Path to the output Python file for decrypted code.
        mapping (dict): The mapping dictionary for character replacements.

    Returns:
        None
    """
    try:
        # Check if the mapping is valid
        if not isinstance(mapping, dict):
            raise ValueError("The mapping parameter must be a dictionary.")

        # Read the encrypted code from the file
        try:
            with open(encrypted_file, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file {encrypted_file} does not exist.")
        except IOError as e:
            raise IOError(f"An error occurred while reading the file {encrypted_file}: {e}")

        # Extract the encrypted code from the comments
        match = re.search(r'# (.+)', content)
        if not match:
            raise ValueError("No encrypted code found in the file. Ensure the file contains a valid encrypted comment.")

        encrypted_code = match.group(1).replace("# ", '')

        # Decrypt the code
        try:
            decrypted_code = decrypt_code(encrypted_code, mapping)
        except Exception as e:
            raise ValueError(f"An error occurred during decryption: {e}")

        # Write the decrypted code to the specified output file
        try:
            with open(output_file, 'w') as file:
                file.write(decrypted_code)
        except IOError as e:
            raise IOError(f"An error occurred while writing to the file {output_file}: {e}")

    except Exception as e:
        print(f"An error occurred during decryption to file: {e}")