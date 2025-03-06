from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils.CPRNG import Shake256PRNG
from hashlib import shake_256


class AES_Manager:
    def __init__(self, key_length:int=32):
        self.key_length = key_length
    def iv_generator(self, random_iterator: Shake256PRNG) -> bytes:
        """Generate a random IV from a seed (main_key)
        Args:
            random_iterator (Shake256PRNG): The random iterator used to generate the IV.
        Returns:
            bytes: The IV

        Works by XORing the message number with the main key, then hashing the result with SHAKE-256.
        Why: The IV is unpredictable to an attacker who doesn't know the main key.
        """
        iv = shake_256(random_iterator.randbytes(self.key_length)).digest(16)
        return iv

    def encrypt(self, plaintext: bytes, password: bytes, random_iterator:Shake256PRNG)->bytes:
        """
        Encrypts the given plaintext using AES encryption with the provided password.
        Args:
            plaintext (bytes): The data to be encrypted. If a string is provided, it will be encoded to bytes using UTF-8.
            password (bytes): The password used for encryption. If a string is provided, it will be encoded to bytes using UTF-8.
                            The password must be 32 bytes long. If it is not, it will be hashed using SHAKE-256 to generate a 16-byte key.
            random_iterator (Shake256PRNG): The random iterator used to generate the initialization vector (IV). Default is a new random iterator seeded with 0.
        Returns:
            bytes: The encrypted ciphertext.
        Raises:
            ValueError: If the password length is not 32 bytes and cannot be hashed to the required length.
        Notes:
            - The plaintext is padded with null bytes to ensure its length is a multiple of 16 bytes.
            - The initialization vector (IV) is generated using the `iv_generator` method, which is assumed to be defined elsewhere in the class.
            - The AES encryption is performed in CBC mode.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if len(password) != 32:
            password = shake_256(password).digest(16)
        if len(plaintext) % 16 != 0:
            plaintext += b"\x00" * (16 - len(plaintext) % 16)
        iv = self.iv_generator(random_iterator)
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    # AES Decryption
    def decrypt(self, ciphertext: bytes, password: bytes, random_iterator:Shake256PRNG) -> bytes:
        if isinstance(password, str):
            password = password.encode("utf-8")
        if len(password) != 32:
            password = shake_256(password).digest(16)
        iv = self.iv_generator(random_iterator)
        cipher = Cipher(algorithms.AES(password), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        #remove trailing null bytes
        plaintext = plaintext.rstrip(b"\x00")
        return plaintext