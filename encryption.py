import base64
import os
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


SALT = b"cs5173_shared_salt"

# converts a key version into bytes for pbkdf2 salt seper ation
def vers_bytes(key_version: int) -> bytes:
    # prevents negative key version values
    if key_version < 0:
        raise ValueError("key version must be >= 0")

    # stores version as a fixed four-byte value
    return key_version.to_bytes(4, "big")

# derives a separate hmac key for one key version
def derive_hmac_key(password: str, key_version: int = 0) -> bytes:
    # creates a version-specific salt for hmac
    versioned_salt = (SALT + b"_hmac_" + vers_bytes(key_version))

    # derives the hmac key using pbkdf2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=versioned_salt,
        iterations=100_000,
    )

    return kdf.derive(
        password.encode("utf-8")
    )

# des 56-bit encryption

def derive_des_key(password: str, key_version: int = 0) -> bytes:
    # creates version specific salt for des
    versioned_salt = (SALT + b"_des_" + vers_bytes(key_version))

    # derives an 8-byte des key from the shared password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=8,
        salt=versioned_salt,
        iterations=100_000,
    )

    return kdf.derive(password.encode("utf-8"))

def encrypt_des_message(message: str, password: str, key_version: int = 0) -> str:
    # derives the des key from the shared password
    key = derive_des_key(password, key_version)

    # creates a random 8 byte initialization vector
    iv = os.urandom(8)

    # creates a des cipher in cbc mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # pads plaintex to match des block size
    padded_message = pad(message.encode("utf-8"), DES.block_size)

    # encrypts the padded plaintext
    ciphertext = cipher.encrypt(padded_message)

    # combine iv w/ ciphertext
    encrypted_data = iv + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")

def decrypt_des_message(encrypted_message: str, password: str, key_version: int = 0) -> str:
    # derives the same des key from the shared password
    key = derive_des_key(password, key_version)

    # converts base64 ciphertext back into bytes
    encrypted_data = base64.b64decode(encrypted_message)

    # separates the iv from ciphertext
    iv = encrypted_data[:8]
    ciphertext = encrypted_data[8:]

    # creates des cipher using received iv
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # decrypts ciphertext
    padded_message = cipher.decrypt(ciphertext)

    # removes padding
    plaintext = unpad(padded_message, DES.block_size)

    return plaintext.decode("utf-8")

# aes-128 encryption

def derive_aes_key(password: str, key_version: int = 0) -> bytes:
    # creates a version specific salt for aes
    versioned_salt = (SALT + b"_aes_" + vers_bytes(key_version))
    # derive a 128-bit AES key from the shared password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=versioned_salt,
        iterations=100_000
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_aes_message(message: str, password: str, key_version: int = 0) -> str:
    # derives the aes key from the shared password
    key = derive_aes_key(password, key_version)

    # creates random 16-byte initialization vector
    iv = os.urandom(16)

    # pads plaintext to match aes block size
    padder = PKCS7(128).padder()
    padded_data = padder.update(message.encode("utf-8"))
    padded_data += padder.finalize()

    # creates aes cipher in cbc mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # encrypts padded plaintext
    ciphertext = encryptor.update(padded_data)
    ciphertext += encryptor.finalize()

    # combines iv and ciphertext
    encrypted_data = iv + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt_aes_message(encrypted_message: str, password: str, key_version: int = 0) -> str:
    # derives same aes key from shared password
    key = derive_aes_key(password, key_version)

    # converts base64 ciphertext back into bytes
    encrypted_data = base64.b64decode(encrypted_message)

    # seperates iv from ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # creates aes cipher using received iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # decrypts ciphertext
    padded_data = decryptor.update(ciphertext)
    padded_data += decryptor.finalize()

    # removes padding
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data)
    plaintext += unpadder.finalize()

    return plaintext.decode("utf-8")

# mode selection func.

def encrypt_by_mode(message: str, password: str, mode: str, key_version: int = 0) -> str:
    # selects encryption method chosen by user
    if mode == "1":
        return encrypt_des_message(message, password, key_version)

    if mode == "2":
        return encrypt_aes_message(message, password, key_version)

    raise ValueError("invalid mode")

def decrypt_by_mode(encrypted_message: str, password: str, mode: str, key_version: int = 0) -> str:
    # selects decryption method chosen by user
    if mode == "1":
        return decrypt_des_message(encrypted_message, password, key_version)

    if mode == "2":
        return decrypt_aes_message(encrypted_message, password, key_version)

    raise ValueError("invalid mode")

# functions for creating and varifying the HMAC

def create_hmac(encrypted_message: str, password: str, key_version: int = 0) -> str:
    # derives a separate key for message authentication
    hmac_key = derive_hmac_key(password, key_version)

    # creates an hmac-sha256 tag for the ciphertext
    tag = hmac.new(
        hmac_key,
        encrypted_message.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    # converts the authentication tag into printable text
    return base64.b64encode(tag).decode("utf-8")


# package ciphertext and hmac together

def verify_hmac(encrypted_message: str, received_tag: str, password: str, key_version: int = 0) -> bool:

    # recalculates the expected authentication tag
    expected_tag = create_hmac(encrypted_message, password, key_version)

    # securely compares the received and expected tags
    return hmac.compare_digest(expected_tag, received_tag)

def protect_message(message: str, password: str, mode: str, key_version: int = 0) -> str:

    # encrypts the plaintext using the selected mode
    encrypted_message = encrypt_by_mode(message, password, mode, key_version)

    # includes version in authenticated data
    authenticated_data = (f"{key_version}|{encrypted_message}")

    # creates an authentication tag for the ciphertext
    authentication_tag = create_hmac(authenticated_data, password, key_version)

    # combines the ciphertext and hmac tag for transmission
    return (f"{key_version}|{encrypted_message}|{authentication_tag}")


def open_message(protected_message: str, password: str, mode: str) -> tuple[str, str]:
    # separates the ciphertext from the authentication tag
    try:
        version_text, encrypted_message, received_tag = protected_message.rsplit("|", 2)

        key_version = int(version_text)

    except (ValueError, TypeError) as error:
        raise ValueError("invalid message format") from error

    # rejects invalid key versions
    if key_version < 0:
        raise ValueError("invalid key version")

    # recreates the authenticated data
    authenticated_data = (f"{key_version}|{encrypted_message}")

    # verifies the message before attempting decryption
    if not verify_hmac(authenticated_data, received_tag, password, key_version):
        raise ValueError(
            "message authentication failed: "
            "incorrect password or modified message"
        )

    # decrypts the message only after authentication succeeds
    plaintext = decrypt_by_mode(encrypted_message, password,mode, key_version)

    return (plaintext, encrypted_message, key_version)
