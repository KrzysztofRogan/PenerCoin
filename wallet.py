
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import os
import json
import binascii


class Wallet:
    def __init__(self, private_key_bytes: bytes = None):
        if private_key_bytes:
            self._signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        else:
            self._signing_key = SigningKey.generate(curve=SECP256k1)
        self._verifying_key = self._signing_key.get_verifying_key()

    @classmethod
    def generate(cls):
        return cls()

    def export_private_bytes(self) -> bytes:
        return self._signing_key.to_string()

    def export_public_bytes(self) -> bytes:
        return self._verifying_key.to_string()

    def public_key_hex(self) -> str:
        return binascii.hexlify(self.export_public_bytes()).decode()

    def private_key_hex(self) -> str:
        return binascii.hexlify(self.export_private_bytes()).decode()

    def sign(self, message: bytes) -> str:
        sig = self._signing_key.sign(message)
        return binascii.hexlify(sig).decode()

    @staticmethod
    def verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
        try:
            vk = VerifyingKey.from_string(binascii.unhexlify(public_key_hex), curve=SECP256k1)
            return vk.verify(binascii.unhexlify(signature_hex), message)
        except Exception:
            return False

    def save_keystore(self, path: str, password: str):
        salt = os.urandom(16)
        iterations = 200_000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        private_bytes = self.export_private_bytes()
        ct = aesgcm.encrypt(nonce, private_bytes, None)
        keystore = {
            'crypto': {
                'ciphertext': binascii.hexlify(ct).decode(),
                'nonce': binascii.hexlify(nonce).decode(),
                'salt': binascii.hexlify(salt).decode(),
                'iterations': iterations
            },
            'pub': self.public_key_hex()
        }
        with open(path, 'w') as f:
            json.dump(keystore, f, indent=2)

    @classmethod
    def load_keystore(cls, path: str, password: str):
        with open(path, 'r') as f:
            keystore = json.load(f)
        crypto = keystore['crypto']
        salt = binascii.unhexlify(crypto['salt'])
        nonce = binascii.unhexlify(crypto['nonce'])
        ct = binascii.unhexlify(crypto['ciphertext'])
        iterations = crypto['iterations']
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        priv = aesgcm.decrypt(nonce, ct, None)
        return cls(private_key_bytes=priv)
