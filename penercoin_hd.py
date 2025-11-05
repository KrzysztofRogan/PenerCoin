import os
import json
import binascii
import hmac
import hashlib
from typing import Tuple, Dict, Any
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

BIP32_KEY = b"PenerCoin seed"


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def _ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")


def _int_to_32(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _point_from_priv(priv32: bytes) -> bytes:
    
    # compressed public key (33 bytes) from 32-byte private key.
  
    sk = SigningKey.from_string(priv32, curve=SECP256k1)
    vk = sk.get_verifying_key()
    raw = vk.to_string()  # 64 bytes: X||Y
    x = raw[:32]
    y = raw[32:]
    prefix = b"\x02" if int.from_bytes(y, "big") % 2 == 0 else b"\x03"
    return prefix + x  


def _pub_to_address(pub_compressed: bytes) -> str:
    sha = hashlib.sha256(pub_compressed).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    return binascii.hexlify(rip).decode()


class HDWallet:

    def __init__(self, master_priv_int: int, master_chaincode: bytes):
        self.master_priv_int = master_priv_int % SECP256k1.order
        self.master_chaincode = master_chaincode
        self.next_index: Dict[int, int] = {}
        self.used_addresses: list[str] = []

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDWallet":
        I = _hmac_sha512(BIP32_KEY, seed)
        IL, IR = I[:32], I[32:]
        priv_int = int.from_bytes(IL, "big")
        if priv_int == 0 or priv_int >= SECP256k1.order:
            raise ValueError("Invalid master key from seed")
        return cls(priv_int, IR)

    @classmethod
    def generate(cls, entropy_bytes: int = 64) -> "HDWallet":
        seed = os.urandom(entropy_bytes)
        return cls.from_seed(seed)

    def ckd_priv(self, parent_priv_int: int, parent_chaincode: bytes, index: int) -> Tuple[int, bytes]:
        if index >= 2**32 or index < 0:
            raise ValueError("Invalid index")
        if index >= 0x80000000:
            data = b"\x00" + _int_to_32(parent_priv_int) + _ser32(index)
        else:
            parent_pub = _point_from_priv(_int_to_32(parent_priv_int))
            data = parent_pub + _ser32(index)
        I = _hmac_sha512(parent_chaincode, data)
        IL, IR = I[:32], I[32:]
        il_int = int.from_bytes(IL, "big")
        child_priv_int = (il_int + parent_priv_int) % SECP256k1.order
        return child_priv_int, IR

    def derive_path(self, path: str) -> Tuple[int, bytes]:
        if path == "m":
            return self.master_priv_int, self.master_chaincode
        priv = self.master_priv_int
        cc = self.master_chaincode
        for p in path.lstrip("m/").split("/"):
            hardened = p.endswith("'") or p.endswith("h")
            idx = int(p.rstrip("'h"))
            if hardened:
                idx += 0x80000000
            priv, cc = self.ckd_priv(priv, cc, idx)
        return priv, cc

    def get_private_key_bytes(self, path: str) -> bytes:
        priv, _ = self.derive_path(path)
        return _int_to_32(priv)

    def get_private_key_hex(self, path: str) -> str:
        return binascii.hexlify(self.get_private_key_bytes(path)).decode()

    def get_public_key_compressed_hex(self, path: str) -> str:
        pubc = _point_from_priv(self.get_private_key_bytes(path))
        return binascii.hexlify(pubc).decode()
    
    def get_public_key_uncompressed_hex(self, path: str) -> str:
        """Zwraca 64-bajtowy (nieskompresowany) klucz publiczny w formacie hex."""
        priv_bytes = self.get_private_key_bytes(path)
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        return binascii.hexlify(vk.to_string()).decode()

    def get_address(self, path: str) -> str:
        pubc = _point_from_priv(self.get_private_key_bytes(path))
        return _pub_to_address(pubc)

    def sign_with_path(self, path: str, message: bytes) -> str:
        sk = SigningKey.from_string(self.get_private_key_bytes(path), curve=SECP256k1)
        sig = sk.sign(message)
        return binascii.hexlify(sig).decode()

    @staticmethod
    def verify(public_key_uncompressed_hex: str, message: bytes, signature_hex: str) -> bool:
        try:
            from ecdsa import VerifyingKey
            pub_bytes = binascii.unhexlify(public_key_uncompressed_hex)
            vk = VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
            return vk.verify(binascii.unhexlify(signature_hex), message)
        except Exception:
            return False

    def _get_next_index_for_chain(self, chain: int) -> int:
        return self.next_index.get(chain, 0)

    def generate_next_address(self, chain: int = 0) -> str:
        idx = self._get_next_index_for_chain(chain)
        path = f"m/{chain}/{idx}"
        addr = self.get_address(path)
        self.used_addresses.append(addr)
        self.next_index[chain] = idx + 1
        return addr

    def mark_address_used(self, address: str):
        if address not in self.used_addresses:
            self.used_addresses.append(address)

    def get_used_addresses(self) -> list:
        return list(self.used_addresses)

    def get_next_index(self, chain: int = 0) -> int:
        return self._get_next_index_for_chain(chain)

    # ---------- keystore ----------
    def save_keystore(self, path: str = None, password: str = None):
        if path is None:
            path = os.path.join(os.getcwd(), "penercoin_keystore.json")
        if password is None:
            raise ValueError("Password is required")

        payload: Dict[str, Any] = {
            "master_priv": binascii.hexlify(_int_to_32(self.master_priv_int)).decode(),
            "master_chaincode": binascii.hexlify(self.master_chaincode).decode(),
            "next_index": {str(k): v for k, v in self.next_index.items()},
            "used_addresses": list(self.used_addresses),
        }
        plaintext = json.dumps(payload).encode()

        salt = os.urandom(16)
        iterations = 200_000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, None)

        keystore = {
            "crypto": {
                "ciphertext": binascii.hexlify(ct).decode(),
                "nonce": binascii.hexlify(nonce).decode(),
                "salt": binascii.hexlify(salt).decode(),
                "iterations": iterations,
            },
            "meta": {"format": "penercoin-hd-keystore-v1"},
        }
        with open(path, "w") as f:
            json.dump(keystore, f, indent=2)
        print(f"Keystore saved to {path}")

    @classmethod
    def load_keystore(cls, path: str, password: str) -> "HDWallet":
        with open(path, "r") as f:
            keystore = json.load(f)
        crypto = keystore["crypto"]
        salt = binascii.unhexlify(crypto["salt"])
        nonce = binascii.unhexlify(crypto["nonce"])
        ct = binascii.unhexlify(crypto["ciphertext"])
        iterations = int(crypto["iterations"])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        payload = json.loads(plaintext.decode())

        master_priv_int = int.from_bytes(binascii.unhexlify(payload["master_priv"]), "big")
        master_chaincode = binascii.unhexlify(payload["master_chaincode"])
        w = cls(master_priv_int, master_chaincode)

        nxt = {int(k): int(v) for k, v in payload.get("next_index", {}).items()}
        w.next_index = nxt
        w.used_addresses = payload.get("used_addresses", [])
        return w
