# crypto_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# ---------- AES ----------

def generate_aes_key():
    return get_random_bytes(32)  # AES-256

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def aes_decrypt(enc_data: bytes, key: bytes) -> bytes:
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------- RSA ----------

def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_wrap_key(aes_key: bytes, public_key_pem: bytes) -> bytes:
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(aes_key)

def rsa_unwrap_key(wrapped_key: bytes, private_key_pem: bytes) -> bytes:
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(wrapped_key)
