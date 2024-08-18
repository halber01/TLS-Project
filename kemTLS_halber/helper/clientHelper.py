import base64
from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def kdf_derive_2(password: bytes, salt: bytes):
    base64_password = base64.b64encode(password).decode('utf-8')
    base_64_salt = base64.b64encode(salt).decode('utf-8')
    # derive
    key = scrypt(base64_password, base_64_salt, 32, N=2 ** 14, r=8, p=1, num_keys=2)
    return key


def kdf_derive_4(password: bytes, salt: bytes):
    if salt is None:
        base_64_salt = b''
    else:
        base_64_salt = base64.b64encode(salt).decode('utf-8')
    base64_password = base64.b64encode(password).decode('utf-8')

    # derive
    key = scrypt(base64_password, base_64_salt, 32, N=2 ** 14, r=8, p=1, num_keys=4)
    return key


def aead_encrypt(shared_key, nonce, data, associated_data):
    aesgcm: AESGCM = AESGCM(shared_key)
    return aesgcm.encrypt(nonce, data, associated_data)

def aead_decrypt(shared_key, nonce, data, associated_data):
    aesgcm: AESGCM = AESGCM(shared_key)
    return aesgcm.decrypt(nonce, data, associated_data)
