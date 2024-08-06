import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


def kdf_derive(password: str):
    salt = (get_random_bytes(16))
    # derive
    if isinstance(password, str):
        password = password.encode()

    key = scrypt(password, salt, 16, N=2 ** 14, r=8, p=1)

    return key



