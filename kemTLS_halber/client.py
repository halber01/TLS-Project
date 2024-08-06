# client.py

from kyberpy.src.kyber_py.kyber import Kyber512
from config import HOST, PORT
from helper.clientHelper import kdf_derive
import socket


pk_e, sk_e = Kyber512.keygen()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # send public key to server
    s.sendall(pk_e)

    # receive ct_e and pk_s from server
    ct_e = s.recv(1024)
    pk_s = s.recv(1024)

    # derive shared secret
    ss_e = Kyber512.decaps(ct_e, sk_e)

    # derive key
    key = kdf_derive(ss_e)

print(f"Received {key!r}")