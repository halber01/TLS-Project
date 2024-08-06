# server.py

from kyberpy.src.kyber_py.kyber import Kyber512
from config import *
import socket


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        # receive public key from client
        pk_e = conn.recv(1024)

        # encapsulate public key from client
        ss_e, ct_e = Kyber512.encaps(pk_e)

        # send encapsulated shared secret and ciphertext to client
        conn.sendall(ct_e)
        conn.sendall(PK_S)