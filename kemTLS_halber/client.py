# client.py
from anyio import sleep
from numpy.f2py.auxfuncs import throw_error

from kyberpy.src.kyber_py.kyber import Kyber512
from config import HOST, PORT
from helper.clientHelper import *
from helper.socketHelper import recv_msg, send_msg
import socket
import os


pk_e, sk_e = Kyber512.keygen()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # 1. send public key to server
    send_msg(s, pk_e)

    # 2. receive ct_e and pk_s from server
    ct_e = recv_msg(s)
    pk_s = recv_msg(s)
    salt = recv_msg(s)

    # derive shared secret
    ss_e = Kyber512.decaps(ct_e, sk_e)



    # derive key
    k_1, k_1_prime = kdf_derive_2(ss_e, salt)

    # encapsulate pk_s
    ss_s, ct_s = Kyber512.encaps(pk_s)

    # send AEAD_k1_prime(ct_s)
    nonce = os.urandom(12)
    ct_s_aead = aead_encrypt(ss_e, nonce, ct_s, k_1_prime)
    send_msg(s, ct_s_aead)
    send_msg(s, nonce)

    ss_shared = ss_e + ss_s
    # send salt so the server can derive the same k_2
    salt = os.urandom(32)
    send_msg(s, salt)
    k_2, k_2_prime, k_2_prime2, k_2_prime3 = kdf_derive_4(ss_shared, salt)

    # Send key conf and application data
    key_conf = bytes("Key confirmation", 'utf-8')
    nonce = os.urandom(12)
    key_conf_aead = aead_encrypt(ss_e, nonce, key_conf, k_2)
    send_msg(s, key_conf_aead)
    send_msg(s, nonce)

    app_data = bytes("Client Finished", 'utf-8')
    nonce = os.urandom(12)
    app_data_aead = aead_encrypt(ss_e, nonce, app_data, k_2_prime)
    send_msg(s, app_data_aead)
    send_msg(s, nonce)
    # receive key conf and application data

    key_conf_aead_s = recv_msg(s)
    nonce = recv_msg(s)
    key_conf = aead_decrypt(ss_e, nonce, key_conf_aead_s, k_2_prime2)
    if key_conf != bytes("Key confirmation", 'utf-8'):
        print("Key confirmation failed")
        s.close()
    
    app_data_aead = recv_msg(s)
    nonce = recv_msg(s)
    app_data = aead_decrypt(ss_e, nonce, app_data_aead, k_2_prime3)
    print(app_data)
    print(nonce)
    print(app_data_aead)
    if key_conf != bytes("Server Finished", 'utf-8'):
        throw_error("Server Finished failed")
        s.close()
    print("Connection established")