# server.py
import threading

from numpy.f2py.auxfuncs import throw_error

from kyberpy.src.kyber_py.kyber import Kyber512
from helper.clientHelper import *
from config import *
from helper.socketHelper import recv_msg, send_msg
import socket
import os
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)


def handle_client(conn, addr):
    with conn:
        # 1. receive public key from client
        pk_e = recv_msg(conn)
        # encapsulate public key from client
        ss_e, ct_e = Kyber512.encaps(pk_e)
        # derive k_1 and k_1_prime with salt
        salt = os.urandom(32)

        k_1, k_1_prime = kdf_derive_2(ss_e, salt)

        # send encapsulated shared secret and ciphertext to client
        send_msg(conn,ct_e)
        send_msg(conn,PK_S)
        send_msg(conn,salt)

        # receive ct_s from client
        aead_ct_s = recv_msg(conn)
        nonce = recv_msg(conn)

        #receive salt so the server can derive k_2
        salt = recv_msg(conn)
        ct_s = aead_decrypt(ss_e,nonce, aead_ct_s, k_1_prime)
        ss_s = Kyber512.decaps(ct_s, SK_S)
        ss_shared = ss_e + ss_s

        k_2, k_2_prime, k_2_prime2, k_2_prime3 = kdf_derive_4(ss_shared, salt)

        # receive key conf and application data
        key_conf_aead = recv_msg(conn)
        nonce = recv_msg(conn)
        key_conf = aead_decrypt(ss_e, nonce, key_conf_aead, k_2)
        if key_conf != bytes("Key confirmation", 'utf-8'):
            throw_error("Key confirmation failed")
            #conn.close()

        app_data_aead = recv_msg(conn)
        nonce = recv_msg(conn)
        app_data = aead_decrypt(ss_e, nonce, app_data_aead, k_2_prime)
        if app_data != bytes("Client Finished", 'utf-8'):
            print("Houston, we have a problem")
            #conn.close()

        new_key_conf = bytes("Key confirmation", 'utf-8')
        nonce = os.urandom(12)
        key_conf_aead = aead_encrypt(ss_e, nonce, new_key_conf, k_2_prime2)


        send_msg(conn, key_conf_aead)
        send_msg(conn, nonce)

        app_data = "Server Finished".encode()
        nonce = os.urandom(12)
        app_data_aead = aead_encrypt(ss_e, nonce, app_data, k_2_prime3)
        send_msg(conn, app_data_aead)
        send_msg(conn, nonce)

        print("Connection established")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening on", (HOST, PORT))
        while True:
            conn, addr = s.accept()
            print("Connected by", addr)
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    main()

# testing 1000x handshakes and what average time it takes