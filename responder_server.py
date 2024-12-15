import socket
import threading
from rsa import generate_rsa_keys, encrypt_rsa
import time
from time import sleep

# Daftar koneksi klien
clients = []
timestamp_client_a, timestamp_client_b = None, None
request_msg_a, request_msg_b = None, None

public_key_a, public_key_b = None, None
public_key_auth, private_key_auth = None, None

def distribute_public_keys():
    print("Dua klien telah terhubung, mengirimkan public key...")

    # Tahap 2:
    # Mengirim public_key_auth, serta public_key_b, request_msg_a, dan timestamp_client_a ke klien A
    clients[0].send(str(public_key_auth).encode())
    print("Public key otentikasi (PUauth) dikirim ke klien A")

    # Pesan yang akan ditandatangani (ke klien A)
    message_a = f"{public_key_b},{request_msg_a},{timestamp_client_a}"
    signed_message_a = encrypt_rsa(private_key_auth, message_a)
    clients[0].send(str(signed_message_a).encode())
    print("Pesan bertanda tangan dikirim ke klien A")

    # Tahap 5:
    # Mengirim public_key_auth, serta public_key_a, request_msg_b, dan timestamp_client_b ke klien B
    clients[1].send(str(public_key_auth).encode())
    print("Public key otentikasi (PUauth) dikirim ke klien B")

    # Pesan yang akan ditandatangani (ke klien B)
    message_b = f"{public_key_a},{request_msg_b},{timestamp_client_b}"
    signed_message_b = encrypt_rsa(private_key_auth, message_b)
    clients[1].send(str(signed_message_b).encode())
    print("Pesan bertanda tangan dikirim ke klien B")


def handle_connection(connection, address):
    global timestamp_client_a, timestamp_client_b, public_key_a, public_key_b, request_msg_a, request_msg_b
    print(f"Terhubung dengan: {address}")

    # Terima public key dari klien pertama atau kedua
    if len(clients) == 1:
        message_from_a = connection.recv(1024).decode()
        request_msg_a = message_from_a
        public_key_a, timestamp_client_a = message_from_a.rsplit(',', 1)
        print(f"Timestamp klien A: {timestamp_client_a}")
        print(f"Public key klien A: {public_key_a}")
    elif len(clients) == 2:
        message_from_b = connection.recv(1024).decode()
        request_msg_b = message_from_b
        public_key_b, timestamp_client_b = message_from_b.rsplit(',', 1)
        print(f"Timestamp klien B: {timestamp_client_b}")
        print(f"Public key klien B: {public_key_b}")

    while True:
        try:
            # Terima pesan terenkripsi
            encrypted_message = connection.recv(1024).decode()
            if not encrypted_message:
                break

            if encrypted_message.lower() == "bye":
                print(f"{address} terputus.")
                break

            # Teruskan pesan ke klien lain
            for c in clients:
                if c != connection:
                    c.send(encrypted_message.encode())

        except:
            print(f"Terjadi kesalahan pada {address}")
            break

    clients.remove(connection)
    connection.close()


def input_listener(server_socket):
    while True:
        command = input("Ketik 'quit' untuk menghentikan server: ")
        # Server akan berhenti jika perintah "quit" atau jika tidak ada klien dan kedua timestamp tersedia
        if command.lower() == "quit" or (len(clients) == 0 and timestamp_client_a and timestamp_client_b):
            print("Mematikan server dan memutus semua koneksi")
            for c in clients:
                c.close()
            server_socket.close()
            break


def run_server():
    global public_key_auth, private_key_auth
    public_key_auth, private_key_auth = generate_rsa_keys()
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Server siap, menunggu klien...")

    threading.Thread(target=input_listener, args=(server_socket,)).start()

    while True:
        try:
            conn, addr = server_socket.accept()
            clients.append(conn)

            threading.Thread(target=handle_connection, args=(conn, addr)).start()

            # Tunggu sejenak agar timestamp terisi dari kedua klien
            sleep(1)

            # Jika sudah ada 2 klien dan kedua timestamp tersedia, kirim public key otentikasi
            if len(clients) == 2 and timestamp_client_a and timestamp_client_b:
                distribute_public_keys()

        except:
            break

if __name__ == "__main__":
    run_server()
