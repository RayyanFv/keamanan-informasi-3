import socket
import ast
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import rsa_encrypt, rsa_generate_keys, rsa_decrypt

import random
import time
from time import sleep

def update_des_key(sock, public_key_b, private_key_a):
    while True:
        sleep(7200)  # 2 jam dalam detik
        des_key_new = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
        print("Generated new DES key:", des_key_new)

        # Enkripsi dan tanda tangan kunci DES
        signed_des_key = rsa_encrypt(private_key_a, des_key_new)
        signed_des_key = ','.join(map(str, signed_des_key))  
        encrypted_des_key = rsa_encrypt(public_key_b, signed_des_key)
        encrypted_des_key = ','.join(map(str, encrypted_des_key))

        # Kirim kunci DES baru
        sock.send(f"DES_KEY:{encrypted_des_key}".encode())
        print("\n---------- New DES key sent to Client B ----------")

        # Update variabel kunci dengan kunci DES baru
        binary_key = convert_key(des_key_new)
        global key_storage
        key_storage = buat_keys(binary_key)

def initiate_client():
    server_host = socket.gethostname()
    server_port = 5000

    client_socket = socket.socket()
    client_socket.connect((server_host, server_port))
    print("Connected to server.")

    # Langkah 1: Generate RSA keys
    public_key_a, private_key_a = rsa_generate_keys()
    public_key_b = None

    # Buat timestamp
    timestamp = int(time.time())

    # Kirim permintaan ke server
    auth_request = f"{public_key_a},{timestamp}"
    print(f"Public Key A: {public_key_a}")
    client_socket.send(auth_request.encode())

    # Langkah 2: Terima respon server
    try:
        # Menerima signature (auth_signature) dan payload balasan
        auth_signature = client_socket.recv(1024).decode()
        auth_signature = tuple(map(int, auth_signature.strip('()').split(',')))
        response_payload = client_socket.recv(1024).decode()

        try:
            decoded_response = ast.literal_eval(response_payload)
            decoded_payload = rsa_decrypt(auth_signature, decoded_response)
        except Exception as e:
            print(f"Error decoding response: {e}")
            return

        try:
            # Ekstrak public_key_b dari payload yang ter-dekripsi
            public_key_b_str = decoded_payload.split('),(')[0]
            public_key_b = tuple(map(int, public_key_b_str.strip('()').split(',')))
        except Exception as e:
            print(f"Error extracting public key: {e}")
            return
    except:
        print("Failed to receive authentication signature")
        return

    nonce1 = random.randint(1, 100)
    initial_des_key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))

    try:
        print("\n---------- Sending identity and nonce ----------")
        identity_payload = f"CLIENT_A,{nonce1}"
        encrypted_payload = rsa_encrypt(public_key_b, identity_payload)
        encrypted_payload = ','.join(map(str, encrypted_payload))
        client_socket.send(encrypted_payload.encode())

        response_data = client_socket.recv(1024).decode()
        response_data = ast.literal_eval(response_data)
        decrypted_response = rsa_decrypt(private_key_a, response_data)
        received_nonce1, received_nonce2 = decrypted_response.split(',', 1)
        
        if str(nonce1) != received_nonce1:
            print("Error: Nonce mismatch")
            return
        else:
            print("Nonce validated")

        nonce2_payload = rsa_encrypt(public_key_b, received_nonce2)
        nonce2_payload = ','.join(map(str, nonce2_payload))
        client_socket.send(nonce2_payload.encode())

        print("Original DES key:", initial_des_key)
        signed_des_key = rsa_encrypt(private_key_a, initial_des_key)
        signed_des_key = ','.join(map(str, signed_des_key))
        encrypted_des_key = rsa_encrypt(public_key_b, signed_des_key)
        encrypted_des_key = ','.join(map(str, encrypted_des_key))
        client_socket.send(encrypted_des_key.encode())

    except Exception as e:
        print("Error:", e)
        return

    # Kirim 'bye' untuk mengakhiri tahap autentikasi
    client_socket.send(b'bye')

    # Setup kunci DES awal
    binary_key = convert_key(initial_des_key)
    global key_storage
    key_storage = buat_keys(binary_key)

    # Terhubung langsung ke klien B
    try:
        direct_host = socket.gethostname()
        direct_port = 6000

        direct_connection = socket.socket()
        direct_connection.connect((direct_host, direct_port))
        print("Connected to Client B.")

        # Jalankan thread untuk update kunci DES setiap 2 jam
        threading.Thread(target=update_des_key, args=(direct_connection, public_key_b, private_key_a), daemon=True).start()

        def receive_direct():
            while True:
                try:
                    data = direct_connection.recv(1024).decode()
                    if not data:
                        break
                    # Data di sini adalah ciphertext hex (ECB)
                    decrypted_msg = decrypt_ecb_mode(data, key_storage)
                    print("Message from Client B:", decrypted_msg)
                except Exception as e:
                    print("Error receiving message:", e)
                    break

        threading.Thread(target=receive_direct).start()

        while True:
            message = input("----------\n")
            if message == 'bye':
                direct_connection.send(message.encode())
                print("Disconnected from direct connection.")
                break
            else:
                # Konversi pesan ke biner
                binary_message = str_to_bin(message)
                # Enkripsi dengan ECB mode
                encrypted_message = encrypt_ecb_mode(binary_message, key_storage)
                direct_connection.send(encrypted_message.encode())

        direct_connection.close()

    except Exception as e:
        print("Failed to connect to Client B:", e)

    client_socket.close()

if __name__ == "__main__":
    initiate_client()
