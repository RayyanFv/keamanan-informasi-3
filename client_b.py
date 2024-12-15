import socket
import threading
from des import convert_key, buat_keys, str_to_bin, encrypt_ecb_mode, decrypt_ecb_mode
from rsa import rsa_decrypt, rsa_generate_keys, rsa_encrypt
import time
import ast
from time import sleep
import random

def is_des_key_update(message):
    return message.startswith("DES_KEY:")

def handle_des_key_update(message, private_key_b, public_key_a, public_key_b):
    try:
        encrypted_signature = message.replace("DES_KEY:", "")
        # Dekripsi signature dengan kunci privat B
        decrypted_signature = rsa_decrypt(private_key_b, list(map(int, encrypted_signature.split(','))))
        # Dekripsi hasil di atas dengan public key A untuk mendapat DES key baru
        new_des_key = rsa_decrypt(public_key_a, ast.literal_eval(decrypted_signature))
        global des_keys
        binary_key = convert_key(new_des_key)
        des_keys = buat_keys(binary_key)
        print("\n---------- DES Key Updated ----------")
        print("New DES Key:", new_des_key)
        print("-------------------------------------\n")
    except Exception as e:
        print("Error updating DES key:", e)

def start_client():
    server_host = socket.gethostname()
    server_port = 5000

    client_socket = socket.socket()
    client_socket.connect((server_host, server_port))
    print("Connected to the server.")

    # Step 4: Generate RSA keys untuk Client B
    public_key_b, private_key_b = rsa_generate_keys()
    public_key_a = None

    # Generate timestamp
    timestamp = int(time.time())

    # Kirim permintaan RSA key ke server
    rsa_request = f"{public_key_b},{timestamp}"
    print(f"Public Key B: {public_key_b}")
    client_socket.send(rsa_request.encode())

    # Step 5: Terima respon dari server
    try:
        received_auth_signature = client_socket.recv(1024).decode()
        auth_signature = tuple(map(int, received_auth_signature.strip('()').split(',')))
        response_payload = client_socket.recv(1024).decode()
        try:
            decoded_list = ast.literal_eval(response_payload)
            decoded_payload = rsa_decrypt(auth_signature, decoded_list)
        except Exception as e:
            print(f"Error decoding response: {e}")
            return

        try:
            public_key_a_str = decoded_payload.split('),(')[0]
            public_key_a = tuple(map(int, public_key_a_str.strip('()').split(',')))
        except Exception as e:
            print(f"Error extracting Public Key A: {e}")
            return
    except:
        print("Failed to receive authentication signature")
        return

    nonce2 = random.randint(1, 100)
    des_key = None

    # Terima data identitas klien A dan nonce
    try:
        data = client_socket.recv(1024).decode()
        print("\n---------- Receive Identity and Nonce ----------")
        data = ast.literal_eval(data)
        data = rsa_decrypt(private_key_b, data)
        client_id, nonce1 = data.rsplit(',', 1)
        print(f"Client ID: {client_id}")

        # Kirim Nonce1 dan Nonce2 ke klien A
        nonce_payload = f"{nonce1},{nonce2}"
        encrypted_nonce = rsa_encrypt(public_key_a, nonce_payload)
        encrypted_nonce = ','.join(map(str, encrypted_nonce))
        print("Nonce1:", nonce1)
        print("Nonce2:", nonce2)
        client_socket.send(encrypted_nonce.encode())

        print("\n---------- Receive Nonce2 Confirmation ----------")
        confirmation_data = client_socket.recv(1024).decode()
        confirmation_data = ast.literal_eval(confirmation_data)
        confirmed_nonce2 = rsa_decrypt(private_key_b, confirmation_data)
        print(f"Confirmed Nonce2: {confirmed_nonce2}")

        if str(nonce2) != confirmed_nonce2:
            print("Error: Nonce2 mismatch")
            return
        else:
            print("Valid: Nonce2 match")

        # Terima DES key
        des_key_data = client_socket.recv(1024).decode()
        des_key_data = ast.literal_eval(des_key_data)
        des_key = rsa_decrypt(private_key_b, des_key_data)
        des_key = ast.literal_eval(des_key)
        des_key = rsa_decrypt(public_key_a, des_key)
        print("DES Key (original):", des_key)
    except Exception as e:
        print("Error:", e)
        return

    # Kirim "bye" untuk mengakhiri tahap autentikasi
    client_socket.send(b'bye')

    # Inisialisasi kunci DES
    binary_key = convert_key(des_key)
    global des_keys
    des_keys = buat_keys(binary_key)

    # Mulai server langsung untuk koneksi dari Client A
    try:
        direct_host = socket.gethostname()
        direct_port = 6000

        direct_server = socket.socket()
        direct_server.bind((direct_host, direct_port))
        direct_server.listen(1)
        print("Waiting for direct connection from Client A...")

        direct_connection, address = direct_server.accept()
        print(f"Direct connection established with {address}")

        def handle_direct_messages():
            while True:
                try:
                    message = direct_connection.recv(1024).decode()
                    if not message:
                        break
                    if is_des_key_update(message):
                        handle_des_key_update(message, private_key_b, public_key_a, public_key_b)
                    else:
                        # Pesan terenkripsi dengan mode ECB (hex)
                        decrypted_msg = decrypt_ecb_mode(message, des_keys)
                        print("Message from Client A:", decrypted_msg)
                except Exception as e:
                    print("Error:", e)
                    break

        threading.Thread(target=handle_direct_messages).start()

        while True:
            user_message = input("----------\n")
            if user_message == 'bye':
                direct_connection.send(user_message.encode())
                print("Disconnected from direct connection.")
                break
            else:
                # Konversi pesan ke biner
                binary_message = str_to_bin(user_message)
                # Enkripsi dengan ECB mode
                encrypted_message = encrypt_ecb_mode(binary_message, des_keys)
                direct_connection.send(encrypted_message.encode())

        direct_connection.close()
        direct_server.close()

    except Exception as e:
        print("Failed to start direct server:", e)

    client_socket.close()

if __name__ == "__main__":
    start_client()
