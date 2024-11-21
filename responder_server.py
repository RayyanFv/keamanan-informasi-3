import socket
from rsa import rsa_decrypt, rsa_encrypt
from des import decrypt_long_text

def receive_encrypted_message():
    # Terima pesan terenkripsi dari Initiator
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 5556))
    server.listen(1)
    conn, addr = server.accept()
    encrypted_data = eval(conn.recv(4096).decode())
    conn.close()
    return encrypted_data

def send_response_to_initiator(response, initiator_public_key):
    # Enkripsi respons menggunakan RSA dengan public key Initiator
    encrypted_response = rsa_encrypt(response, initiator_public_key)

    # Kirim respons terenkripsi ke Initiator
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5557))  # Port untuk balasan
    client.send(str(encrypted_response).encode())
    client.close()

    print(f"Response sent to Initiator: {response} (Encrypted: {encrypted_response})")

def decrypt_message(encrypted_data, private_key):
    # Dekripsi kunci DES
    encrypted_des_key, encrypted_message = encrypted_data
    des_key = rsa_decrypt(encrypted_des_key, private_key)
    print(f"Decrypted DES Key: {des_key}")

    # Dekripsi pesan menggunakan DES
    decrypted_message = decrypt_long_text(encrypted_message, des_key)
    print(f"Decrypted Message (DES): {decrypted_message}")
    return decrypted_message

def get_public_key_from_pka(name):
    # Mendapatkan kunci publik dari PKA
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5555))
    client.send(f"GET_KEY {name}".encode())
    response = client.recv(1024).decode()
    client.close()
    return eval(response.split(" ", 1)[1])

def main():
    # Dapatkan pasangan kunci Responder dari PKA
    pka_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pka_client.connect(("localhost", 5555))
    pka_client.send("REGISTER ResponderB".encode())
    pka_response = pka_client.recv(1024).decode()
    responder_private_key = eval(pka_response.split(" ", 1)[1])
    pka_client.close()

    # Terima pesan dari Initiator
    encrypted_data = receive_encrypted_message()

    # Dekripsi pesan
    decrypted_message = decrypt_message(encrypted_data, responder_private_key)

    # Kirim respons ke Initiator
    initiator_public_key = get_public_key_from_pka("InitiatorA")
    send_response_to_initiator("Message received and processed.", initiator_public_key)

if __name__ == "__main__":
    main()
