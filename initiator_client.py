import socket
from rsa import rsa_encrypt, rsa_decrypt
from des import encrypt_long_text

def get_public_key(name):
    # Mendapatkan public key dari PKA
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5555))
    client.send(f"GET_KEY {name}".encode())
    response = client.recv(1024).decode()
    client.close()
    return eval(response.split(" ", 1)[1])

def send_encrypted_message():
    # Ambil input pesan dari pengguna
    message = input("Enter your message: ")
    des_key = "12345678"  # Kunci DES (hardcoded untuk demonstrasi)

    # Enkripsi pesan dengan DES
    encrypted_message = encrypt_long_text(message, des_key)

    # Dapatkan public key Responder dari PKA
    responder_name = "ResponderB"
    responder_public_key = get_public_key(responder_name)

    # Enkripsi kunci DES menggunakan RSA
    encrypted_des_key = rsa_encrypt(des_key, responder_public_key)

    print(f"DES Key (Plaintext): {des_key}")
    print(f"Encrypted DES Key (RSA): {encrypted_des_key}")
    print(f"Encrypted Message (DES): {encrypted_message}")

    # Kirim pesan terenkripsi ke Responder
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5556))
    client.send(str((encrypted_des_key, encrypted_message)).encode())
    client.close()

    print("Message sent to Responder.")

def receive_response_from_responder(private_key):
    # Menerima respons terenkripsi dari Responder
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 5557))  # Port untuk menerima balasan
    server.listen(1)
    conn, addr = server.accept()
    encrypted_response = int(conn.recv(1024).decode())
    conn.close()

    # Dekripsi respons menggunakan private key Initiator
    response = rsa_decrypt(encrypted_response, private_key)
    print(f"Response from Responder (Decrypted): {response}")

# Kirim pesan dan terima respons
def main():
    # Dapatkan pasangan kunci Initiator dari PKA
    pka_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pka_client.connect(("localhost", 5555))
    pka_client.send("REGISTER InitiatorA".encode())
    pka_response = pka_client.recv(1024).decode()
    initiator_private_key = eval(pka_response.split(" ", 1)[1])
    pka_client.close()

    # Kirim pesan ke Responder
    send_encrypted_message()

    # Terima respons dari Responder
    receive_response_from_responder(initiator_private_key)

if __name__ == "__main__":
    main()
