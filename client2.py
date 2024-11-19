import socket
from des import hex_to_bit_array, key_generation, encrypt_long_text, decrypt_long_text
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def client2():
    # Buat pasangan kunci RSA
    rsa_key = RSA.generate(2048)
    private_key = rsa_key
    public_key = rsa_key.publickey()

    # Hubungkan ke server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Kirim public key ke server
    client_socket.send(public_key.export_key())

    # Terima public key Client 1 dari server
    other_public_key = RSA.import_key(client_socket.recv(2048))
    other_cipher = PKCS1_OAEP.new(other_public_key)

    while True:
        try:
            # Terima data dari Client 1
            data = client_socket.recv(4096)
            encrypted_des_key, encrypted_message = data.split(b'||')

            # Debug log untuk data yang diterima
            print(f"Data diterima dari Client 1: {encrypted_des_key.hex()}, {encrypted_message[:50]}...")

            # Dekripsi kunci DES
            rsa_cipher = PKCS1_OAEP.new(private_key)
            des_key = rsa_cipher.decrypt(encrypted_des_key).decode('utf-8')
            round_keys = key_generation(hex_to_bit_array(des_key))

            # Dekripsi pesan
            decrypted_message = decrypt_long_text(encrypted_message.decode('utf-8'), round_keys)
            print(f"Pesan dari Client 1: {decrypted_message}")

            # Kirim balasan ke Client 1
            message = input("Balas ke Client 1: ")
            encrypted_message = encrypt_long_text(message, round_keys)
            encrypted_des_key = other_cipher.encrypt(des_key.encode('utf-8'))

            # Debug log untuk data yang dikirim
            print(f"Kunci DES terenkripsi dikirim: {encrypted_des_key.hex()}")
            print(f"Pesan terenkripsi dikirim: {encrypted_message}")

            client_socket.sendall(encrypted_des_key + b'||' + encrypted_message.encode('utf-8'))
        except ValueError as e:
            print(f"Error: {e} (Kemungkinan kunci tidak cocok atau data rusak)")
            break
        except Exception as e:
            print(f"Error lainnya: {e}")
            break

if __name__ == "__main__":
    client2()
