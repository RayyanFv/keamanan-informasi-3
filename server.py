import socket
from threading import Thread
from Crypto.PublicKey import RSA

def handle_client(conn, addr, other_conn):
    """
    Fungsi untuk menangani komunikasi dari satu klien ke klien lain.
    """
    print(f"Client {addr} terhubung.")
    try:
        while True:
            # Terima data dari klien
            data = conn.recv(4096)
            if not data:
                break

            # Debug log data yang diterima
            print(f"Data diterima dari {addr}: {data[:50]}...")

            # Kirim data ke klien lain
            other_conn.sendall(data)
            print(f"Data dari {addr} diteruskan ke klien lain.")
    except Exception as e:
        print(f"Error dalam koneksi {addr}: {e}")
    finally:
        conn.close()
        print(f"Client {addr} terputus.")

def server():
    # Siapkan socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(2)
    print("Server siap, menunggu klien...")

    # Terima koneksi dari Client 1
    conn1, addr1 = server_socket.accept()
    print(f"Client 1 terhubung dari {addr1}")
    client1_public_key = RSA.import_key(conn1.recv(2048))  # Terima public key Client 1

    # Terima koneksi dari Client 2
    conn2, addr2 = server_socket.accept()
    print(f"Client 2 terhubung dari {addr2}")
    client2_public_key = RSA.import_key(conn2.recv(2048))  # Terima public key Client 2

    # Kirim public key masing-masing klien
    conn1.send(client2_public_key.export_key())
    conn2.send(client1_public_key.export_key())

    # Komunikasi dua arah
    Thread(target=handle_client, args=(conn1, addr1, conn2)).start()
    Thread(target=handle_client, args=(conn2, addr2, conn1)).start()

if __name__ == "__main__":
    server()
