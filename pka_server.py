import socket
from rsa import generate_rsa_keys

pka_keys = {}

def handle_client(conn):
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        command, name = data.split()
        if command == "REGISTER":
            public_key, private_key = generate_rsa_keys()
            pka_keys[name] = (public_key, private_key)
            conn.send(f"REGISTERED {public_key}".encode())
        elif command == "GET_KEY":
            if name in pka_keys:
                conn.send(f"PUBLIC_KEY {pka_keys[name][0]}".encode())
            else:
                conn.send("ERROR Key not found.".encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 5555))
server.listen(5)
print("PKA Server running...")

while True:
    conn, addr = server.accept()
    handle_client(conn)
    conn.close()
