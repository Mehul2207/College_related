import socket
import hashlib

# ----------------- Create TCP server socket -----------------
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 12345)
server_socket.bind(server_address)   # bind to localhost and port 12345
server_socket.listen(1)             # listen for 1 incoming connection

num_connections = 0
print('Waiting for a connection...')

while True:
    # ----------------- Accept incoming connection -----------------
    connection, client_address = server_socket.accept()
    print('Connection from', client_address)
    num_connections += 1
    print("Number of connections:", num_connections)

    # ----------------- Receive data from client -----------------
    data = connection.recv(1024)

    # ----------------- Exit conditions -----------------
    if data == b'exit' or not data or num_connections == 3:
        break

    # ----------------- Compute SHA-256 hash and send back -----------------
    data_hash = hashlib.sha256(data).hexdigest()
    connection.sendall(data_hash.encode())

# ----------------- Close server socket -----------------
server_socket.close()
