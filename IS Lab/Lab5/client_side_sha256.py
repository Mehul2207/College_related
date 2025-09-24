import socket
import hashlib

# ----------------- Prepare data -----------------
data_to_send = input("Enter data:- ").encode()  # get user input and encode to bytes

# ----------------- Create TCP client socket -----------------
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 12345)
client_socket.connect(server_address)  # connect to server

try:
    # Exit if no data or 'exit'
    if data_to_send == b'exit' or not data_to_send:
        exit()

    # ----------------- Send data to server -----------------
    client_socket.sendall(data_to_send)

    # ----------------- Receive SHA-256 hash from server -----------------
    received_hash = client_socket.recv(64).decode()

    # ----------------- Compute local hash for verification -----------------
    local_hash = hashlib.sha256(data_to_send).hexdigest()

    # ----------------- Compare hashes -----------------
    print(f'Received hash: {received_hash}')
    print(f'Local hash: {local_hash}')
    if received_hash == local_hash:
        print('Data integrity verified: Hashes match.')
    else:
        print('Data integrity failed: Hashes do not match.')

except Exception as e:
    print("Exception occurred:", e)

finally:
    client_socket.close()  # close the connection
