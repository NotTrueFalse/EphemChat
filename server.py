import socket
import threading

# Configuration
HOST = '0.0.0.0'
PORT = 12345

# Globals
clients = []
lock = threading.Lock()

# Function to handle a single client
def handle_client(conn, addr):
    global clients
    with conn:
        print(f"New client connected: {addr}")
        clients.append(conn)
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                # print(f"Received data from {addr} ({len(data)})")
                with lock:
                    for client in clients:
                        if client != conn:
                            client.sendall(data)
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            with lock:
                clients.remove(conn)
                print(f"Client disconnected: {addr}")

# Main server function
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print(f"Server running on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()