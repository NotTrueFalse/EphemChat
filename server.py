import socket
import threading
import time

# Configuration
HOST = '0.0.0.0'
PORT = 12345
MAX_PAYLOAD_SIZE = 1024**2  # 1 MB
RATE_LIMIT = 1024**3 # 1 GB
TIMEOUT = 60*5  # 5 minutes

# Globals
clients = []
lock = threading.Lock()
rate_limit_data = {}

# Rate limiting function
def check_rate_limit(client_addr, payload_length:int):
    now = time.time()
    if client_addr not in rate_limit_data:
        rate_limit_data[client_addr] = {"count": 0, "last_time": now, "timeout": 0}

    rate_data = rate_limit_data[client_addr]
    if rate_data["timeout"] > now:return False
    if now - rate_data["last_time"] > 1:  # Reset counter every second
        rate_data["count"] = 0
        rate_data["last_time"] = now

    rate_data["count"] += payload_length
    is_rate_limited = rate_data["count"] > RATE_LIMIT
    if is_rate_limited:
        rate_data["timeout"] = now + TIMEOUT
    return not is_rate_limited

# Function to handle a single client
def handle_client(conn, addr):
    global clients
    with conn:
        print(f"New client connected: {addr}")
        clients.append(conn)
        try:
            while True:
                data = conn.recv(MAX_PAYLOAD_SIZE)
                if not data:
                    break
                if not check_rate_limit(addr, len(data)):
                    print(f"Rate limiting client {addr}")
                    conn.sendall(b"Rate limited")
                    break
                print(f"Received data from {addr}: {data}")
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