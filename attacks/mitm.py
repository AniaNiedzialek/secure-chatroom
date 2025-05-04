import socket
import threading
import sys

if len(sys.argv) != 3:
    print("Usage:python mitm.py <REAL_SERVER_HOST> <REAL_SERVER_PORT>")
    sys.exit(1)

REAL_SERVER_HOST = sys.argv[1]
REAL_SERVER_PORT = int(sys.argv[2])

LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8080

def handle_client(client_sock):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))
    except Exception as e:
        print(f"[Error] Failed to connect to server: {e}")
        client_sock.close()
        return

    threading.Thread(target=forward, args=(client_sock, server_sock, "C→S")).start()
    threading.Thread(target=forward, args=(server_sock, client_sock, "S→C")).start()

def forward(src, dst, direction):
    try:
        while True:
            data = src.recv(1024)
            if not data:
                break

            print(f"[{direction}] {data.decode(errors='ignore').strip()}")
            dst.send(data)
    except Exception as e:
        print(f"[Error] {direction}: {e}")
    finally:
        try: src.shutdown(socket.SHUT_RDWR)
        except: pass
        try: src.close()
        except: pass
        try: dst.shutdown(socket.SHUT_RDWR)
        except: pass
        try: dst.close()
        except: pass


def start_proxy():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind((LISTEN_HOST, LISTEN_PORT))
    proxy.listen(5)
    print(f"[Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client_sock, addr = proxy.accept()
        print(f"[Proxy] Got connection from {addr}")
        threading.Thread(target=handle_client, args=(client_sock,)).start()

if __name__ == "__main__":
    start_proxy()
