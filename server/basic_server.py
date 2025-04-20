import socket 
import threading

HOST = input("Enter server IP address (run 'ifconfig lo0' command if unsure: ")
PORT = 12345
clients = []

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    while True:
        try:
            msg = conn.recv(1024)
            if not msg:
                break
            broadcast(msg, conn)
        except:
            break
    conn.close()
    clients.remove(conn)
    
def broadcast(message, sender_conn):
    for client in clients[:]:
        if client != sender_conn:
            try:
                client.send(message)
            except:
                clients.remove(client)

            
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server running on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = server.accept()
            clients.append(conn)
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except KeyboardInterrupt:
        print("\n[SERVER]: Shutting down...")
        for client in clients:
            client.close()
        server.close()
        
start_server()