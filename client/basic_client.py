import socket
import threading

HOST = input("Enter server IP address (e.g. 127.0.0.1): ")
PORT = 12345  # You can also make this input() if you want to ask interactively
username = input("Enter your username: ")

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode()
            if not msg.startswith(f"[{username}]:"):
                print(f"\r{msg}\n[{username}] > ", end="")
        except:
            print("\n[!] Disconnected from server.")
            break


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("Connected to server.")

    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.start()

    while True:
        msg = input(f"[{username}] > ")
        full_msg = f"[{username}]: {msg}"
        client.send(full_msg.encode())

        if msg.lower() == "exit":
            client.close()
            break

start_client()
