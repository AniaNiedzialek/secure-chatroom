import socket
import threading
HOST = input("Enter server IP address (run 'ifconfig lo0' command if unsure: ")
PORT = 12345 # change to interactively ask for the port as well?

username = input("Enter your username: ")

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode('utf-8')
            print(f"\r{msg}\n[{username}] > ", end="")
        except:
            print("Disconnected from server.")
            break
def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print("Connected to server.")
    
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.start()
    
    while True:
        msg = input(f"[{username}] > ")
        if msg.lower() == "exit":
            client.send(f"[{username}] has left the chat.".encode('utf-8'))
            client.close()
            break
        client.send(f"[{username}]: {msg}".encode('utf-8'))

        
start_client()
    