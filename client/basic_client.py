import socket
import threading

from crypto_utils import encrypt_message, decrypt_message

import json
import hashlib
import os

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if not os.path.exists("users.json"):
        return {}
    with open("users.json", "r") as f:
        return json.load(f)
    
def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

users = load_users()
print("[1] Login")
print("[2] Register")
choice = input("Choose an option: ")

while choice not in ["1", "2"]:
    choice = input("Please type 1 or 2: ")
username = input("Enter your username: ")
password = input("Enter your password: ")
hashed = hash_password(password)

if choice == "1":
    if username not in users or users[username] != hashed:
        print("Invalid username or password! Exiting")
        exit()
    else:
        print("Login successful!")
else:
    if username in users:
        print("Username already exists! Exiting..")
        exit()
    users[username] = hashed
    save_users(users)
    print("Registration was successful! Welcome ")        



HOST = input("Enter server IP address (run 'ifconfig lo0' command if unsure: ")
PORT = 12345 # change to interactively ask for the port as well?



# username = input("Enter your username: ")

def receive_messages(sock):
    while True:
        try:
            encrypted = sock.recv(1024)
            try:
                msg = decrypt_message(encrypted)
                print(f"\r{msg}\n[{username}] > ", end="")
            except:
                print("\n[!] Failed to decrypt message.")
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
        encrypted = encrypt_message(f"[{username}]: {msg}")
        client.send(encrypted)

        if msg.lower() == "exit":
            client.close()
            break



start_client()