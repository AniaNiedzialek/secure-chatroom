# Secure Chat Room with Usernames
## Project Overview

This is a secure chatroom built in Python for the CS 166 course. It features login/registration, AES_based message encryption, multi-client support, GUI (PyQt5), and simulated attacks (MITM, tampering, spoofing).

This simple terminal-based chat application that allows multiple users to communicate in real time through a server, and supports user-defined names and demonstrates socket programming in Python.


## Directory Structure
chatroom/
    attacks/
        mitm.py
    client/
        crypto_utils.py
    server
        basic_Server.py
    login_window.py
    users.json
    history_<users>.txt
    requirements.txt
    README.md

## How to Run the Project

### Requirements

- Python 3.10 or newer (recommended)
- OS: macOS, Linux, or Windows
- All dependencies are standard (`socket`, `threading`, etc.)
- Required Libraries:
    - cryptography — used for AES encryption

Install Dependencies
If you haven’t already:
```
pip install -r requirements.txt
```

1. Install Requirements
```
pip install pyqt5 cryptography
```
2. Start the server
```
python3 server/basic_server.py
```
3. Launch the GUI
```
python3 login_window.py
```
Use different terminals to simulate multiple users
---
### Setup

1. **Clone the repository:**
git clone https://github.com/your-username/secure-chat-room.git
cd secure-chat-room

2. **Create a virtual environment:**
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
---
### Running the server
cd server
python3 basic_server.py

Enter the server IP address
Type CTRL^C to exit
---
### Running the client
In a new terminal window:
cd client
python3 basic_client.py

- Enter the same IP and port as the server
- Enter your username
- Type messages to chat
- Type exit to disconnect cleanly
---
### Encryption Mode
Uses AES with a predefined key. Messages are encrypted in send_message and decrypted in receive_message.

To temporarily disable encryption for demo purposes:
In login_window.py:
```
#encrypted = encrypted_message(full_message)
#self.client_socket.send(encrypted)
self.client_socket.send(full_message.encode())
```

and
```
# message = decrypt_message(data)
message = data.decode()
```
---
MITM Attack Simulation (Manual)
### Set up steps
1. Run proxy
```
python3 attacks/mitm.py
```
2. In login_window.py, set:
```
PORT = 8080 # instead of 12345
```
3. Run the server on port 12345
```
python3 server/basic_server.py
```
4. Launch chat clients. Messages will pass through the proxy
example output:
[Proxy] Got connection from ('127.0.0.1', 54201)
[C→S] [Ania]: Hello Sunny!
[S→C] [Sunny]: Hi Ania!

---

## Team:
- Anna Niedzialek
- Sunny Doan
- Aaron Mundanilkunathil

**Course:**<br>
CS 166 — Information Security<br>
Instructor: Dr. Chao-Li Tarng<br>
Semester: Spring 2025<br>
Team #: 11

