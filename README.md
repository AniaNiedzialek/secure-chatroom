# Secure Chat Room with Usernames

This project is a simple terminal-based chat application that allows multiple users to communicate in real time through a server. It supports user-defined names and demonstrates socket programming in Python.

> This is the **insecure version** — future stages of the project will include encryption, authentication, and simulated attacks.

---

---

## How to Run the Project

### Requirements

- Python 3.10 or newer (recommended)
- OS: macOS, Linux, or Windows
- All dependencies are standard (`socket`, `threading`, etc.)

### Setup

1. **Clone the repository:**

```bash
git clone https://github.com/your-username/secure-chat-room.git
cd secure-chat-room


2. **Create a virtual environment:
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

### Running the server
cd server
python3 basic_server.py

Enter the server IP address
Type CTRL^C to exit

### Running the client
In a new terminal window:
cd client
python3 basic_client.py
Enter the same IP and port as the server

Enter your username

Type messages to chat

Type exit to disconnect cleanly

*** Features 
Supports multiple users
Custom usernames
Graceful disconnect (exit)
Server shutdown via Ctrl + C with proper cleanup


Team:
Anna Niedzialek
Sunny Doan
Aaron Mundanilkunathil

Course: CS 166 — Information Security
Instructor: Dr. Chao-Li Tarng
Semester: Spring 2025
Team #: 11

