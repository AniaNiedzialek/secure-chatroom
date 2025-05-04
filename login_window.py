from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
)
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

import sys

import json
import hashlib
import os


def hash_password(password: str) -> str:
    # import hashlib
    return hashlib.sha256(password.encode()).hexdigest()
    
def load_users():
    import json, os
    if not os.path.exists("users.json"):
        return {}
    with open("users.json", "r") as f:
        return json.load(f)
    
class SignalWrapper(QObject):
    message_received = pyqtSignal(str)
 
class ConnectionWindow(QWidget):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Connect to Server")
        self.setGeometry(200,200, 400, 300)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Server IP Addres")
        layout.addWidget(self.ip_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port Number")
        layout.addWidget(self.port_input)
        
        self.connect_button = QPushButton("Next")
        self.connect_button.clicked.connect(self.proceed_to_login)
        layout.addWidget(self.connect_button)
        
        self.setLayout(layout)
        
        self.setStyleSheet("""
        QWidget{
            background-color: #442b54;
                color: #ffffff;
                    font-family: 'Helvetica Neue';
                    font-size: 13px;
        }
        
        QTextEdit {
            background-color: #6d4d6e;
                border: 1px solid #3e3e55;
                padding: 8px;
                color: #d0d0ff;
        }
        
        QLineEdit {
            background-color: #6d4d6e;
                border: 1px solid #444466;
                padding: 6px;
                color: #e0e0ff;
        }
        
        QPushButton {
            background-color: #6b5e7d;
            color: white;
            border-radius:6x;
            padding: 6px;
        }
        
        QPushButton:hover {
            background-color: #e667b8;
                
        }
        
        """)
    
    def proceed_to_login(self):
        ip = self.ip_input.text().strip()
        port = int(self.port_input.text().strip())
        
        if not ip or not port:
            QMessageBox.warning(self, "Error", "Enter a valid IP and port.")
            return
        
        self.login_window = LoginWindow(ip, port)
        self.login_window.show()
        self.close()
        
        
 
class LoginWindow(QWidget):
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
                
        self.setWindowTitle("SafeChat")
        self.setGeometry(200,200, 400, 300)
        
        layout = QVBoxLayout()
        
        self.intro = QLabel("Welcome to the SafeChat!")
        self.intro.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 15px;")
        self.intro.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.intro)
        
        self.label = QLabel("Enter your credentials")
        self.label.setStyleSheet("margin-bottom: 5px;")
        
        layout.addWidget(self.label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username") 
        layout.addWidget(self.username_input)  
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")    
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.attempt_login) 
        layout.addWidget(self.login_button)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.attempt_register)
        layout.addWidget(self.register_button)
        
        self.setLayout(layout)
        
        self.setStyleSheet("""
            QWidget {
                
                font-family: 'Helvetica Neue';
                font-size: 13px;
                color: #ffffff;

            }
            
            LoginWindow{
                background-color: #472d45;
            }
            
            QLineEdit {
                background-color: #573d61;
                border: 1px solid #7e5e74;
                padding: 5px;
                border-radius: 4px;
                color: #f0f0ff;
            }
            
            QPushButton {
                background-color: #a0588a;
                color: white;
                padding: 6px;
                border: none;
                border-radius: 6px;
            }
            
            QPushButton:hover {
                background-color: #bc5ebf;
            }
        """)
        
    def attempt_login(self):
        # ip = self.ip
        # port = self.port

        # self.chat_window = ChatWindow(username, self.ip, self.port, self)
        
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        users = load_users()
        hashed = hash_password(password)
        
        if username in users and users[username] == hashed:
            self.label.setText(f"Login successful! Welcome to Chatroom, {username}!")
            
            self.chat_window = ChatWindow(username, self.ip, self.port, self)
            self.chat_window.show()
            self.hide()
        else:
            self.label.setText("Invalid username or password!")
        
    def attempt_register(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        users = load_users()
        
        if username in users:
            self.label.setText("Username already exists!")
        elif not username or not password:
            self.label.setText("Please enter both fields..")
        else:
            users[username] = hash_password(password)
            with open("users.json", "w") as f:
                json.dump(users, f, indent=4)
            self.label.setText("Registration successful! You can log in now!")
    
    
from PyQt5.QtWidgets import QTextEdit, QLineEdit, QPushButton, QHBoxLayout  
import socket
import threading
from client.crypto_utils import encrypt_message, decrypt_message

# HOST = "127.0.0.1"
# PORT = 12345 #8080 for MITM attack


class ChatWindow(QWidget):
    def __init__(self, username, ip, port, login_window=None):
        super().__init__()
        self.running = True
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((ip, port))
            self.connected = True
            print("[Client] connected to the server.")
        except Exception as e:
            self.connected = False
            QMessageBox.critical(self, "Connection Failed", f"Could not connect to the {ip}:{port}\nError: {str(e)}")
            self.close()
            return
        self.username = username
        self.ip = ip
        self.port = port
        self.login_window = login_window
        self.encryption_enabled = True  # Default to enabled
        
        self.setWindowTitle(f"Chatroom - {username}")
        self.setGeometry(250, 250, 400, 500)
        
        layout = QVBoxLayout()
        
        # Add encryption toggle button
        self.encryption_toggle = QPushButton("Encryption: ON")
        self.encryption_toggle.setCheckable(True)
        self.encryption_toggle.setChecked(True)
        self.encryption_toggle.clicked.connect(self.toggle_encryption)
        layout.addWidget(self.encryption_toggle)
        
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)
        
        self.load_history()
        
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        input_layout.addWidget(self.message_input)
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)
        
        self.logout_button = QPushButton("Log Out")
        self.logout_button.clicked.connect(self.logout)
        layout.addWidget(self.logout_button)
        
        layout.addLayout(input_layout)
        self.setLayout(layout)
        

        receive_thread = threading.Thread(target=self.receive_message)
        receive_thread.daemon = True
        receive_thread.start()
        
        self.send_button.setEnabled(False)
        self.message_input.textChanged.connect(self.check_input)
        
        self.signals = SignalWrapper()
        self.signals.message_received.connect(self.display_message)

        
        self.setStyleSheet("""
            QWidget{
                background-color: #442b54;
                    color: #ffffff;
                        font-family: 'Helvetica Neue';
                        font-size: 13px;
            }
            
            QTextEdit {
                background-color: #6d4d6e;
                    border: 1px solid #3e3e55;
                    padding: 8px;
                    color: #d0d0ff;
            }
            
            QLineEdit {
                background-color: #6d4d6e;
                    border: 1px solid #444466;
                    padding: 6px;
                    color: #e0e0ff;
            }
            
            QPushButton {
                background-color: #6b5e7d;
                color: white;
                border-radius:6x;
                padding: 6px;
            }
            
            QPushButton:hover {
                background-color: #e667b8;
                    
            }
            
        """)
    
    def check_input(self):
        text = self.message_input.text().strip()
        self.send_button.setEnabled(bool(text))
    
    def toggle_encryption(self):
        self.encryption_enabled = self.encryption_toggle.isChecked()
        self.encryption_toggle.setText(f"Encryption: {'ON' if self.encryption_enabled else 'OFF'}")
        self.encryption_toggle.setStyleSheet(
            "background-color: #4CAF50;" if self.encryption_enabled else "background-color: #f44336;"
        )
    
    def send_message(self):
        if not self.connected:
            QMessageBox.warning(self, "Not Connected", "You are not connected to the server.")
            return
        
        message = self.message_input.text()
        self.message_input.returnPressed.connect(self.send_message)
        if message:
            full_message = f"[{self.username}]: {message}"
            
            try:
                if self.encryption_enabled:
                    encrypted_message = encrypt_message(full_message)
                    self.client_socket.send(encrypted_message)
                else:
                    self.client_socket.send(full_message.encode())
                
                self.message_input.clear()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to send message: {str(e)}")

    def receive_message(self):
        while self.running and self.connected:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                    
                try:
                    # Try to decrypt first (in case it's encrypted)
                    decrypted_message = decrypt_message(data)
                    if self.encryption_enabled:
                        self.signals.message_received.emit(decrypted_message)
                    else:
                        self.signals.message_received.emit(f"[Encrypted Message Received]")
                except:
                    # If decryption fails, treat as plain text
                    message = data.decode()
                    self.signals.message_received.emit(message)
                    
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                break
           
    def logout(self):
        self.running = False
        self.connected = False
        self.client_socket.close()
        self.close()
        
        self.login_window = LoginWindow(self.ip, self.port)
        self.login_window.show()

    def display_message(self, message):
        if message.startswith(f"[{self.username}]"):
            formatted = f'<span style="color:#d7aaff;">{message}</span>'
        else:
            formatted = f'<span style="color:#80dfff;">{message}</span>'
        self.chat_display.append(formatted)
    
    def load_history(self):
        try: 
            with open(f"history_{self.username}.txt", "r") as f:
                history = f.read()
                self.chat_display.setPlainText(history)
        except FileNotFoundError:
            self.chat_display.setPlainText("[No chat history]")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConnectionWindow()
    window.show()
    sys.exit(app.exec_())