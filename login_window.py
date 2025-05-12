from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QInputDialog
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
        
        # Add note about IP address
        note_label = QLabel("Note: Enter the server's IP address and port to connect.")
        note_label.setStyleSheet("color: #a0a0a0; font-style: italic; margin-bottom: 10px;")
        note_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(note_label)
        
        # Server connection fields
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Server IP Address")
        self.ip_input.setText("127.0.0.1")  # Set default IP
        layout.addWidget(self.ip_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Server Port Number")
        self.port_input.setText("12345")  # Set default port
        layout.addWidget(self.port_input)
        
        # MITM proxy fields
        self.mitm_ip_input = QLineEdit()
        self.mitm_ip_input.setPlaceholderText("MITM Proxy IP (optional) - default 127.0.0.1")
        layout.addWidget(self.mitm_ip_input)
        
        self.mitm_port_input = QLineEdit()
        self.mitm_port_input.setPlaceholderText("MITM Proxy Port (optional) - default 8080")

        layout.addWidget(self.mitm_port_input)
        
        self.connect_button = QPushButton("Next")
        self.connect_button.clicked.connect(self.proceed_to_login)
        layout.addWidget(self.connect_button)
        
        self.setLayout(layout)
        self.setStyleSheet("""
            QWidget {
                background-color: #472d45;
                font-family: 'Helvetica Neue';
                font-size: 13px;
                color: #ffffff;
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
    
    def proceed_to_login(self):
        ip = self.ip_input.text().strip()
        port = int(self.port_input.text().strip())
        
        # Get MITM values with defaults if empty
        mitm_ip = self.mitm_ip_input.text().strip() or "127.0.0.1"
        try:
            mitm_port = int(self.mitm_port_input.text().strip()) if self.mitm_port_input.text().strip() else 8080
        except ValueError:
            mitm_port = 8080  # Default if invalid number
        
        if not ip or not port:
            QMessageBox.warning(self, "Error", "Enter a valid server IP and port.")
            return
        
        self.login_window = LoginWindow(ip, port, mitm_ip, mitm_port)
        self.login_window.show()
        self.close()
        
        
 
class LoginWindow(QWidget):
    def __init__(self, ip, port, mitm_ip, mitm_port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.mitm_ip = mitm_ip
        self.mitm_port = mitm_port
                
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
            
            self.chat_window = ChatWindow(username, self.ip, self.port, self.mitm_ip, self.mitm_port)
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
    def __init__(self, username, ip, port, mitm_ip, mitm_port, login_window=None):
        super().__init__()
        self.running = True
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Add MITM proxy option
        self.use_mitm = QMessageBox.question(
            self, 
            "Connection Mode",
            "Do you want to use MITM proxy?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        ) == QMessageBox.Yes
        
        try:
            if self.use_mitm:
                # Connect through MITM proxy using provided details
                self.client_socket.connect((mitm_ip, mitm_port))
            else:
                # Direct connection to server
                self.client_socket.connect((ip, port))
            self.connected = True
            print("[Client] connected to the server.")
        except Exception as e:
            self.connected = False
            QMessageBox.critical(self, "Connection Failed", f"Could not connect to the server\nError: {str(e)}")
            self.close()
            return
        self.username = username
        self.ip = ip
        self.port = port
        self.mitm_ip = mitm_ip
        self.mitm_port = mitm_port
        self.login_window = login_window
        self.encryption_enabled = False  # Default to disabled
        self.cipher = None  # Will store the Fernet cipher instance
        
        self.setWindowTitle(f"Chatroom - {username}")
        self.setGeometry(250, 250, 400, 500)
        
        layout = QVBoxLayout()
        
        # Add encryption toggle button
        self.encryption_toggle = QPushButton("Encryption: OFF")
        self.encryption_toggle.setCheckable(True)
        self.encryption_toggle.setChecked(False)
        self.encryption_toggle.clicked.connect(self.toggle_encryption)
        layout.addWidget(self.encryption_toggle)
        
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)
        
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.message_input.returnPressed.connect(self.send_message)
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
        if not self.encryption_enabled:
            # Prompt for encryption key when enabling
            key, ok = QInputDialog.getText(
                self, 
                "Encryption Key",
                "Enter encryption key (leave empty to cancel):",
                QLineEdit.Password
            )
            
            if ok and key:
                try:
                    from client.crypto_utils import generate_key_from_password, create_cipher
                    encryption_key = generate_key_from_password(key)
                    self.cipher = create_cipher(encryption_key)
                    self.encryption_enabled = True
                    self.encryption_toggle.setText("Encryption: ON")
                    self.encryption_toggle.setStyleSheet("background-color: #4CAF50;")
                    QMessageBox.information(self, "Success", "Encryption enabled successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to enable encryption: {str(e)}")
                    self.encryption_enabled = False
                    self.encryption_toggle.setChecked(False)
                    self.encryption_toggle.setText("Encryption: OFF")
                    self.encryption_toggle.setStyleSheet("")
            else:
                self.encryption_enabled = False
                self.encryption_toggle.setChecked(False)
                self.encryption_toggle.setText("Encryption: OFF")
                self.encryption_toggle.setStyleSheet("")
        else:
            # Disable encryption
            self.encryption_enabled = False
            self.cipher = None
            self.encryption_toggle.setText("Encryption: OFF")
            self.encryption_toggle.setStyleSheet("")
            QMessageBox.information(self, "Encryption Disabled", "Messages will now be sent unencrypted.")
    
    def send_message(self):
        if not self.connected:
            QMessageBox.warning(self, "Not Connected", "You are not connected to the server.")
            return
        
        message = self.message_input.text()
        self.message_input.returnPressed.connect(self.send_message)
        if message:
            full_message = f"[{self.username}]: {message}"
            
            try:
                if self.encryption_enabled and self.cipher:
                    from client.crypto_utils import encrypt_message
                    encrypted_message = encrypt_message(full_message, self.cipher)
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
                    if self.encryption_enabled and self.cipher:
                        from client.crypto_utils import decrypt_message
                        decrypted_message = decrypt_message(data, self.cipher)
                        self.signals.message_received.emit(decrypted_message)
                    else:
                        # If encryption is disabled or we don't have a cipher, try to decode as plain text
                        try:
                            message = data.decode()
                            self.signals.message_received.emit(message)
                        except:
                            self.signals.message_received.emit("[Encrypted Message Received]")
                except Exception as e:
                    # If decryption fails, show encrypted message
                    self.signals.message_received.emit("[Encrypted Message Received]")
                    
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                break
           
    def logout(self):
        self.running = False
        self.connected = False
        self.client_socket.close()
        self.close()
        
        self.login_window = LoginWindow(self.ip, self.port, self.mitm_ip, self.mitm_port)
        self.login_window.show()

    def display_message(self, message):
        if message.startswith(f"[{self.username}]"):
            formatted = f'<span style="color:#d7aaff;">{message}</span>'
        else:
            formatted = f'<span style="color:#80dfff;">{message}</span>'
        self.chat_display.append(formatted)
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConnectionWindow()
    window.show()
    sys.exit(app.exec_())