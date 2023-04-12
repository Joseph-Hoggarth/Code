import tkinter as tk
import socket
import threading
import sys
import base64
import os

from cryptography.fernet import Fernet

class ChatClient:
    def __init__(self, host, port, name, fernet=None):
        self.host = host
        self.port = port
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.fernet = fernet or Fernet(base64.b64encode(os.urandom(32)))
        self.sock.connect((host, port)
    def connect(self):
        self.sock.connect((self.host, self.port))
        self.sock.send(self.name.encode())
        print("Connected to", self.host, "on port", self.port)

    def send_msg(self, msg):
        try:
            encrypted_msg = self.fernet.encrypt(msg.encode())
            self.socket.send(encrypted_msg)
        except:
            print("Error sending message")

    def receive_msg(self):
        while True:
            try:
                msg = self.socket.recv(1024)
                if msg:
                    decrypted_msg = self.fernet.decrypt(msg).decode()
                    print(decrypted_msg)
            except:
                print("Connection Error")
                self.socket.close()
                break

    def start_chatting(self):
        receive_thread = threading.Thread(target=self.receive_msg)
        receive_thread.start()

        while True:
            msg = input()
            self.send_msg(f"{self.name}: {msg}")

class ChatGUI:

    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Encrypted Chat App")

        self.chat_client = None

        self.host_label = tk.Label(self.window, text="Host:")
        self.host_label.pack()
        self.host_entry = tk.Entry(self.window)
        self.host_entry.pack()

        self.port_label = tk.Label(self.window, text="Port:")
        self.port_label.pack()
        self.port_entry = tk.Entry(self.window)
        self.port_entry.pack()

        self.name_label = tk.Label(self.window, text="Name:")
        self.name_label.pack()
        self.name_entry = tk.Entry(self.window)
        self.name_entry.pack()

        self.connect_button = tk.Button(self.window, text="Connect", command=self.connect)
        self.connect_button.pack()

        self.chat_frame = tk.Frame(self.window)

        self.scrollbar = tk.Scrollbar(self.chat_frame)

        self.msg_list = tk.Listbox(self.chat_frame, height=15, width=50, yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.msg_list.pack(side=tk.LEFT, fill=tk.BOTH)
        self.msg_list.pack()
        self.chat_frame.pack()

        self.entry_field = tk.Entry(self.window)
        self.entry_field.pack()

        self.send_button = tk.Button(self.window, text="Send", command=self.send_message)
        self.send_button.pack()

    def connect(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        name = self.name_entry.get()

        self.chat_client = ChatClient(host, port, name)
        self.chat_client.connect()

        threading.Thread(target=self.chat_client.start_chatting).start()

    def send_message(self):
        if self.chat_client:
            msg = self.entry_field.get()
            self.chat_client.send_msg(f"{self.chat_client.name}: {msg}")

            self.msg_list.insert(tk.END, f"{self.chat_client.name}: {msg}")
            self.entry_field.delete(0, tk.END)

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    client = ChatGUI()
    client.run()
