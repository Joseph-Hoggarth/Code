import tkinter as tk
import socket
import threading

from Crypto.Cipher import AES
import os

#TO DO LIST:
# Setup server to handle several connections at once between clients
# Add encryption
# 
# Current setup is vulnerable to lots of stuff eg
# Message injection: no input sanitisation, would be worse if we had a database where we kept the message logs and stuff
# Man in the middle: Fixed by encryption
# DOS: Can flood server with connection requests or lots of messages
# Bufferoverflow: Don't know how messagebox works in tkinter 
# Authentication: Attacker could emulate legitimate connection and gain unauthorised access to server


class MessagingApp:

    # generate a random 16-byte key for AES encryption
    key = os.urandom(16)

    # initialize the cipher object with the key and AES mode as EAX
    # using another cipher could be better because this one parses it twice so might reduce runtime and put stress on server
    cipher = AES.new(key, AES.MODE_EAX)

    def __init__(self, master):
        self.master = master
        self.master.title("Chronos")

        self.entry = tk.Entry(self.master)
        self.entry.pack()

        self.button = tk.Button(self.master, text="Send", command=self.send_message)
        self.button.pack()

        self.text = tk.Text(self.master)
        self.text.pack()

        self.name = tk.Entry(self.master)
        self.name.pack()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # would chasnge localhost if we host server online, port number has to be same as server.
        self.sock.connect(('localhost', 9999))

        self.thread = threading.Thread(target=self.receive_messages)
        self.thread.daemon = True
        self.thread.start()

    #def receive_messages(self):
    # Receive messages from the server, decrypt them, and update the text area
     #   while True:
      #      data = self.sock.recv(1024)
       #     if not data:
        #        break
         #   print(data)
          #  nonce, ciphertext = data.split(b'|')
           # plaintext = self.cipher.decrypt(ciphertext)
            #self.text.insert(tk.END, "\n" + plaintext.decode())
    
    def send_message(self):
        #function for encrypting messages in correct format before sending
        def decombobulate(self, message: str) -> bytes:
            message_bytes = message.encode("utf-8")
            nonce = self.cipher.nonce
            ciphertext, tag = self.cipher.encrypt_and_digest(message_bytes)
            return b"".join([nonce, ciphertext, tag])

        # Encrypt the message and send it to the server
        message = self.entry.get()
        encrypted_message = decombobulate(self, message)
        self.sock.sendall(bytes(encrypted_message))

    def receive_messages(self):
    # Receive messages from the server, decrypt them, and update the text area
        while True:
            data = self.sock.recv(1024)
            if not data:
                break
            print(data)
            if b'|' not in data:
                self.text.insert(tk.END, "\n" + data.decode())
            else:
                nonce, ciphertext = data.split(b'|')
                plaintext = self.cipher.decrypt(ciphertext)
                self.text.insert(tk.END, "\n" + plaintext.decode()) 

root = tk.Tk()
app = MessagingApp(root)
root.mainloop()
