import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

host = 'localhost'
port = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, port))
sock.listen()
clients = []

# generate public-private key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

def broadcast(message):
    for client in clients:
        client.send(message)

def handle_client(client):
    # create cipher object with private key
    cipher = PKCS1_OAEP.new(key)

    while True:
        try:
            # receive and decrypt message
            encrypted_message = client.recv(4096)
            print(encrypted_message)
            message = cipher.decrypt(encrypted_message).decode()

            # broadcast decrypted message
            broadcast(message.encode('utf-8'))
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            broadcast(f'A User has left the chat room!'.encode('utf-8'))
            break

def receive():
    while True:
        print('Server is running and listening ...')
        client, address = sock.accept()
        print(f'connection is established with {str(address)}')

        # send public key to client
        client.send(public_key)

        clients.append(client)
        broadcast(f'\n User has connected to the chat room'.encode('utf-8'))
        client.send('\n you are now connected!'.encode('utf-8'))

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    receive()
