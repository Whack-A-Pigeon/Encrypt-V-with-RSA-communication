from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import string
import socket
import pymysql
import os
import sys
import hashlib
import time

# Function to establish a database connection
def connectToDatabase():
    try:
        connection = pymysql.connect(host="localhost", user="root", password="root", database="encryptiv_db") # Add your own username and password here
        return connection
    except Exception as e:
        print(e)
        return None

# Function to generate a pair of private and public keys
def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to serialize a public key to bytes
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

# Function to deserialize a public key from bytes
def deserialize_key(data):
    return serialization.load_pem_public_key(data, backend=default_backend())
    
# Function to hash a password
def hashPassword(password):
    return hashlib.sha256(password.encode()).hexdigest()
    
# Check if the Login details match in the database
def checkLoginDetails(decrypted_message, connection):

    # Separate decrypted_message to username and password
    decrypted_message = decrypted_message.split(',')
    username, password = decrypted_message[0], decrypted_message[1]
    
    # Find the username and password in the database
    try:
        with connection.cursor() as cursor:
            query = "SELECT user_id FROM users WHERE username = %s AND password = %s"
            cursor.execute(query, (username, hashPassword(password)))
            result = cursor.fetchone()
            if result:
                return result[0]
    except Exception as e:
        print(e)
    return -1

def registerUser(decrypted_message, connection):

    # Separate decrypted_message to username and password
    decrypted_message = decrypted_message.split(',')
    username, password = decrypted_message[0], decrypted_message[1]
    try:
        with connection.cursor() as cursor:
            insert_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
            cursor.execute(insert_query, (username, hashPassword(password)))
        connection.commit()
        return True
    except Exception as e:
        print(e)



# Main function to run the server
def main():

    # Initialize userID and Establish MYSQL connection
    userId = 0
    connection = connectToDatabase()
    if connection is None:
        sys.exit("MYSQL connection unsuccessful!")
    
    # Generate server's private and public keys
    server_private_key, server_public_key = generate_key()

    # Create a socket for the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

        # Bind the socket to an IP address and port
        server_socket.bind(("192.168.0.103", 12345))
        # Listen for incoming connections
        server_socket.listen()

        print("Server is listening for incoming connections...")

        # Accept a connection from a client
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connection from {addr}")

            # Send the server's public key to the client
            conn.sendall(serialize_key(server_public_key))

            # Receive the client's public key
            client_public_key_data = conn.recv(1024)
            client_public_key = deserialize_key(client_public_key_data)

            while True:

                # Receive and decrypt a message from the client
                encrypted_message = conn.recv(1024)
                decrypted_message = server_private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                decrypted_message = decrypted_message.decode()

                # Login Procedure
                if decrypted_message[:5] == 'login':

                    # Function will fetch the userID for the given username and password
                    user_id = checkLoginDetails(decrypted_message[6:], connection)

                    # Encrypt and Send the user_id to client
                    message = str(user_id)
                    encrypted_user_id = client_public_key.encrypt(
                        message.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    conn.sendall(encrypted_user_id)
                
                # Register Procedure
                if decrypted_message[:8] == 'register':

                    # It takes the user data and registers to database 
                    if registerUser(decrypted_message[9:], connection):

                        # If registered, send encrypted message to client
                        message = "registered"
                        encrypted_response = client_public_key.encrypt(
                            message.encode(),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                        conn.sendall(encrypted_response)


# Maybe I dont need to send encrypted response for each If clause


# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
