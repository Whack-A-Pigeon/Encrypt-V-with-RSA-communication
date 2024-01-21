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

'''# Function to generate a pair of private and public keys
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
'''

# Function to send encrypted message to client
def send_message(message):

    print("Message to be sent to client: ", message)   

    '''encrypted_response = client_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )'''
    conn.sendall(message.encode())

# Function to recieve message from client and decrypt it
def recieve_message():
    
    message = conn.recv(1024)
    '''decrypted_message = server_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )'''

    return message.decode()

# Function to hash a password
def hashPassword(password):
    return hashlib.sha256(password.encode()).hexdigest()
    
# Check if the Login details match in the database
def checkLoginDetails(username, password, connection):
    
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

# Store user details to database in users table
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

# Store encryption key details to database in files table [Post Encryption process]
def storeKeyInDatabase(decrypted_message, connection):

    # Separate decrypted message
    data = decrypted_message.split(',')
    print("data: ", data)

    # Establish data
    username = data[4]
    password = data[5]
    user_id = checkLoginDetails(username, password, connection) # Get user ID for the given user
    file_id = bytes.fromhex(data[0])
    FileName = data[1] 
    key_bytes = bytes.fromhex(data[2])
    iv = bytes.fromhex(data[3])

    # Instead of making new variables, I could put the elements of data for query, but new variables are helpful
    print(file_id, "\n", FileName,"\n", key_bytes,"\n", iv)
    encryptFileList = [file_id, FileName, key_bytes, iv]
    print([len(i) for i in encryptFileList])

    print("UserID: ", user_id, "\nFileID: ", file_id, "\nFileName: ", FileName, "\nkeybytes: ", key_bytes, "\nIV: ", iv)
    print([len(file_id), len(FileName), len(key_bytes), len(iv)])
    # Store data into the database
    try:
        with connection.cursor() as cursor:
            query = "INSERT INTO files (user_id, file_id, file_name, encryption_key, iv) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (user_id, file_id, FileName, key_bytes, iv))
        connection.commit()
        print("Storing successful")
    except Exception as e:
        print(e)

# [Pre Decryption Process]
def getKeyFromDatabase(decrypted_message, connection):

    # Establish data
    data = decrypted_message.split(',')
    file_id = bytes.fromhex(data[0])
    username = data[1]
    password = data[2]
    user_id = checkLoginDetails(username, password, connection)
    
    # Retrive details from database
    try:
        with connection.cursor() as cursor:
            query = "SELECT file_name, encryption_key, iv FROM files WHERE file_id = %s AND user_id = %s"
            cursor.execute(query, (file_id, user_id))
            result = cursor.fetchone()
            if result:
                details = [result[0], result[1].hex(), result[2].hex()]
                print(details)
                return details
    except Exception as e:
        print(e)
        return None

def deleteRecord(decrypted_message, connection):

    # Establish data
    data = decrypted_message.split(',')
    file_id = bytes.fromhex(data[0])
    username = data[1]
    password = data[2]
    user_id = checkLoginDetails(username, password, connection)
    try:
        with connection.cursor() as cursor:
            query = "DELETE FROM files WHERE file_id = %s AND user_id = %s"
            cursor.execute(query, (file_id, user_id))
        connection.commit()
        return True
    except Exception as e:
        print(e)


# ---GLOBAL STARTS HERE---
        
# Initialize userID and Establish MYSQL connection
connection = connectToDatabase()
if connection is None:
    sys.exit("MYSQL connection unsuccessful!")

# Generate server's private and public keys
'''server_private_key, server_public_key = generate_key()'''

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
        '''conn.sendall(serialize_key(server_public_key))'''

        # Receive the client's public key
        '''client_public_key_data = conn.recv(1024)
        client_public_key = deserialize_key(client_public_key_data)'''

        while True:

            # Receive and decrypt a message from the client
            received_message = recieve_message()

            # Login Check
            if received_message[0] == 'L':

                # Separate received_message to username and password
                received_message = received_message[2:].split(',')
                username, password = received_message[0], received_message[1]

                # Function will fetch the userID for the given username and password
                user_id = checkLoginDetails(username, password, connection)
                message = str(user_id)
            
            # Register User
            if received_message[0] == 'R':

                # Separate received_message to username and password
                received_message = received_message[2:].split(',')
                username, password = received_message[0], received_message[1]

                # It takes the user data and registers to database 
                if registerUser(username, password, connection):
                    message = "registered"
                """IN CASE THERE IS A DATABASE ERROR, WE NEED A PROPER ALTERNATIVE MESSAGE TO PROVIDE"""
            
            # Encrypted Details Storage
            if received_message[0] == 'E':

                # Store key and metadata into database
                storeKeyInDatabase(received_message[2:], connection)

                # Send message that key is stored
                message = "stored"
            
            # Data for decryption
            if received_message[0] == 'D':

                # Get key and metadata from database
                details = getKeyFromDatabase(received_message[2:], connection)

                # Formulate message to send to client
                message = ','.join(details)
                print("message for keys to be sent: ", message)
            
            # Delete record
            if received_message[0] == 'O':

                print("Time for deletion")

                # If deletion of record is successful
                if deleteRecord(received_message[2:], connection):
                    print("Deletion Successful")
                """IN CASE THERE IS A DATABASE ERROR, WE NEED A PROPER ALTERNATIVE MESSAGE TO PROVIDE"""
                
                continue

            # Send message to client
            send_message(message)

