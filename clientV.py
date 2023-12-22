from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import socket
import time
import re

# Function to generate a pair of private and public keys for the client
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

# Function to display a message dialog
def showMessage(message):
    messagebox.showinfo("Message", message)

# Function to show encryption and decryption buttons
def showButtons():
    encryptFileButton.place(x=100, y=110, width=90, height=30)
    decryptFileButton.place(x=210, y=110, width=90, height=30)

# Function to check if a password is strong
def isStrongPassword(password):
    return password is not None and re.match("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[_@#$%^&+=!]).{8,}$", password)

# Function for when login button is clicked
def loginButtonClicked(username, password):
            
    # Encrypt and send username and password to the server for cross-checking
    message = 'login' + ':' + username + ',' + password
    encrypted_response = server_public_key.encrypt(
        message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
    )
    client_socket.sendall(encrypted_response)

    # Recieve userID from server
    encrypted_message = client_socket.recv(1024)
    decrypted_message = client_private_key.decrypt(
        encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
    )
    # user_id is a string
    user_id = decrypted_message.decode()

    # Check whether the user_id is valid
    if user_id == '-1':
        showMessage("Login failed. Invalid username or password.")
    else:
        hideComponents(usernameLabel, usernameField, passwordField, passwordLabel, loginButton, registerButton, welcomeLabel)
        showButtons()


# Function for when register button is clicked
def registerButtonClicked(username, password):
    
    # Check if username or password is entered
    if username is None or password is None:
        showMessage("Enter a Valid Username and password.")
    
    # Check if the password is strong
    elif isStrongPassword(password):

        # Encrypt and send username and password to server to add to database
        message = 'register' + ':' + username + ',' + password
        encrypted_response = server_public_key.encrypt(
            message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
        )
        client_socket.sendall(encrypted_response)

        # Recieve confirmation of registration from user
        encrypted_message = client_socket.recv(1024)
        decrypted_message = client_private_key.decrypt(
            encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
        )
        if decrypted_message.decode() == 'registered':
            showMessage("Registration successful. You can now log in")
    
    # The password is not strong
    else:
        showMessage("Enter a Strong password.")
    return False  
    


# Function to Encrypt file
def encryptFile():
    return

# Function to Decrypt file
def decryptFile():
    return

# Function to hide components
def hideComponents(*components):
    for component in components:
        component.place_forget()



# Generate client's private and public keys
client_private_key, client_public_key = generate_key()

# Create a socket for the client
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    # Connect to the server
    client_socket.connect(("192.168.0.103", 12345))

    # Receive the server's public key
    server_public_key_data = client_socket.recv(1024)
    server_public_key = deserialize_key(server_public_key_data)

    # Send the client's public key to the server
    client_socket.sendall(serialize_key(client_public_key))

    # Create the main Tkinter window
    root = Tk()
    root.geometry("400x250")
    root.title("Encrypti V")
    root.resizable(False, False)

    # Load the background image
    backgroundImage = PhotoImage(file="C://Users//whack//OneDrive//Desktop//STUFF//Programming STUFF//Python//Encrypti-V//src//background.gif")
    backgroundLabel = Label(root, image=backgroundImage)
    backgroundLabel.place(x=0, y=0, relwidth=1, relheight=1)

    # Create and place UI elements
    welcomeLabel = Label(root, text="Welcome to Encrypti V")
    welcomeLabel.place(x=150, y=30)
    usernameLabel = Label(root, text="Username:")
    usernameLabel.place(x=50, y=80)
    passwordLabel = Label(root, text="Password:")
    passwordLabel.place(x=50, y=120)
    usernameField = Entry(root)
    usernameField.place(x=140, y=80, width=200, height=25)
    passwordField = Entry(root, show="*")
    passwordField.place(x=140, y=120, width=200, height=25)
    loginButton = Button(root, text="Login", command=lambda: loginButtonClicked(usernameField.get(), passwordField.get()))
    loginButton.place(x=140, y=160, width=90, height=30)
    registerButton = Button(root, text="Register", command=lambda: registerButtonClicked(usernameField.get(), passwordField.get()))
    registerButton.place(x=250, y=160, width=90, height=30)
    encryptFileButton = Button(root, text="Encrypt", command=encryptFile)
    decryptFileButton = Button(root, text="Decrypt", command=decryptFile)

    hideComponents(encryptFileButton, decryptFileButton)

    root.mainloop()



