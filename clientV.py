from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import string
import random
import os
import socket
import time
import re

'''# Function to generate a pair of private and public keys for the client
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

# Function to send encrypted message to the server
def send_message(message):
    '''encrypted_response = server_public_key.encrypt(
        message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
    )'''

    client_socket.sendall(message.encode())

# Function to recieve message from server and decrypt it
def recieve_message():

    '''encrypted_message = client_socket.recv(1024)
    decrypted_message = client_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )'''

    message = client_socket.recv(1024)
    print("Recieved message: " , message) # DELETE 
    return message.decode()
    
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

# --- ENCRYPTION FUNCTIONS START ---

# Function to open dialog to pick file
def pickFile():
    return filedialog.askopenfilename()

# Function to open a directory picker dialog
def pickDir():
    return filedialog.askdirectory()

# Function to generate a random encryption key
def generateRandomKey():
    return get_random_bytes(32)

# Function to generate a random file name
def generateRandomFileName():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

# Function to encrypt bytes using AES-GCM
def encryptBytes(bytes, key):
    cipher = AES.new(key, AES.MODE_GCM)
    encryptedBytes, tag = cipher.encrypt_and_digest(pad(bytes, AES.block_size))
    return encryptedBytes, cipher.nonce

# Function to perform file encryption
def performEncryption(selectedFile, encryptDialog, createNewName, saveInNewLocation, username, password):
    encryptDialog.destroy()
    try:
        # Gets the directory of the selected file if the value of saveInNewLocation is 0, otherwise executes pickDir function to get new location directory
        selectedDir = os.path.dirname(selectedFile) if not saveInNewLocation else pickDir()

        # Get name of the file along with extension
        originalFileName = os.path.basename(selectedFile)

        # Generate a file ID to store for the database
        fileId = generateRandomKey()

        # Split the extension from the file name if createNewName value is 0, otherwise generate a random name, and attach to fileName variable
        fileName = os.path.splitext(originalFileName)[0] if not createNewName else generateRandomFileName()

        # Generate keyBytes to be used for encryption
        keyBytes = generateRandomKey() # TO BE DELETED AFTER STORING TO DATABASE???

        # Open the file to read and encrypt its contents with encryptByte function
        with open(selectedFile, "rb") as file:
            fileBytes = file.read()
        encryptedFileBytes, iv = encryptBytes(fileBytes, keyBytes)

        # Store cipher as encrypted fileID + encrypted content
        cipher = fileId + encryptedFileBytes

        # Store information in database
        # Create a message containing data to send to server
        encrypt_data_list = [fileId.hex(), originalFileName, keyBytes.hex(), iv.hex(), username, password]
        print(type(encrypt_data_list[0])) # DELETE
        print([len(i) for i in encrypt_data_list]) # DELETE
        send_message("E " + ','.join(encrypt_data_list))
        

        # Create file with .V extension in the provided directory to write and write the cipher onto it
        with open(os.path.join(selectedDir, fileName + ".V"), "wb") as file:
            file.write(cipher)    
        os.remove(selectedFile) # Deletes the file that was not encrypted
        showMessage("File encrypted successfully.")
    except Exception as e:
        print(e)
        showMessage("Error encrypting file.")

# --- ENCRYPTION FUNCTIONS END ---
        
# --- DECRYPTION FUNCTIONS START ---
        
# Function to retrieve file details from the database
def fileDetails(file_id, username, password):
    
    # Formulate a message to send to server
    message = [file_id.hex(), username, password]

    # Request data from server
    send_message("D " + ','.join(message))

    # Receive data from server
    message = recieve_message()
    print("Recieved message for keys: ", message)
    details = message.split(',')
    print("details: ", details) # DELETE

    # Return the list
    return details

# Function to decrypt bytes using AES-GCM
def decryptBytes(encryptedText, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        decryptedBytes = unpad(cipher.decrypt(encryptedText), AES.block_size)
        return decryptedBytes
    except (ValueError, KeyError):
        return None

# Function to delete encryption records from database   
def deleteRecord(file_id, username, password):

    message = [file_id.hex(), username, password]
    print("Deleted Message: ", message)

    # Send message to server, requesting to delete encryption records
    send_message("O " + ','.join(message))

    # Receive confirmation

# --- DECRYPTION FUNCTIONS END ---

# Function for when login button is clicked
def loginButtonClicked(username, password):
            
    # Encrypt and send username and password to the server for cross-checking
    send_message("L " + username + "," + password)

    # Recieve userID from server
    # user_id is a string
    user_id = recieve_message()

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
        send_message("R " + username + "," + password)

        # Recieve confirmation of registration from user
        if recieve_message() == 'registered':
            showMessage("Registration successful. You can now log in")
    
    # The password is not strong
    else:
        showMessage("Enter a Strong password.")
    return False  

# Function to Encrypt file
def encryptFile():
    
    # Select file to Encrypt
    selectedFile = pickFile()
    if selectedFile is None:
        return
    encryptDialog = Toplevel(root)
    encryptDialog.title("Encryption Options")
    encryptDialog.geometry("300x150")

    createNewName = BooleanVar()
    saveInNewLocation = BooleanVar()

    # If clicked, createNewName value becomes 1 or True else 0 or False
    createNewNameCheckBox = Checkbutton(encryptDialog, text="Change File Name", variable=createNewName)
    # If clicked, saveInNewLocation value becomes 1 or True else 0 or False
    saveInNewLocationCheckBox = Checkbutton(encryptDialog, text="Save in New Location", variable=saveInNewLocation)

    # On clicking the button, selected file, dialog box, values of createNewName and saveInNewLocation get sent to performEncryption function
    encryptButton = Button(encryptDialog, text="Encrypt", command=lambda: performEncryption(selectedFile, encryptDialog, createNewName.get(), saveInNewLocation.get(), usernameField.get(), passwordField.get()))
    # Destroys the dialog box
    cancelButton = Button(encryptDialog, text="Cancel", command=encryptDialog.destroy)

    createNewNameCheckBox.pack()
    saveInNewLocationCheckBox.pack()
    encryptButton.pack()
    cancelButton.pack()


# Function to Decrypt file
def decryptFile():
    
    print("--- DELETION BEGINS ---")
    # Pick file to decrypt
    selectedFile = pickFile()
    if selectedFile is None:
        return
    
    # Decryption Process
    username = usernameField.get()
    password = passwordField.get()

    try:
        with open(selectedFile, "rb") as file:
            cipher = file.read()

        # We know that contents of the encrypted file is cipher which is encrypted FileID + encrypted file contents    
        file_id = cipher[:32] # Encrypted fileID
        encryptedFileBytes = cipher[32:] # Encrypted file contents
        

        # Get the details of the filename, text used for encryption from database
        details = fileDetails(file_id, username, password)

        originalFileName = details[0]
        keyBytes = bytes.fromhex(details[1])
        iv = bytes.fromhex(details[2])
        print("keybytes: ", keyBytes) # DELETE
        print("iv: ", iv) # DELETE

        # With the details, decrypt the file using decryptBytes function
        decryptedBytes = decryptBytes(encryptedFileBytes, keyBytes, iv)
        print(" Decryption Worked") # DELETE
        
        if decryptedBytes is not None:

            # Get original directory and create a new file with the OG name and dir
            originalDir = os.path.dirname(selectedFile)
            decryptedFile = os.path.join(originalDir, originalFileName)

            # Open the file to write and write the contents produced by decryption
            with open(decryptedFile, "wb") as file:
                file.write(decryptedBytes)
            os.remove(selectedFile) # Remove selected file
            print("Delete Record...")
            deleteRecord(file_id, username, password) # Remove the database record for the particular encryption

            showMessage("File decrypted successfully and saved as " + os.path.basename(decryptedFile))

        else:
            showMessage("Error decrypting file. Please make sure you selected the correct encryption key.")
    except Exception as e:
        print(e)
        showMessage("Error decrypting file.")   

# Function to hide components
def hideComponents(*components):
    for component in components:
        component.place_forget()


# ---GLOBAL STARTS HERE---

# Generate client's private and public keys
'''client_private_key, client_public_key = generate_key()'''

# Create a socket for the client
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:

    # Connect to the server
    client_socket.connect(("192.168.0.103", 12345))

    # Receive the server's public key
    '''server_public_key_data = client_socket.recv(1024)'''
    

    # Send the client's public key to the server
    '''client_socket.sendall("connected!".encode())'''

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



