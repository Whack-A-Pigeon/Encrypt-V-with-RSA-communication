# Encrypti-V

Encrypti-V is a simple client-server file encryption and decryption application developed in Python using the Tkinter library for the graphical user interface, MySQL for database storage, and the Crypto library for encryption.

## Features

 - User registration and login
 - File decryption with the correct encryption key
 - Option to change the file name during encryption
 - Option to save encrypted files in a different location
 - Strong password enforcement
 - Secure storage of encryption keys in a database

## Getting Started

### Prerequisites

- Python 3.x
- Tkinter (usually included with Python installations)
- MySQL server
- pymysql library (install using `pip install pymysql`)
- cryptography

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/Encrypti-V.git
   ```
2. **Navigate to the project directory:**

    ```bash
    cd Encrypti-V
    ```
3. **Set up the MySQL database**

   **Steps**
    1. Create Database:
       ```sql
       CREATE DATABASE encryptiv_db;
       ```
   2. Use the Database:
      ```sql
      USE encryptiv_db;
      ```
   3. Create User Table:
      ```sql
      CREATE TABLE users (
      user_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(255) NOT NULL,
      password VARCHAR(64) NOT NULL
      );
      ```
   4. Create Files Table:
      ```sql
      CREATE TABLE files (
      user_id INT NOT NULL,
      file_id BINARY(32) NOT NULL,
      file_name VARCHAR(255) NOT NULL,
      encryption_key BINARY(32) NOT NULL,
      iv BINARY(16),
      PRIMARY KEY (file_id),
      FOREIGN KEY (user_id) REFERENCES users(user_id)
      );
      ```
### Usage
  1. **Run the server:**
     ```bash
     python server.py
     ```
  2. **Run the Client:**
     ```bash
     python client.py
     ```
     
