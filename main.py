import sys, json, hashlib, getpass, os, pyperclip
from cryptography.fernet import Fernet

#Hashing Login Password
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

#create secret key
def create_key():
    return Fernet.generate_key()

# Initialize Fernet cipher
def initialize_cipher(key):
    return Fernet(key)

# encrypt password
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

# decrypt password
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()
