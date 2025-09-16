"""
Crypto utilities for file encryption/decryption using AES-256 in CBC mode.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

def load_key(key_file="secret_aes.key"):
    """Load the AES key from file."""
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_file(input_data, key):
    """
    Encrypt the input data using AES-256 in CBC mode.
    Returns: (iv + ciphertext) as bytes
    """
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(input_data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Return IV + ciphertext
    return iv + ciphertext

def decrypt_file(encrypted_data, key):
    """
    Decrypt data that was encrypted with encrypt_file.
    """
    # Extract the IV from the beginning of the data
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    # Create cipher object and decrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # Unpad and return the original data
    return unpad(decrypted_padded, AES.block_size)
