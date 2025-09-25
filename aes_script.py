from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Step 1: Load AES key from existing file ---
key_path = r"C:\Users\chiru\OneDrive\Documents\FALL 1 SEMESTER\InfoSec\InfoSec_Fall2025-main\InfoSec_Fall2025-main\secret_aes.key"

with open(key_path, "rb") as f:
    key = f.read().strip()  # read raw key bytes
print(f"Using AES key from file ({len(key)*8} bits): {key.hex()}")

# --- Step 2: Original message ---
M = 82
print(f"Original message M: {M}")

# --- Step 3: AES encryption (ECB + PKCS7 padding) ---
cipher = AES.new(key, AES.MODE_ECB)
plaintext_bytes = bytes([M])  # one-byte message
ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))

print("AES ciphertext:", ciphertext.hex())

# --- Step 4: AES decryption ---
decipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)

M_prime = decrypted[0]
print(f"Decrypted message M': {M_prime}")
