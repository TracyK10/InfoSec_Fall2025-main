from Crypto.Random import get_random_bytes

def generate_key(filename="secret_aes.key"):
    key = get_random_bytes(32) # 32 bytes = 256-bit AES key
    with open(filename, "wb") as f:
        f.write(key)
    print(f"[+] AES key generated and saved to {filename}")
if __name__ == "__main__":
    generate_key()