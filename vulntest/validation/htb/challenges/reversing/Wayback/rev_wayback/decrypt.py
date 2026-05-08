from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def decrypt_message(encrypted_message, key):
    try:
        key = key.ljust(32, b'\x00')
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        return decrypted_message.decode()
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

if __name__ == "__main__":
    encrypted_message = bytes.fromhex('ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89')
    key = input("Please input your key : ")
    decrypted_message = decrypt_message(encrypted_message, key.encode())
    if decrypted_message:
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Decryption failed or no valid message found.")
