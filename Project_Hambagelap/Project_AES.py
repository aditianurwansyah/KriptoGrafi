from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

def encrypt_aes(text, key):
    """Encrypt text using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher.iv + ciphertext  # IV + ciphertext

def decrypt_aes(ciphertext, key):
    """Decrypt text using AES-256-CBC"""
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext.decode()

def main():
    print("="*50)
    print("PROGRAM ENKRIPSI & DEKRIPSI MENGGUNAKAN AES")
    print("="*50)

    # Input teks rahasia dari pengguna
    plaintext = input("\nMasukkan teks rahasia: ")

    # Generate AES key (256-bit)
    aes_key = get_random_bytes(32)

    # Enkripsi
    start_time = time.time()
    aes_ciphertext = encrypt_aes(plaintext, aes_key)
    aes_encrypt_time = time.time() - start_time

    print(f"\nHasil Enkripsi AES (dalam bytes): {aes_ciphertext}")
    print(f"Waktu enkripsi AES: {aes_encrypt_time:.6f} detik")

    # Dekripsi
    start_time = time.time()
    aes_decrypted = decrypt_aes(aes_ciphertext, aes_key)
    aes_decrypt_time = time.time() - start_time

    print(f"\nHasil Dekripsi AES: {aes_decrypted}")
    print(f"Waktu dekripsi AES: {aes_decrypt_time:.6f} detik")

    # Ukuran ciphertext
    print(f"\nUkuran ciphertext AES: {len(aes_ciphertext)} byte")

if __name__ == "__main__":
    main() 