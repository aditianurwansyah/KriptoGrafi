from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time

def encrypt_aes(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_aes(ciphertext_bytes, key):
    iv = ciphertext_bytes[:AES.block_size]
    ct = ciphertext_bytes[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def main():
    print("="*60)
    print("AES - ENKRIPSI/DEKRIPSI") 
    print("="*60)

    plaintext = input("\nMasukkan teks rahasia: ")

    aes_key = get_random_bytes(32)  # 256-bit

    # Enkripsi → bytes → base64 string
    start_time = time.time()
    ct_bytes = encrypt_aes(plaintext, aes_key)
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
    enc_time = time.time() - start_time

    print(f"\n🔓 Plaintext        : {plaintext}")
    print(f"🔒 Ciphertext         : {ct_b64}")
    print(f"⏱️  Waktu enkripsi    : {enc_time:.6f} detik")

    # Dekripsi: base64 → bytes → plaintext
    start_time = time.time()
    ct_bytes_restored = base64.b64decode(ct_b64)
    decrypted = decrypt_aes(ct_bytes_restored, aes_key)
    dec_time = time.time() - start_time

    print(f"\n🔓 Hasil dekripsi     : {decrypted}")
    print(f"⏱️  Waktu dekripsi    : {dec_time:.6f} detik")

if __name__ == "__main__":
    main() 