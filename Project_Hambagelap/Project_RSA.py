from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import time

def generate_rsa_keys():
    """Generate RSA public and private keys"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(text, public_key):
    """Encrypt text using RSA-OAEP"""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(text.encode())
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    """Decrypt text using RSA-OAEP"""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

def main():
    print("="*50)
    print("PROGRAM ENKRIPSI & DEKRIPSI MENGGUNAKAN RSA")
    print("="*50)

    # Input teks rahasia dari pengguna
    plaintext = input("\nMasukkan teks rahasia (maksimal ~200 karakter): ")
    
    # Batasi panjang teks karena RSA tidak bisa enkripsi data besar
    if len(plaintext) > 200:
        print("⚠️ Teks terlalu panjang. Dibatasi menjadi 200 karakter.")
        plaintext = plaintext[:200]

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Enkripsi
    start_time = time.time()
    rsa_ciphertext = encrypt_rsa(plaintext, public_key)
    rsa_encrypt_time = time.time() - start_time

    print(f"\nHasil Enkripsi RSA (dalam bytes): {rsa_ciphertext}")
    print(f"Waktu enkripsi RSA: {rsa_encrypt_time:.6f} detik")

    # Dekripsi
    start_time = time.time()
    rsa_decrypted = decrypt_rsa(rsa_ciphertext, private_key)
    rsa_decrypt_time = time.time() - start_time

    print(f"\nHasil Dekripsi RSA: {rsa_decrypted}")
    print(f"Waktu dekripsi RSA: {rsa_decrypt_time:.6f} detik")

    # Ukuran ciphertext
    print(f"\nUkuran ciphertext RSA: {len(rsa_ciphertext)} byte")

if __name__ == "__main__":
    main() 